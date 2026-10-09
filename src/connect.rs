use crate::client::ClientManager;
use crate::config::local_commit;
use lan_mouse_ipc::{ClientHandle, DEFAULT_PORT};
use lan_mouse_proto::{MAX_EVENT_SIZE, ProtoEvent};
use local_channel::mpsc::{Receiver, Sender, channel};
use std::{
    cell::Cell,
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    rc::{Rc, Weak},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::{
    net::UdpSocket,
    sync::Mutex,
    task::{JoinHandle, JoinSet, spawn_local},
};
use tokio_util::sync::CancellationToken;
use webrtc_dtls::{
    config::{Config, ExtendedMasterSecretType},
    conn::DTLSConn,
    crypto::Certificate,
};
use webrtc_util::Conn;

#[derive(Debug, Error)]
pub(crate) enum LanMouseConnectionError {
    #[error(transparent)]
    Bind(#[from] io::Error),
    #[error(transparent)]
    Dtls(#[from] webrtc_dtls::Error),
    #[error(transparent)]
    Webrtc(#[from] webrtc_util::Error),
    #[error("not connected")]
    NotConnected,
    #[error("emulation is disabled on the target device")]
    TargetEmulationDisabled,
    #[error("Connection timed out")]
    Timeout,
}

const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

type ArcConn = Arc<dyn Conn + Send + Sync>;
type Connections = Rc<Mutex<HashMap<SocketAddr, Connection>>>;
type WeakConnections = Weak<Mutex<HashMap<SocketAddr, Connection>>>;

struct Connection {
    conn: ArcConn,
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl Connection {
    async fn shutdown(mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            if let Err(e) = task.await {
                log::warn!("connection task: {e}");
            }
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

async fn connect(
    addr: SocketAddr,
    cert: Certificate,
) -> Result<(Arc<dyn Conn + Sync + Send>, SocketAddr), (SocketAddr, LanMouseConnectionError)> {
    log::info!("connecting to {addr} ...");
    let conn = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| (addr, e.into()))?,
    );
    conn.connect(addr).await.map_err(|e| (addr, e.into()))?;
    let config = Config {
        certificates: vec![cert],
        server_name: "ignored".to_owned(),
        insecure_skip_verify: true,
        extended_master_secret: ExtendedMasterSecretType::Require,
        ..Default::default()
    };
    let timeout = tokio::time::sleep(DEFAULT_CONNECTION_TIMEOUT);
    tokio::select! {
        _ = timeout => Err((addr, LanMouseConnectionError::Timeout)),
        result = DTLSConn::new(conn, config, true, None) => match result {
            Ok(dtls_conn) => Ok((Arc::new(dtls_conn), addr)),
            Err(e) => Err((addr, e.into())),
        }
    }
}

async fn connect_any(
    addrs: &[SocketAddr],
    cert: Certificate,
) -> Result<(Arc<dyn Conn + Send + Sync>, SocketAddr), LanMouseConnectionError> {
    let mut joinset = JoinSet::new();
    for &addr in addrs {
        joinset.spawn_local(connect(addr, cert.clone()));
    }
    loop {
        match joinset.join_next().await {
            None => return Err(LanMouseConnectionError::NotConnected),
            Some(r) => match r.expect("join error") {
                Ok(conn) => return Ok(conn),
                Err((a, e)) => {
                    log::warn!("failed to connect to {a}: `{e}`")
                }
            },
        };
    }
}

pub(crate) struct LanMouseConnection {
    cert: Certificate,
    client_manager: ClientManager,
    conns: Connections,
    connecting: Rc<Mutex<HashSet<ClientHandle>>>,
    recv_rx: Receiver<(ClientHandle, ProtoEvent)>,
    recv_tx: Sender<(ClientHandle, ProtoEvent)>,
}

impl LanMouseConnection {
    pub(crate) fn new(cert: Certificate, client_manager: ClientManager) -> Self {
        let (recv_tx, recv_rx) = channel();
        Self {
            cert,
            client_manager,
            conns: Default::default(),
            connecting: Default::default(),
            recv_rx,
            recv_tx,
        }
    }

    pub(crate) async fn recv(&mut self) -> (ClientHandle, ProtoEvent) {
        self.recv_rx.recv().await.expect("channel closed")
    }

    pub(crate) async fn send(
        &self,
        event: ProtoEvent,
        handle: ClientHandle,
    ) -> Result<(), LanMouseConnectionError> {
        let (buf, len): ([u8; MAX_EVENT_SIZE], usize) = event.into();
        let buf = &buf[..len];
        if let Some(addr) = self.client_manager.active_addr(handle) {
            let conn = {
                let conns = self.conns.lock().await;
                conns.get(&addr).map(|session| session.conn.clone())
            };
            if let Some(conn) = conn {
                if !self.client_manager.alive(handle) {
                    return Err(LanMouseConnectionError::TargetEmulationDisabled);
                }
                match conn.send(buf).await {
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!("client {handle} failed to send: {e}");
                        if let Some(session) =
                            disconnect(&self.client_manager, handle, addr, &conn, &self.conns).await
                        {
                            session.shutdown().await;
                        }
                        return Err(e.into());
                    }
                }
                log::trace!("{event} >->->->->- {addr}");
                return Ok(());
            }
        }

        // check if we are already trying to connect
        let mut connecting = self.connecting.lock().await;
        if !connecting.contains(&handle) {
            connecting.insert(handle);
            // connect in the background
            spawn_local(connect_to_handle(
                self.client_manager.clone(),
                self.cert.clone(),
                handle,
                self.conns.clone(),
                self.connecting.clone(),
                self.recv_tx.clone(),
            ));
        }
        Err(LanMouseConnectionError::NotConnected)
    }
}

async fn connect_to_handle(
    client_manager: ClientManager,
    cert: Certificate,
    handle: ClientHandle,
    conns: Connections,
    connecting: Rc<Mutex<HashSet<ClientHandle>>>,
    tx: Sender<(ClientHandle, ProtoEvent)>,
) -> Result<(), LanMouseConnectionError> {
    log::info!("client {handle} connecting ...");
    // sending did not work, figure out active conn.
    if let Some(addrs) = client_manager.get_ips(handle) {
        let port = client_manager.get_port(handle).unwrap_or(DEFAULT_PORT);
        let addrs = addrs
            .into_iter()
            .map(|a| SocketAddr::new(a, port))
            .collect::<Vec<_>>();
        log::info!("client ({handle}) connecting ... (ips: {addrs:?})");
        let res = connect_any(&addrs, cert).await;
        let (conn, addr) = match res {
            Ok(c) => c,
            Err(e) => {
                connecting.lock().await.remove(&handle);
                return Err(e);
            }
        };
        log::info!("client ({handle}) connected @ {addr}");
        start_connection(&client_manager, handle, addr, conn, &conns, tx).await;
        connecting.lock().await.remove(&handle);
        return Ok(());
    }
    connecting.lock().await.remove(&handle);
    Err(LanMouseConnectionError::NotConnected)
}

async fn start_connection(
    client_manager: &ClientManager,
    handle: ClientHandle,
    addr: SocketAddr,
    conn: ArcConn,
    conns: &Connections,
    tx: Sender<(ClientHandle, ProtoEvent)>,
) {
    let cancellation = CancellationToken::new();
    let mut connections = conns.lock().await;
    let task = spawn_local(run_connection(
        client_manager.clone(),
        handle,
        addr,
        conn.clone(),
        Rc::downgrade(conns),
        tx,
        cancellation.clone(),
    ));
    let previous = connections.insert(
        addr,
        Connection {
            conn,
            cancellation,
            task: Some(task),
        },
    );
    client_manager.set_active_addr(handle, Some(addr));
    client_manager.set_alive(handle, false);
    client_manager.set_peer_commit(handle, None);
    drop(connections);
    if let Some(previous) = previous {
        previous.shutdown().await;
    }
}

async fn run_connection(
    client_manager: ClientManager,
    handle: ClientHandle,
    addr: SocketAddr,
    conn: ArcConn,
    conns: WeakConnections,
    tx: Sender<(ClientHandle, ProtoEvent)>,
    cancellation: CancellationToken,
) {
    // One owner polls both futures. Ending either drops the other, even when
    // DTLS close fails to wake recv during a network outage.
    let ping_response = Cell::new(false);
    tokio::select! {
        _ = cancellation.cancelled() => {},
        _ = async {
            let (buf, len) = ProtoEvent::Hello { commit: local_commit() }.into();
            match tokio::time::timeout(DEFAULT_CONNECTION_TIMEOUT, conn.send(&buf[..len])).await {
                Ok(Ok(_)) => {},
                Ok(Err(e)) => log::debug!("hello send to {addr} failed: {e}"),
                Err(_) => log::debug!("hello send to {addr} timed out"),
            }
            tokio::select! {
                _ = ping_pong(addr, &conn, &ping_response) => {},
                _ = receive_loop(&client_manager, handle, addr, &conn, &conns, tx, &ping_response) => {},
            }
        } => {},
    }

    if let Some(conns) = conns.upgrade() {
        drop(disconnect(&client_manager, handle, addr, &conn, &conns).await);
    }
    // Retirement must not depend on successfully sending CloseNotify. Dropping
    // the final DTLS reference also stops its internal reader after close errors.
    match tokio::time::timeout(CONNECTION_CLOSE_TIMEOUT, conn.close()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::debug!("closing connection to {addr}: {e}"),
        Err(_) => log::warn!("closing connection to {addr} timed out"),
    }
}

async fn ping_pong(addr: SocketAddr, conn: &ArcConn, ping_response: &Cell<bool>) {
    loop {
        let (buf, len) = ProtoEvent::Ping.into();

        // send 4 pings, at least one must be answered
        for _ in 0..4 {
            if let Err(e) = conn.send(&buf[..len]).await {
                log::warn!("{addr}: send error `{e}`, closing connection");
                return;
            }
            log::trace!("PING >->->->->- {addr}");

            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        if !ping_response.replace(false) {
            log::warn!("{addr} did not respond, closing connection");
            return;
        }
    }
}

async fn receive_loop(
    client_manager: &ClientManager,
    handle: ClientHandle,
    addr: SocketAddr,
    conn: &ArcConn,
    conns: &WeakConnections,
    tx: Sender<(ClientHandle, ProtoEvent)>,
    ping_response: &Cell<bool>,
) {
    let mut buf = [0u8; MAX_EVENT_SIZE];
    while conn.recv(&mut buf).await.is_ok() {
        let Some(conns) = conns.upgrade() else {
            return;
        };
        if !conns
            .lock()
            .await
            .get(&addr)
            .is_some_and(|session| Arc::ptr_eq(&session.conn, conn))
        {
            return;
        }
        match buf.try_into() {
            Ok(event) => {
                log::trace!("{addr} <==<==<== {event}");
                match event {
                    ProtoEvent::Pong(b) => {
                        client_manager.set_active_addr(handle, Some(addr));
                        client_manager.set_alive(handle, b);
                        ping_response.set(true);
                    }
                    ProtoEvent::Hello { commit } => {
                        client_manager.set_peer_commit(handle, Some(commit));
                    }
                    event => {
                        if tx.send((handle, event)).is_err() {
                            return;
                        }
                    }
                }
            }
            // Skip undecodable datagrams without dropping the
            // connection. Each DTLS recv is one framed message, so
            // skipping is safe and keeps us forward-compatible with
            // peers that send event types we don't yet know about.
            Err(e) => log::debug!("ignoring undecodable event from {addr}: {e}"),
        }
    }
    log::warn!("recv error");
}

async fn disconnect(
    client_manager: &ClientManager,
    handle: ClientHandle,
    addr: SocketAddr,
    expected: &ArcConn,
    conns: &Connections,
) -> Option<Connection> {
    let mut conns = conns.lock().await;
    if !conns
        .get(&addr)
        .is_some_and(|session| Arc::ptr_eq(&session.conn, expected))
    {
        return None;
    }
    log::warn!("client ({handle}) @ {addr} connection closed");
    let session = conns.remove(&addr);
    if client_manager.active_addr(handle) == Some(addr) {
        client_manager.set_active_addr(handle, None);
        client_manager.set_alive(handle, false);
        client_manager.set_peer_commit(handle, None);
    }
    let active: Vec<SocketAddr> = conns.keys().copied().collect();
    log::info!("active connections: {active:?}");
    session
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::{sync::mpsc, task::LocalSet, time::timeout};

    type Packet = Result<Vec<u8>, ()>;

    #[derive(Clone, Copy)]
    enum CloseMode {
        Ok,
        Error,
        Pending,
    }

    struct TestConn {
        incoming: Mutex<mpsc::UnboundedReceiver<Packet>>,
        fail_send: Arc<AtomicBool>,
        sends: Arc<AtomicUsize>,
        closes: Arc<AtomicUsize>,
        close_mode: CloseMode,
    }

    impl TestConn {
        fn new(close_mode: CloseMode) -> (Arc<Self>, mpsc::UnboundedSender<Packet>) {
            let (tx, rx) = mpsc::unbounded_channel();
            (
                Arc::new(Self {
                    incoming: Mutex::new(rx),
                    fail_send: Default::default(),
                    sends: Default::default(),
                    closes: Default::default(),
                    close_mode,
                }),
                tx,
            )
        }
    }

    #[async_trait]
    impl Conn for TestConn {
        async fn connect(&self, _: SocketAddr) -> Result<(), webrtc_util::Error> {
            Ok(())
        }

        async fn recv(&self, buf: &mut [u8]) -> Result<usize, webrtc_util::Error> {
            match self.incoming.lock().await.recv().await {
                Some(Ok(packet)) => {
                    buf[..packet.len()].copy_from_slice(&packet);
                    Ok(packet.len())
                }
                _ => Err(webrtc_util::Error::Other("injected receive error".into())),
            }
        }

        async fn recv_from(
            &self,
            buf: &mut [u8],
        ) -> Result<(usize, SocketAddr), webrtc_util::Error> {
            self.recv(buf).await.map(|n| (n, addr()))
        }

        async fn send(&self, buf: &[u8]) -> Result<usize, webrtc_util::Error> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            if self.fail_send.load(Ordering::SeqCst) {
                Err(webrtc_util::Error::Other("injected send error".into()))
            } else {
                Ok(buf.len())
            }
        }

        async fn send_to(&self, buf: &[u8], _: SocketAddr) -> Result<usize, webrtc_util::Error> {
            self.send(buf).await
        }

        fn local_addr(&self) -> Result<SocketAddr, webrtc_util::Error> {
            Ok(addr())
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            Some(addr())
        }

        async fn close(&self) -> Result<(), webrtc_util::Error> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            // Neither error nor success wakes recv. This models the DTLS
            // CloseNotify failure instead of assuming close ends every reader.
            match self.close_mode {
                CloseMode::Ok => Ok(()),
                CloseMode::Error => Err(webrtc_util::Error::Other("injected close error".into())),
                CloseMode::Pending => std::future::pending().await,
            }
        }

        fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
            self
        }
    }

    fn addr() -> SocketAddr {
        "127.0.0.1:4242".parse().unwrap()
    }

    fn dialer() -> (LanMouseConnection, ClientManager, ClientHandle) {
        let clients = ClientManager::default();
        let handle = clients.add_client();
        let cert = Certificate::generate_self_signed(vec!["localhost".into()]).unwrap();
        (
            LanMouseConnection::new(cert, clients.clone()),
            clients,
            handle,
        )
    }

    async fn wait_until(mut ready: impl FnMut() -> bool) {
        timeout(Duration::from_secs(4), async {
            while !ready() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("connection lifecycle did not finish");
    }

    fn packet(event: ProtoEvent) -> Packet {
        let (buf, len): ([u8; MAX_EVENT_SIZE], usize) = event.into();
        Ok(buf[..len].to_vec())
    }

    #[tokio::test]
    async fn receive_error_releases_connection_even_when_close_fails() {
        LocalSet::new()
            .run_until(async {
                let (dialer, clients, handle) = dialer();
                let (conn, tx) = TestConn::new(CloseMode::Error);
                let weak = Arc::downgrade(&conn);
                let closes = conn.closes.clone();
                start_connection(
                    &clients,
                    handle,
                    addr(),
                    conn,
                    &dialer.conns,
                    dialer.recv_tx.clone(),
                )
                .await;
                clients.set_alive(handle, true);
                clients.set_peer_commit(handle, Some(*b"oldbuild"));
                tx.send(Err(())).unwrap();
                wait_until(|| weak.upgrade().is_none()).await;
                assert!(dialer.conns.lock().await.is_empty());
                assert_eq!(clients.active_addr(handle), None);
                assert!(!clients.alive(handle));
                assert_eq!(clients.get_state(handle).unwrap().1.peer_commit, None);
                assert_eq!(closes.load(Ordering::SeqCst), 1);
            })
            .await;
    }

    #[tokio::test]
    async fn send_error_clears_state_before_bounded_shutdown_finishes() {
        LocalSet::new()
            .run_until(async {
                let (dialer, clients, handle) = dialer();
                let (conn, _tx) = TestConn::new(CloseMode::Pending);
                let weak = Arc::downgrade(&conn);
                let fail_send = conn.fail_send.clone();
                let sends = conn.sends.clone();
                start_connection(
                    &clients,
                    handle,
                    addr(),
                    conn,
                    &dialer.conns,
                    dialer.recv_tx.clone(),
                )
                .await;
                // Wait for Hello and the first heartbeat, then fail a user send
                // while the heartbeat is sleeping and recv remains blocked.
                wait_until(|| sends.load(Ordering::SeqCst) >= 2).await;
                clients.set_alive(handle, true);
                clients.set_peer_commit(handle, Some(*b"oldbuild"));
                fail_send.store(true, Ordering::SeqCst);
                let send = spawn_local(async move { dialer.send(ProtoEvent::Ping, handle).await });
                wait_until(|| clients.active_addr(handle).is_none()).await;
                assert!(!clients.alive(handle));
                assert_eq!(clients.get_state(handle).unwrap().1.peer_commit, None);
                assert!(!send.is_finished());
                assert!(
                    timeout(Duration::from_secs(2), send)
                        .await
                        .unwrap()
                        .unwrap()
                        .is_err()
                );
                assert!(weak.upgrade().is_none());
            })
            .await;
    }

    #[tokio::test]
    async fn heartbeat_timeout_retires_without_another_input_event() {
        LocalSet::new()
            .run_until(async {
                let (dialer, clients, handle) = dialer();
                let (conn, _tx) = TestConn::new(CloseMode::Error);
                let weak = Arc::downgrade(&conn);
                start_connection(
                    &clients,
                    handle,
                    addr(),
                    conn,
                    &dialer.conns,
                    dialer.recv_tx.clone(),
                )
                .await;
                clients.set_alive(handle, true);
                wait_until(|| weak.upgrade().is_none()).await;
                assert_eq!(clients.active_addr(handle), None);
                assert!(!clients.alive(handle));
                assert!(dialer.conns.lock().await.is_empty());
            })
            .await;
    }

    #[tokio::test]
    async fn stale_cleanup_and_pong_cannot_change_replacement() {
        LocalSet::new()
            .run_until(async {
                let (mut dialer, clients, handle) = dialer();
                let (old, old_tx) = TestConn::new(CloseMode::Error);
                let old: ArcConn = old;
                start_connection(&clients, handle, addr(), old.clone(), &dialer.conns, dialer.recv_tx.clone()).await;
                let (new, new_tx) = TestConn::new(CloseMode::Ok);
                let new: ArcConn = new;
                start_connection(&clients, handle, addr(), new.clone(), &dialer.conns, dialer.recv_tx.clone()).await;
                new_tx.send(packet(ProtoEvent::Pong(true))).unwrap();
                new_tx.send(packet(ProtoEvent::Hello { commit: *b"newbuild" })).unwrap();
                wait_until(|| clients.get_state(handle).unwrap().1.peer_commit == Some(*b"newbuild")).await;

                assert!(disconnect(&clients, handle, addr(), &old, &dialer.conns).await.is_none());
                old_tx.send(packet(ProtoEvent::Pong(false))).unwrap();
                timeout(Duration::from_secs(1), receive_loop(&clients, handle, addr(), &old, &Rc::downgrade(&dialer.conns), dialer.recv_tx.clone(), &Cell::new(false))).await.unwrap();
                assert_eq!(clients.active_addr(handle), Some(addr()));
                assert!(clients.alive(handle));
                assert_eq!(clients.get_state(handle).unwrap().1.peer_commit, Some(*b"newbuild"));
                assert!(Arc::ptr_eq(&dialer.conns.lock().await[&addr()].conn, &new));

                new_tx.send(packet(ProtoEvent::Ack(0))).unwrap();
                assert!(matches!(timeout(Duration::from_secs(1), dialer.recv()).await.unwrap(), (h, ProtoEvent::Ack(0)) if h == handle));
                disconnect(&clients, handle, addr(), &new, &dialer.conns).await.unwrap().shutdown().await;
            })
            .await;
    }

    #[tokio::test]
    async fn reconnects_after_peer_closes_connection() {
        LocalSet::new()
            .run_until(async {
                use webrtc_util::conn::Listener;

                let (dialer, clients, handle) = dialer();
                let listener = webrtc_dtls::listener::listen(
                    "127.0.0.1:0",
                    Config {
                        certificates: vec![
                            Certificate::generate_self_signed(vec!["localhost".into()]).unwrap(),
                        ],
                        extended_master_secret: ExtendedMasterSecretType::Require,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
                clients.set_fix_ips(handle, vec!["127.0.0.1".parse().unwrap()]);
                clients.set_port(handle, listener.addr().await.unwrap().port());
                for _ in 0..3 {
                    assert!(matches!(
                        dialer.send(ProtoEvent::Ping, handle).await,
                        Err(LanMouseConnectionError::NotConnected)
                    ));
                    let (peer, _) = timeout(Duration::from_secs(3), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                    let (buf, len): ([u8; MAX_EVENT_SIZE], usize) = ProtoEvent::Pong(true).into();
                    peer.send(&buf[..len]).await.unwrap();
                    wait_until(|| clients.alive(handle)).await;
                    dialer.send(ProtoEvent::Ack(0), handle).await.unwrap();
                    timeout(Duration::from_secs(1), async {
                        loop {
                            let mut buf = [0u8; MAX_EVENT_SIZE];
                            peer.recv(&mut buf).await.unwrap();
                            if matches!(ProtoEvent::try_from(buf), Ok(ProtoEvent::Ack(0))) {
                                break;
                            }
                        }
                    })
                    .await
                    .unwrap();
                    peer.close().await.unwrap();
                    wait_until(|| clients.active_addr(handle).is_none()).await;
                    assert!(!clients.alive(handle));
                    assert!(dialer.conns.lock().await.is_empty());
                }
                listener.close().await.unwrap();
            })
            .await;
    }

    #[tokio::test]
    async fn dropping_owner_cancels_blocked_receiver() {
        LocalSet::new()
            .run_until(async {
                let (dialer, clients, handle) = dialer();
                let (conn, _tx) = TestConn::new(CloseMode::Error);
                let weak = Arc::downgrade(&conn);
                start_connection(
                    &clients,
                    handle,
                    addr(),
                    conn,
                    &dialer.conns,
                    dialer.recv_tx.clone(),
                )
                .await;
                drop(dialer);
                wait_until(|| weak.upgrade().is_none()).await;
            })
            .await;
    }
}
