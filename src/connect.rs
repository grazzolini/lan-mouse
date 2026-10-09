use crate::client::ClientManager;
use crate::config::local_commit;
use crate::discovery::{PrimaryCache, normalize_mdns_name};
use lan_mouse_ipc::{ClientHandle, DEFAULT_PORT};
use lan_mouse_proto::{
    MAX_CLIPBOARD_SIZE, MAX_EVENT_SIZE, ProtoEvent, decode_clipboard_event, encode_clipboard_event,
};
use local_channel::mpsc::{Receiver, Sender, channel};
use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, HashSet},
    hash::{DefaultHasher, Hash, Hasher},
    io,
    net::{IpAddr, SocketAddr},
    rc::{Rc, Weak},
    sync::Arc,
    time::{Duration, Instant},
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

/// Initial backoff between connect attempts that find no usable address
/// (no static IPs, no DNS-resolved IPs, no mDNS primary hint). Doubles
/// on each subsequent failure up to [`MAX_RETRY_BACKOFF`]. The backoff
/// is bypassed entirely when the input set changes (e.g. mDNS browse
/// resolves a primary, DNS lookup returns IPs) so a peer that comes
/// back online reconnects on the next mouse event without waiting.
const INITIAL_RETRY_BACKOFF: Duration = Duration::from_secs(1);
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(30);

/// Per-handle gate that throttles repeat connect attempts when nothing
/// new is available to dial. `signature` hashes the candidate set we
/// last attempted; if the current set differs we skip the gate and
/// retry immediately. Otherwise `next_attempt_at` enforces exponential
/// backoff capped at [`MAX_RETRY_BACKOFF`].
struct RetryState {
    next_attempt_at: Instant,
    backoff: Duration,
    signature: u64,
}

fn signature_of(ips: &HashSet<IpAddr>, primary: Option<IpAddr>) -> u64 {
    let mut sorted: Vec<IpAddr> = ips.iter().copied().collect();
    sorted.sort();
    let mut hasher = DefaultHasher::new();
    sorted.hash(&mut hasher);
    primary.hash(&mut hasher);
    hasher.finish()
}

/// Update `retry_state[handle]` after a failed connect attempt: doubles
/// the backoff (capped at [`MAX_RETRY_BACKOFF`]) and stamps the
/// candidate-set signature so a later signature change can short-
/// circuit the gate.
fn record_retry_failure(
    retry_state: &Rc<RefCell<HashMap<ClientHandle, RetryState>>>,
    handle: ClientHandle,
    ips: &HashSet<IpAddr>,
    primary: Option<IpAddr>,
) {
    let sig = signature_of(ips, primary);
    let mut map = retry_state.borrow_mut();
    let entry = map.entry(handle).or_insert(RetryState {
        next_attempt_at: Instant::now(),
        backoff: INITIAL_RETRY_BACKOFF,
        signature: sig,
    });
    entry.signature = sig;
    let next = entry.backoff;
    entry.next_attempt_at = Instant::now() + next;
    entry.backoff = (next * 2).min(MAX_RETRY_BACKOFF);
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

/// Time the preferred address gets to handshake alone before the
/// rest of the candidate list joins the race. Modeled on RFC 8305
/// "happy eyeballs" v6→v4 fallback delay; long enough that a healthy
/// preferred address virtually always wins, short enough that a
/// broken preferred path only slightly delays connect.
const PREFERRED_ADDR_HEAD_START: Duration = Duration::from_millis(200);

async fn connect_any(
    addrs: &[SocketAddr],
    preferred: Option<SocketAddr>,
    cert: Certificate,
) -> Result<(Arc<dyn Conn + Send + Sync>, SocketAddr), LanMouseConnectionError> {
    let mut joinset = JoinSet::new();
    if let Some(p) = preferred {
        // Dial the peer's mDNS-advertised primary first. If it
        // handshakes within `PREFERRED_ADDR_HEAD_START` we're done
        // before the others even start — the dialer biases toward
        // the OS-preferred interface (Mac service order, Linux
        // default route) without relying on RTT racing alone.
        joinset.spawn_local(connect(p, cert.clone()));
        let head_start = tokio::time::sleep(PREFERRED_ADDR_HEAD_START);
        tokio::pin!(head_start);
        loop {
            tokio::select! {
                _ = &mut head_start => break,
                Some(r) = joinset.join_next() => match r.expect("join error") {
                    Ok(conn) => return Ok(conn),
                    Err((a, e)) => log::warn!("failed to connect to {a}: `{e}`"),
                },
            }
        }
    }
    for &addr in addrs {
        if Some(addr) == preferred {
            // already racing; don't dial the same socket twice
            continue;
        }
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
    /// Map of `peer_hostname -> primary_ipv4` populated by the
    /// `Discovery` mDNS browse task. Read on every `connect_to_handle`
    /// to bias which address gets the handshake head-start. Empty
    /// when discovery is disabled or no peer hint has arrived yet.
    primary_hints: PrimaryCache,
    /// Per-handle retry gate. Suppresses connect spawns when the
    /// previous attempt failed and nothing new is available to dial,
    /// so an offline peer doesn't trigger a fresh `connect_to_handle`
    /// (and the associated DNS / mDNS lookup churn) on every mouse
    /// event. Cleared on successful connect; bypassed automatically
    /// when the candidate-set signature changes.
    retry_state: Rc<RefCell<HashMap<ClientHandle, RetryState>>>,
}

impl LanMouseConnection {
    pub(crate) fn new(
        cert: Certificate,
        client_manager: ClientManager,
        primary_hints: PrimaryCache,
    ) -> Self {
        let (recv_tx, recv_rx) = channel();
        Self {
            cert,
            client_manager,
            conns: Default::default(),
            connecting: Default::default(),
            recv_rx,
            recv_tx,
            primary_hints,
            retry_state: Default::default(),
        }
    }

    pub(crate) async fn recv(&mut self) -> (ClientHandle, ProtoEvent) {
        self.recv_rx.recv().await.expect("channel closed")
    }

    /// Cheap send-only handle that shares all the dialer state with
    /// `self`. The clone's `recv_rx` is a dead stub — only the
    /// original [`LanMouseConnection`] (held by Capture) drains the
    /// live receiver. Used by Service to fan clipboard frames out
    /// without routing through the capture session loop.
    pub(crate) fn sender_clone(&self) -> Self {
        let (_, dead_rx) = channel();
        Self {
            cert: self.cert.clone(),
            client_manager: self.client_manager.clone(),
            conns: self.conns.clone(),
            connecting: self.connecting.clone(),
            recv_rx: dead_rx,
            recv_tx: self.recv_tx.clone(),
            primary_hints: self.primary_hints.clone(),
            retry_state: self.retry_state.clone(),
        }
    }

    pub(crate) async fn send(
        &self,
        event: ProtoEvent,
        handle: ClientHandle,
    ) -> Result<(), LanMouseConnectionError> {
        let event_display = format!("{event}");
        // Clipboard frames are variable-length and can't ride the
        // fixed-size codec; route them through the dedicated helper.
        // For all other events the existing 21-byte path is faster.
        let bytes_owned: Option<Vec<u8>> = match &event {
            ProtoEvent::Clipboard { .. } => match encode_clipboard_event(&event) {
                Ok(v) => Some(v),
                Err(e) => {
                    log::warn!("dropping oversize clipboard event for client {handle}: {e}");
                    return Ok(());
                }
            },
            _ => None,
        };
        let bytes_fixed: ([u8; MAX_EVENT_SIZE], usize) = if bytes_owned.is_some() {
            ([0u8; MAX_EVENT_SIZE], 0)
        } else {
            event.into()
        };
        let buf: &[u8] = if let Some(v) = bytes_owned.as_deref() {
            v
        } else {
            &bytes_fixed.0[..bytes_fixed.1]
        };
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
                log::trace!("{event_display} >->->->->- {addr}");
                return Ok(());
            }
        }

        // check if we are already trying to connect
        let mut connecting = self.connecting.lock().await;
        if !connecting.contains(&handle) && self.should_attempt(handle) {
            connecting.insert(handle);
            // connect in the background
            spawn_local(connect_to_handle(
                self.client_manager.clone(),
                self.cert.clone(),
                handle,
                self.conns.clone(),
                self.connecting.clone(),
                self.recv_tx.clone(),
                self.primary_hints.clone(),
                self.retry_state.clone(),
            ));
        }
        Err(LanMouseConnectionError::NotConnected)
    }

    /// Decide whether to spawn another `connect_to_handle` for `handle`.
    /// Returns true (and refreshes the recorded signature) when:
    ///   - we have no prior attempt for this handle, or
    ///   - the candidate-set signature has changed since the last
    ///     attempt (new IP from DNS, or new mDNS primary), or
    ///   - the recorded backoff has elapsed.
    ///
    /// Otherwise returns false; the caller treats this as "still in
    /// cooldown, keep returning NotConnected silently."
    fn should_attempt(&self, handle: ClientHandle) -> bool {
        let ips = self.client_manager.get_ips(handle).unwrap_or_default();
        let primary = self.client_manager.get_hostname(handle).and_then(|h| {
            let key = normalize_mdns_name(&h);
            self.primary_hints.borrow().get(&key).copied()
        });
        let sig = signature_of(&ips, primary);
        let mut state = self.retry_state.borrow_mut();
        match state.get_mut(&handle) {
            None => true,
            Some(s) if s.signature != sig => {
                s.signature = sig;
                s.next_attempt_at = Instant::now();
                s.backoff = INITIAL_RETRY_BACKOFF;
                true
            }
            Some(s) => Instant::now() >= s.next_attempt_at,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn connect_to_handle(
    client_manager: ClientManager,
    cert: Certificate,
    handle: ClientHandle,
    conns: Connections,
    connecting: Rc<Mutex<HashSet<ClientHandle>>>,
    tx: Sender<(ClientHandle, ProtoEvent)>,
    primary_hints: PrimaryCache,
    retry_state: Rc<RefCell<HashMap<ClientHandle, RetryState>>>,
) -> Result<(), LanMouseConnectionError> {
    log::info!("client {handle} connecting ...");
    // sending did not work, figure out active conn.
    if let Some(ips_set) = client_manager.get_ips(handle) {
        let port = client_manager.get_port(handle).unwrap_or(DEFAULT_PORT);
        let addrs = ips_set
            .iter()
            .copied()
            .map(|a| SocketAddr::new(a, port))
            .collect::<Vec<_>>();
        // mDNS-advertised primary IP for this peer, if known. Used
        // by `connect_any` as a head-start address: the dialer races
        // it alone for ~200ms before joining the rest of the list,
        // so a healthy primary almost always wins regardless of
        // raw RTT ordering.
        let primary_ip = client_manager.get_hostname(handle).and_then(|h| {
            let key = normalize_mdns_name(&h);
            primary_hints.borrow().get(&key).copied()
        });
        let preferred = primary_ip.map(|ip| SocketAddr::new(ip, port));
        log::info!("client ({handle}) connecting ... (ips: {addrs:?}, preferred: {preferred:?})");
        if addrs.is_empty() && preferred.is_none() {
            // Nothing to dial. Bump backoff and bail without spawning
            // DTLS work or spamming logs on every subsequent mouse
            // event — `should_attempt` will keep gating until either
            // the backoff elapses or new info arrives.
            record_retry_failure(&retry_state, handle, &ips_set, primary_ip);
            connecting.lock().await.remove(&handle);
            return Err(LanMouseConnectionError::NotConnected);
        }
        let res = connect_any(&addrs, preferred, cert).await;
        let (conn, addr) = match res {
            Ok(c) => c,
            Err(e) => {
                record_retry_failure(&retry_state, handle, &ips_set, primary_ip);
                connecting.lock().await.remove(&handle);
                return Err(e);
            }
        };
        log::info!("client ({handle}) connected @ {addr}");
        start_connection(&client_manager, handle, addr, conn, &conns, tx).await;
        connecting.lock().await.remove(&handle);
        retry_state.borrow_mut().remove(&handle);

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
    // Buffer sized for the largest legal clipboard frame so a single
    // DTLS recv never gets truncated. Non-clipboard events use only
    // the first MAX_EVENT_SIZE bytes; the rest of the buffer is
    // unused for those datagrams.
    let mut buf = [0u8; MAX_CLIPBOARD_SIZE];
    while let Ok(n) = conn.recv(&mut buf).await {
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
        if n == 0 {
            continue;
        }
        let datagram = &buf[..n];
        let event = match decode_proto_datagram(datagram) {
            Some(event) => event,
            // Skip undecodable datagrams without dropping the
            // connection. Each DTLS recv is one framed message, so
            // skipping is safe and keeps us forward-compatible with
            // peers that send event types we don't yet know about.
            None => {
                log::debug!("ignoring undecodable {n}-byte event from {addr}");
                continue;
            }
        };
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
    log::warn!("recv error");
}

/// Classify the first byte of a DTLS datagram and dispatch through
/// either the variable-length clipboard codec or the fixed-buffer
/// `try_into` path. Returns `None` on any decode failure (bad tag,
/// truncated payload, oversize frame).
fn decode_proto_datagram(bytes: &[u8]) -> Option<ProtoEvent> {
    use lan_mouse_proto::EventType;
    let tag = *bytes.first()?;
    if tag == EventType::Clipboard as u8 {
        return decode_clipboard_event(bytes).ok();
    }
    let mut fixed = [0u8; MAX_EVENT_SIZE];
    let copy_len = bytes.len().min(MAX_EVENT_SIZE);
    fixed[..copy_len].copy_from_slice(&bytes[..copy_len]);
    fixed.try_into().ok()
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
            LanMouseConnection::new(cert, clients.clone(), Default::default()),
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
