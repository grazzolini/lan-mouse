use futures::{Stream, StreamExt, future::join_all};
use lan_mouse_ipc::IncomingPeerConfig;
use lan_mouse_proto::{MAX_CLIPBOARD_SIZE, MAX_EVENT_SIZE, ProtoEvent, decode_clipboard_event};
use local_channel::mpsc::{Receiver, Sender, channel};
use rustls::pki_types::CertificateDer;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    rc::Rc,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use thiserror::Error;
use tokio::task::{JoinHandle, spawn_local};
use tokio::time::MissedTickBehavior;
use webrtc_dtls::{
    config::{ClientAuthType::RequireAnyClientCert, Config, ExtendedMasterSecretType},
    conn::DTLSConn,
    crypto::Certificate,
    listener::listen,
};
use webrtc_util::{Conn, Error, conn::Listener};

use crate::crypto;

#[derive(Error, Debug)]
pub enum ListenerCreationError {
    #[error(transparent)]
    WebrtcUtil(#[from] webrtc_util::Error),
    #[error(transparent)]
    WebrtcDtls(#[from] webrtc_dtls::Error),
    #[error("no listener could be bound on any local address")]
    NoBoundListener,
}

type ArcConn = Arc<dyn Conn + Send + Sync>;
type DynListener = Arc<dyn Listener + Send + Sync>;
type Connections = Rc<RefCell<Vec<RegisteredConnection>>>;
type Sessions = Rc<RefCell<HashMap<SessionId, AcceptedConnection>>>;
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SessionId(u64);

impl SessionId {
    pub(crate) fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        Self(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }
}

struct RegisteredConnection {
    addr: SocketAddr,
    session: SessionId,
    conn: ArcConn,
}

struct AcceptedConnection {
    addr: SocketAddr,
    conn: ArcConn,
    read_task: Option<JoinHandle<()>>,
}

enum ListenerRequest {
    ChangePort(u16),
    Terminate,
}

pub(crate) enum ListenEvent {
    Msg {
        event: ProtoEvent,
        addr: SocketAddr,
        session: SessionId,
    },
    Accept {
        addr: SocketAddr,
        fingerprint: String,
        session: SessionId,
    },
    Disconnected {
        addr: SocketAddr,
        session: SessionId,
    },
    Rejected {
        fingerprint: String,
    },
}

pub(crate) struct LanMouseListener {
    listen_rx: Receiver<ListenEvent>,
    listen_tx: Sender<ListenEvent>,
    listen_task: JoinHandle<()>,
    conns: Connections,
    request_port_change: Sender<ListenerRequest>,
    port_changed: Receiver<Result<u16, ListenerCreationError>>,
}

type VerifyPeerCertificateFn = Arc<
    dyn (Fn(&[Vec<u8>], &[CertificateDer<'static>]) -> Result<(), webrtc_dtls::Error>)
        + Send
        + Sync,
>;

/// Owns every connection accepted on one local binding. Teardown must finish
/// before the supervisor can bind that address again.
struct ListenerSlot {
    listener: Option<DynListener>,
    accept_task: Option<JoinHandle<()>>,
    sessions: Sessions,
    conns: Connections,
    listen_tx: Sender<ListenEvent>,
}

impl ListenerSlot {
    async fn shutdown(mut self, conns: &Connections, listen_tx: &Sender<ListenEvent>) {
        let mut accept_task = self.accept_task.take().expect("accept task");
        accept_task.abort();
        let _ = (&mut accept_task).await;
        let sessions: Vec<_> = self.sessions.borrow_mut().drain().collect();
        // Retire identities before any network await; queued events from these
        // readers must not release keys belonging to a newer session.
        for (session, accepted) in &sessions {
            retire_connection(conns, *session, accepted.addr, listen_tx);
            if let Some(task) = &accepted.read_task {
                task.abort();
            }
        }
        join_all(sessions.into_iter().map(|(_, mut accepted)| async move {
            if let Some(task) = accepted.read_task.take() {
                let _ = task.await;
            }
            close_connection(&accepted.conn).await;
            // Drop even after a failed/timed-out close. DTLSConn's sender drop
            // stops its internal reader, including the close-notify error path.
        }))
        .await;
        let listener = self.listener.take().expect("listener");
        match tokio::time::timeout(CLOSE_TIMEOUT, listener.close()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => log::debug!("listener close failed: {e}"),
            Err(_) => log::warn!("listener close timed out"),
        }
        drop(listener);
        // webrtc-util's UDP reader is detached; let its close notification run
        // after the last accepted connection and listener references are gone.
        tokio::task::yield_now().await;
    }
}

// Normal removals use shutdown() and await task completion. Keep cancellation
// on Drop as a fallback if the supervisor itself is unexpectedly cancelled.
impl Drop for ListenerSlot {
    fn drop(&mut self) {
        if let Some(task) = &self.accept_task {
            task.abort();
        }
        for (session, accepted) in self.sessions.borrow_mut().drain() {
            retire_connection(&self.conns, session, accepted.addr, &self.listen_tx);
            if let Some(task) = accepted.read_task {
                task.abort();
            }
        }
    }
}

async fn close_connection(conn: &ArcConn) {
    match tokio::time::timeout(CLOSE_TIMEOUT, conn.close()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::debug!("dtls close failed: {e}"),
        Err(_) => log::warn!("dtls close timed out"),
    }
}

fn retire_connection(
    conns: &Connections,
    session: SessionId,
    addr: SocketAddr,
    listen_tx: &Sender<ListenEvent>,
) {
    let mut conns = conns.borrow_mut();
    if let Some(index) = conns.iter().position(|c| c.session == session) {
        conns.remove(index);
        let _ = listen_tx.send(ListenEvent::Disconnected { addr, session });
    }
}

impl LanMouseListener {
    pub(crate) async fn new(
        port: u16,
        cert: Certificate,
        authorized_keys: Arc<RwLock<HashMap<String, IncomingPeerConfig>>>,
    ) -> Result<Self, ListenerCreationError> {
        let (listen_tx, listen_rx) = channel();
        let (request_port_change, request_port_change_rx) = channel();
        let (port_changed_tx, port_changed) = channel();
        let connection_attempts: Arc<Mutex<VecDeque<String>>> = Default::default();

        let authorized = authorized_keys.clone();
        let verify_peer_certificate: Option<VerifyPeerCertificateFn> = {
            let connection_attempts = connection_attempts.clone();
            Some(Arc::new(
                move |certs: &[Vec<u8>], _chains: &[CertificateDer<'static>]| {
                    assert!(certs.len() == 1);
                    let fingerprints = certs
                        .iter()
                        .map(|c| crypto::generate_fingerprint(c))
                        .collect::<Vec<_>>();
                    if authorized
                        .read()
                        .expect("lock")
                        .contains_key(&fingerprints[0])
                    {
                        Ok(())
                    } else {
                        let fingerprint = fingerprints.into_iter().next().expect("fingerprint");
                        connection_attempts
                            .lock()
                            .expect("lock")
                            .push_back(fingerprint);
                        Err(webrtc_dtls::Error::ErrVerifyDataMismatch)
                    }
                },
            ))
        };
        let cfg = Config {
            certificates: vec![cert.clone()],
            extended_master_secret: ExtendedMasterSecretType::Require,
            client_auth: RequireAnyClientCert,
            verify_peer_certificate,
            ..Default::default()
        };

        let conns: Connections = Rc::new(RefCell::new(Vec::new()));

        // Bind one listener per local IPv4 address (skip loopback +
        // link-local) instead of a single 0.0.0.0:port listener. With
        // a single 0.0.0.0 bind on a multi-homed host, replies use
        // the kernel's preferred outbound interface as source IP —
        // which may not match the IP the peer dialed, breaking QUIC
        // 4-tuple matching. Per-IP binds make replies symmetric
        // automatically: each listener's reply socket is bound to a
        // specific IP, so the kernel uses *that* IP as source.
        let initial_addrs = enumerate_listenable_ipv4();
        if initial_addrs.is_empty() {
            // Fall back to 0.0.0.0 so we at least listen somewhere if
            // interface enumeration fails (very unusual).
            log::warn!("no listenable IPv4 addresses found; falling back to 0.0.0.0");
        }
        let mut listeners: HashMap<IpAddr, ListenerSlot> = HashMap::new();
        let mut bound_count = 0usize;
        for ip in &initial_addrs {
            match try_bind_listener(*ip, port, &cfg).await {
                Ok(listener) => {
                    let slot = spawn_accept_task(
                        listener,
                        listen_tx.clone(),
                        conns.clone(),
                        connection_attempts.clone(),
                    );
                    listeners.insert(*ip, slot);
                    bound_count += 1;
                    log::info!("listening for DTLS on {ip}:{port}");
                }
                Err(e) => log::warn!("failed to bind listener on {ip}:{port}: {e}"),
            }
        }
        if bound_count == 0 {
            // Either enumeration returned no addrs, or every bind
            // failed. Try `0.0.0.0:port` as a last resort.
            let fallback = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
            match try_bind_listener(fallback, port, &cfg).await {
                Ok(listener) => {
                    let slot = spawn_accept_task(
                        listener,
                        listen_tx.clone(),
                        conns.clone(),
                        connection_attempts.clone(),
                    );
                    listeners.insert(fallback, slot);
                    log::info!(
                        "listening for DTLS on {fallback}:{port} (fallback — symmetric replies not guaranteed)"
                    );
                }
                Err(e) => return Err(e),
            }
        }

        let listen_task = spawn_supervisor_task(
            port,
            cfg,
            listeners,
            listen_tx.clone(),
            conns.clone(),
            connection_attempts,
            request_port_change_rx,
            port_changed_tx,
        );

        Ok(Self {
            conns,
            listen_rx,
            listen_tx,
            listen_task,
            port_changed,
            request_port_change,
        })
    }

    pub(crate) fn request_port_change(&mut self, port: u16) {
        self.request_port_change
            .send(ListenerRequest::ChangePort(port))
            .expect("channel closed");
    }

    pub(crate) async fn port_changed(&mut self) -> Result<u16, ListenerCreationError> {
        self.port_changed.recv().await.expect("channel closed")
    }

    pub(crate) async fn terminate(&mut self) {
        let _ = self.request_port_change.send(ListenerRequest::Terminate);
        let _ = (&mut self.listen_task).await;
        self.listen_tx.close();
    }

    pub(crate) fn is_current_session(&self, addr: SocketAddr, session: SessionId) -> bool {
        self.conns
            .borrow()
            .iter()
            .rev()
            .find(|c| c.addr == addr)
            .is_some_and(|c| c.session == session)
    }

    pub(crate) async fn reply(&self, addr: SocketAddr, event: ProtoEvent) {
        log::trace!("reply {event} >=>=>=>=>=> {addr}");
        let (buf, len): ([u8; MAX_EVENT_SIZE], usize) = event.into();
        let conn = self
            .conns
            .borrow()
            .iter()
            .rev()
            .find(|c| c.addr == addr)
            .map(|c| c.conn.clone());
        if let Some(conn) = conn {
            let _ = conn.send(&buf[..len]).await;
        }
    }

    pub(crate) async fn get_certificate_fingerprint(&self, addr: SocketAddr) -> Option<String> {
        let conn = self
            .conns
            .borrow()
            .iter()
            .rev()
            .find(|c| c.addr == addr)
            .map(|c| c.conn.clone());
        if let Some(conn) = conn {
            let conn: &DTLSConn = conn.as_any().downcast_ref().expect("dtls conn");
            let certs = conn.connection_state().await.peer_certificates;
            let cert = certs.first()?;
            let fingerprint = crypto::generate_fingerprint(cert);
            Some(fingerprint)
        } else {
            None
        }
    }
}

impl Stream for LanMouseListener {
    type Item = ListenEvent;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.listen_rx.poll_next_unpin(cx)
    }
}

/// Enumerate local IPv4 addresses suitable for binding a public
/// listener: skip loopback (127.0.0.0/8) and link-local
/// (169.254.0.0/16) since neither is reachable from a peer. IPv6
/// is intentionally omitted — lan-mouse is IPv4-only on the wire
/// today.
fn enumerate_listenable_ipv4() -> Vec<IpAddr> {
    let ifaces = match if_addrs::get_if_addrs() {
        Ok(v) => v,
        Err(e) => {
            log::warn!("get_if_addrs failed: {e}");
            return Vec::new();
        }
    };
    ifaces
        .into_iter()
        .filter_map(|iface| match iface.addr {
            if_addrs::IfAddr::V4(v4) => Some(v4.ip),
            if_addrs::IfAddr::V6(_) => None,
        })
        .filter(|ip| !ip.is_loopback() && !ip.is_link_local())
        .map(IpAddr::V4)
        .collect()
}

async fn try_bind_listener(
    ip: IpAddr,
    port: u16,
    cfg: &Config,
) -> Result<DynListener, ListenerCreationError> {
    let addr = SocketAddr::new(ip, port);
    let listener = listen(addr, cfg.clone()).await?;
    Ok(Arc::new(listener))
}

/// Spawn an accept loop for one bound listener. Each accepted
/// `(conn, addr)` is registered in the shared `conns` vec and an
/// `Accept` event is published. Verify-peer-certificate failures are
/// re-published as `Rejected` so the UI can surface unauthorized
/// fingerprints. The accept loop exits when the listener errors
/// out or its task is aborted (interface went down, port changed).
/// The returned slot owns every accepted connection and reader.
fn spawn_accept_task(
    listener: DynListener,
    listen_tx: Sender<ListenEvent>,
    conns: Connections,
    connection_attempts: Arc<Mutex<VecDeque<String>>>,
) -> ListenerSlot {
    let sessions: Sessions = Rc::new(RefCell::new(HashMap::new()));
    let accept_sessions = sessions.clone();
    let accept_listener = listener.clone();
    let slot_conns = conns.clone();
    let slot_listen_tx = listen_tx.clone();
    let accept_task = spawn_local(async move {
        loop {
            // workaround for https://github.com/webrtc-rs/webrtc/issues/614
            let sleep = tokio::time::sleep(Duration::from_secs(2));
            tokio::select! {
                _ = sleep => continue,
                c = accept_listener.accept() => match c {
                    Ok((conn, addr)) => {
                        log::info!("dtls client connected, ip: {addr}");
                        let session = SessionId::new();
                        // Record ownership immediately, before certificate lookup can
                        // yield and the accept task can be cancelled.
                        accept_sessions.borrow_mut().insert(session, AcceptedConnection {
                            addr, conn: conn.clone(), read_task: None,
                        });
                        let dtls_conn: &DTLSConn = conn.as_any().downcast_ref().expect("dtls conn");
                        let certs = dtls_conn.connection_state().await.peer_certificates;
                        let cert = certs.first().expect("cert");
                        let fingerprint = crypto::generate_fingerprint(cert);
                        conns.borrow_mut().push(RegisteredConnection {
                            addr, session, conn: conn.clone(),
                        });
                        let _ = listen_tx.send(ListenEvent::Accept { addr, fingerprint, session });
                        let task = spawn_local(read_loop(
                            conns.clone(), accept_sessions.clone(), session, addr, conn, listen_tx.clone(),
                        ));
                        accept_sessions.borrow_mut().get_mut(&session).expect("accepted session").read_task = Some(task);
                    }
                    Err(e) => {
                        if let Error::Std(ref se) = e {
                            if let Some(de) = se.0.downcast_ref::<webrtc_dtls::Error>() {
                                match de {
                                    webrtc_dtls::Error::ErrVerifyDataMismatch => {
                                        if let Some(fingerprint) =
                                            connection_attempts.lock().expect("lock").pop_front()
                                        {
                                            listen_tx
                                                .send(ListenEvent::Rejected { fingerprint })
                                                .expect("channel closed");
                                        }
                                    }
                                    _ => log::warn!("accept: {de}"),
                                }
                            } else {
                                log::warn!("accept: {se:?}");
                            }
                        } else {
                            log::warn!("accept: {e:?}");
                        }
                    }
                },
            };
        }
    });
    ListenerSlot {
        listener: Some(listener),
        accept_task: Some(accept_task),
        sessions,
        conns: slot_conns,
        listen_tx: slot_listen_tx,
    }
}

/// Supervisor task: owns the set of active listeners, watches for
/// interface up/down events via `if_watch`, and rebuilds listeners
/// on port change. Each listener slot is keyed by its local IPv4
/// address; on `IfEvent::Up` we add a slot, on `IfEvent::Down` we
/// completely shut down that binding before any replacement is created.
#[allow(clippy::too_many_arguments)]
fn spawn_supervisor_task(
    initial_port: u16,
    cfg: Config,
    initial_listeners: HashMap<IpAddr, ListenerSlot>,
    listen_tx: Sender<ListenEvent>,
    conns: Connections,
    connection_attempts: Arc<Mutex<VecDeque<String>>>,
    mut request_port_change_rx: Receiver<ListenerRequest>,
    port_changed_tx: Sender<Result<u16, ListenerCreationError>>,
) -> JoinHandle<()> {
    spawn_local(async move {
        let mut port = initial_port;
        let mut listeners = initial_listeners;
        let mut watcher = match if_watch::tokio::IfWatcher::new() {
            Ok(w) => Some(w),
            Err(e) => {
                log::warn!(
                    "if_watch::IfWatcher::new failed: {e}; interface plug/unplug \
                     will not be detected (restart lan-mouse to pick up new addrs)"
                );
                None
            }
        };
        // Periodic reconciliation: enumerate live IPs and diff against
        // `listeners`. Network.framework on macOS doesn't reliably fire
        // `IfEvent::Down` when an interface is administratively
        // disabled (e.g. user toggles Wi-Fi off in System Settings),
        // leaving stale slots bound to vanished IPs that no traffic
        // can reach. Polling every 30s catches whatever if-watch
        // misses — both adds (covers missed Up events too) and drops.
        // `Skip` so a long suspend (laptop closed for hours) doesn't
        // burst-fire backlog ticks at resume.
        let mut reconcile_tick = tokio::time::interval(Duration::from_secs(30));
        reconcile_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // Skip the immediate-first tick — we just enumerated at startup
        // and don't want to thrash listeners on the first iteration.
        reconcile_tick.tick().await;
        loop {
            tokio::select! {
                _ = reconcile_tick.tick() => {
                    let current_ips: HashSet<IpAddr> =
                        enumerate_listenable_ipv4().into_iter().collect();
                    let to_drop: Vec<IpAddr> = listeners
                        .keys()
                        .filter(|ip| !current_ips.contains(*ip))
                        .copied()
                        .collect();
                    for ip in to_drop {
                        // `to_drop` was just collected from
                        // `listeners.keys()` and we run single-
                        // threaded, so the remove always returns Some.
                        if let Some(slot) = listeners.remove(&ip) {
                            slot.shutdown(&conns, &listen_tx).await;
                        }
                        log::info!(
                            "reconcile: dropping stale listener on {ip}:{port} \
                             (IP no longer present on any interface)"
                        );
                    }
                    // `try_bind_listener` is async and may fail, so
                    // `entry().or_insert_with(...)` doesn't fit — we
                    // only want to insert on bind success. Match the
                    // `Entry::Vacant` slot up front so the same hash
                    // lookup covers both the existence check and the
                    // later insert, satisfying clippy::map_entry.
                    for ip in current_ips {
                        if let std::collections::hash_map::Entry::Vacant(slot) =
                            listeners.entry(ip)
                        {
                            match try_bind_listener(ip, port, &cfg).await {
                                Ok(l) => {
                                    let listener_slot = spawn_accept_task(
                                        l,
                                        listen_tx.clone(),
                                        conns.clone(),
                                        connection_attempts.clone(),
                                    );
                                    slot.insert(listener_slot);
                                    log::info!(
                                        "reconcile: now listening on {ip}:{port} \
                                         (IP appeared without an Up event)"
                                    );
                                }
                                Err(e) => log::warn!(
                                    "reconcile: failed to bind on {ip}:{port}: {e}"
                                ),
                            }
                        }
                    }
                }
                ev = async {
                    match watcher.as_mut() {
                        Some(w) => w.select_next_some().await,
                        None => std::future::pending().await,
                    }
                } => match ev {
                    Ok(if_watch::IfEvent::Up(net)) => {
                        let ip = net.addr();
                        let usable = if let IpAddr::V4(v4) = ip {
                            !v4.is_loopback() && !v4.is_link_local()
                        } else {
                            false
                        };
                        if usable && !listeners.contains_key(&ip) {
                            match try_bind_listener(ip, port, &cfg).await {
                                Ok(l) => {
                                    let listener_slot = spawn_accept_task(
                                        l,
                                        listen_tx.clone(),
                                        conns.clone(),
                                        connection_attempts.clone(),
                                    );
                                    listeners.insert(ip, listener_slot);
                                    log::info!("interface up: now listening on {ip}:{port}");
                                }
                                Err(e) => log::warn!("failed to bind on {ip}:{port}: {e}"),
                            }
                        }
                    }
                    Ok(if_watch::IfEvent::Down(net)) => {
                        let ip = net.addr();
                        if let Some(slot) = listeners.remove(&ip) {
                            slot.shutdown(&conns, &listen_tx).await;
                            log::info!("interface down: stopped listening on {ip}:{port}");
                        }
                    }
                    Err(e) => log::debug!("if_watch error: {e}"),
                },
                p = request_port_change_rx.recv() => {
                    let new_port = match p {
                        Some(ListenerRequest::ChangePort(port)) => port,
                        Some(ListenerRequest::Terminate) | None => break,
                    };
                    shutdown_listeners(&mut listeners, &conns, &listen_tx).await;
                    let mut bound = 0usize;
                    let addrs = enumerate_listenable_ipv4();
                    for ip in &addrs {
                        match try_bind_listener(*ip, new_port, &cfg).await {
                            Ok(l) => {
                                let slot = spawn_accept_task(
                                    l,
                                    listen_tx.clone(),
                                    conns.clone(),
                                    connection_attempts.clone(),
                                );
                                listeners.insert(*ip, slot);
                                bound += 1;
                            }
                            Err(e) => log::warn!("port change: failed to bind {ip}:{new_port}: {e}"),
                        }
                    }
                    if bound == 0 {
                        port_changed_tx
                            .send(Err(ListenerCreationError::NoBoundListener))
                            .expect("channel closed");
                    } else {
                        port = new_port;
                        port_changed_tx
                            .send(Ok(port))
                            .expect("channel closed");
                    }
                }
            }
        }
        shutdown_listeners(&mut listeners, &conns, &listen_tx).await;
    })
}

async fn shutdown_listeners(
    listeners: &mut HashMap<IpAddr, ListenerSlot>,
    conns: &Connections,
    listen_tx: &Sender<ListenEvent>,
) {
    let slots: Vec<_> = listeners.drain().map(|(_, slot)| slot).collect();
    join_all(
        slots
            .into_iter()
            .map(|slot| slot.shutdown(conns, listen_tx)),
    )
    .await;
}

async fn read_loop(
    conns: Connections,
    sessions: Sessions,
    session: SessionId,
    addr: SocketAddr,
    conn: ArcConn,
    dtls_tx: Sender<ListenEvent>,
) {
    // Buffer sized for the largest legal clipboard frame; mouse /
    // keyboard datagrams use only the first MAX_EVENT_SIZE bytes.
    let mut b = [0u8; MAX_CLIPBOARD_SIZE];

    while let Ok(n) = conn.recv(&mut b).await {
        if n == 0 {
            continue;
        }
        let datagram = &b[..n];
        match decode_listen_datagram(datagram) {
            Some(event) => dtls_tx
                .send(ListenEvent::Msg {
                    event,
                    addr,
                    session,
                })
                .expect("channel closed"),
            None => {
                // Skip the malformed/unknown datagram and keep
                // listening. Each DTLS recv returns one full
                // datagram, so a parse error here can't desync a
                // stream; the next call gets a fresh, framed
                // message. This makes the protocol forward-
                // compatible: a peer running a newer Lan Mouse
                // version can introduce additional event types
                // and old peers will simply ignore them rather
                // than dropping the connection.
                log::debug!("ignoring undecodable {n}-byte event from {addr}");
            }
        }
    }
    log::info!("dtls client disconnected {addr:?}");
    retire_connection(&conns, session, addr, &dtls_tx);
    close_connection(&conn).await;
    sessions.borrow_mut().remove(&session);
}

/// Classify a DTLS datagram by its first-byte event-type tag and
/// route through the variable-length clipboard codec or the fixed-
/// buffer `try_into` path. Mirrors `decode_proto_datagram` on the
/// connect side so both directions accept the same wire formats.
fn decode_listen_datagram(bytes: &[u8]) -> Option<ProtoEvent> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::net::UdpSocket;

    fn run_local(future: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(tokio::task::LocalSet::new().run_until(future));
    }

    fn server_config() -> Config {
        Config {
            certificates: vec![Certificate::generate_self_signed(["test".to_owned()]).unwrap()],
            extended_master_secret: ExtendedMasterSecretType::Require,
            client_auth: RequireAnyClientCert,
            ..Default::default()
        }
    }

    async fn connect(addr: SocketAddr) -> ArcConn {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(addr).await.unwrap();
        let cfg = Config {
            certificates: vec![Certificate::generate_self_signed(["test".to_owned()]).unwrap()],
            extended_master_secret: ExtendedMasterSecretType::Require,
            insecure_skip_verify: true,
            ..Default::default()
        };
        Arc::new(
            DTLSConn::new(Arc::new(socket), cfg, true, None)
                .await
                .unwrap(),
        )
    }

    #[test]
    fn active_dtls_shutdown_rebinds_and_accepts_repeatedly() {
        run_local(async {
            let cfg = server_config();
            let conns: Connections = Default::default();
            let attempts = Default::default();
            let (tx, mut rx) = channel();
            let listener = try_bind_listener("127.0.0.1".parse().unwrap(), 0, &cfg)
                .await
                .unwrap();
            let addr = listener.addr().await.unwrap();
            let mut slot = spawn_accept_task(listener, tx.clone(), conns.clone(), attempts);
            for _ in 0..4 {
                let client = tokio::time::timeout(Duration::from_secs(5), connect(addr))
                    .await
                    .unwrap();
                let accepted = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert!(matches!(accepted, ListenEvent::Accept { .. }));
                let (buf, len): ([u8; MAX_EVENT_SIZE], usize) = ProtoEvent::Ping.into();
                client.send(&buf[..len]).await.unwrap();
                let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert!(matches!(
                    event,
                    ListenEvent::Msg {
                        event: ProtoEvent::Ping,
                        ..
                    }
                ));
                slot.shutdown(&conns, &tx).await;
                assert!(conns.borrow().is_empty());
                assert!(matches!(
                    rx.recv().await,
                    Some(ListenEvent::Disconnected { .. })
                ));
                drop(client);
                let listener = try_bind_listener(addr.ip(), addr.port(), &cfg)
                    .await
                    .unwrap();
                slot = spawn_accept_task(listener, tx.clone(), conns.clone(), Default::default());
            }
            slot.shutdown(&conns, &tx).await;
        });
    }

    struct TestConn {
        socket: UdpSocket,
        hang_close: bool,
    }

    #[async_trait]
    impl Conn for TestConn {
        async fn connect(&self, addr: SocketAddr) -> webrtc_util::Result<()> {
            self.socket.connect(addr).await.map_err(Into::into)
        }
        async fn recv(&self, _: &mut [u8]) -> webrtc_util::Result<usize> {
            std::future::pending().await
        }
        async fn recv_from(&self, _: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
        async fn send(&self, _: &[u8]) -> webrtc_util::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe).into())
        }
        async fn send_to(&self, buf: &[u8], _: SocketAddr) -> webrtc_util::Result<usize> {
            self.send(buf).await
        }
        fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
            self.socket.local_addr().map_err(Into::into)
        }
        fn remote_addr(&self) -> Option<SocketAddr> {
            None
        }
        async fn close(&self) -> webrtc_util::Result<()> {
            if self.hang_close {
                std::future::pending().await
            } else {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe).into())
            }
        }
        fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
            self
        }
    }

    struct TestListener(Arc<AtomicBool>);
    #[async_trait]
    impl Listener for TestListener {
        async fn accept(&self) -> webrtc_util::Result<(ArcConn, SocketAddr)> {
            std::future::pending().await
        }
        async fn close(&self) -> webrtc_util::Result<()> {
            self.0.store(true, Ordering::SeqCst);
            Ok(())
        }
        async fn addr(&self) -> webrtc_util::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }
    }

    fn add_test_session(
        slot: &ListenerSlot,
        conns: &Connections,
        addr: SocketAddr,
        conn: ArcConn,
    ) -> SessionId {
        let session = SessionId::new();
        conns.borrow_mut().push(RegisteredConnection {
            addr,
            session,
            conn: conn.clone(),
        });
        let reader_conn = conn.clone();
        let read_task = spawn_local(async move {
            let mut buf = [0; 1];
            let _ = reader_conn.recv(&mut buf).await;
        });
        slot.sessions.borrow_mut().insert(
            session,
            AcceptedConnection {
                addr,
                conn,
                read_task: Some(read_task),
            },
        );
        session
    }

    #[test]
    fn supervisor_termination_drains_every_binding_with_one_close_budget() {
        run_local(async {
            let conns: Connections = Default::default();
            let (tx, mut rx) = channel();
            let (request_tx, request_rx) = channel();
            let (port_tx, _) = channel();
            let mut listeners = HashMap::new();
            let mut retired = Vec::new();
            let mut closed = Vec::new();
            for ip in ["127.0.0.1", "127.0.0.2"] {
                let flag = Arc::new(AtomicBool::new(false));
                let slot = spawn_accept_task(
                    Arc::new(TestListener(flag.clone())),
                    tx.clone(),
                    conns.clone(),
                    Default::default(),
                );
                let conn: ArcConn = Arc::new(TestConn {
                    socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
                    hang_close: true,
                });
                retired.push(Arc::downgrade(&conn));
                add_test_session(&slot, &conns, "127.0.0.1:5555".parse().unwrap(), conn);
                listeners.insert(ip.parse().unwrap(), slot);
                closed.push(flag);
            }
            let task = spawn_supervisor_task(
                0,
                server_config(),
                listeners,
                tx,
                conns.clone(),
                Default::default(),
                request_rx,
                port_tx,
            );
            request_tx.send(ListenerRequest::Terminate).unwrap();
            tokio::time::timeout(Duration::from_millis(1800), task)
                .await
                .unwrap()
                .unwrap();
            assert!(conns.borrow().is_empty());
            assert!(retired.into_iter().all(|weak| weak.upgrade().is_none()));
            assert!(closed.into_iter().all(|flag| flag.load(Ordering::SeqCst)));
            for _ in 0..2 {
                assert!(matches!(
                    rx.recv().await,
                    Some(ListenEvent::Disconnected { .. })
                ));
            }
        });
    }

    #[test]
    fn failed_and_hung_close_retire_only_the_owned_binding() {
        run_local(async {
            let conns: Connections = Default::default();
            let (tx, mut rx) = channel();
            let closed = Arc::new(AtomicBool::new(false));
            let slot = spawn_accept_task(
                Arc::new(TestListener(closed.clone())),
                tx.clone(),
                conns.clone(),
                Default::default(),
            );
            let sibling_closed = Arc::new(AtomicBool::new(false));
            let sibling = spawn_accept_task(
                Arc::new(TestListener(sibling_closed.clone())),
                tx.clone(),
                conns.clone(),
                Default::default(),
            );
            let peer = "127.0.0.1:5555".parse().unwrap();
            let mut retired = Vec::new();
            let mut old_ids = Vec::new();
            for hang_close in [false, true] {
                let conn: ArcConn = Arc::new(TestConn {
                    socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
                    hang_close,
                });
                retired.push((conn.local_addr().unwrap(), Arc::downgrade(&conn)));
                old_ids.push(add_test_session(&slot, &conns, peer, conn));
            }
            let survivor: ArcConn = Arc::new(TestConn {
                socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
                hang_close: false,
            });
            let survivor_addr = survivor.local_addr().unwrap();
            let survivor_id = add_test_session(&sibling, &conns, peer, survivor);
            tokio::task::yield_now().await;
            tokio::time::timeout(Duration::from_secs(2), slot.shutdown(&conns, &tx))
                .await
                .unwrap();
            assert!(closed.load(Ordering::SeqCst));
            assert!(!sibling_closed.load(Ordering::SeqCst));
            assert_eq!(conns.borrow().len(), 1);
            assert_eq!(conns.borrow()[0].session, survivor_id);
            for (addr, weak) in retired {
                assert!(weak.upgrade().is_none());
                assert!(UdpSocket::bind(addr).await.is_ok());
            }
            assert!(UdpSocket::bind(survivor_addr).await.is_err());
            // A stale reader's cleanup neither panics nor removes its sibling.
            retire_connection(&conns, old_ids[0], peer, &tx);
            assert_eq!(conns.borrow()[0].session, survivor_id);
            let mut disconnected = HashSet::new();
            for _ in 0..old_ids.len() {
                if let Some(ListenEvent::Disconnected { session, .. }) = rx.recv().await {
                    disconnected.insert(session);
                } else {
                    panic!("expected disconnect");
                }
            }
            assert_eq!(disconnected, old_ids.into_iter().collect());
            sibling.shutdown(&conns, &tx).await;
            assert!(conns.borrow().is_empty());
        });
    }
}
