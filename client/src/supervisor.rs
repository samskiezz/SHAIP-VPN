//! Keeps a tunnel up for as long as the user wants it: keepalive pings,
//! dead-peer detection, reconnection with backoff, and rekeying by a fresh
//! handshake. Shared by the CLI (`pqanon run`) and native shells through the
//! C ABI, so every front end gets the same behaviour.
//!
//! - **Keepalive.** Every `keepalive` interval the current session pings the
//!   server; the PONG gives the round-trip time shown to the user.
//! - **Dead peer.** If nothing authenticated arrives for `dead_after` (the
//!   pings go unanswered), the session is abandoned and a new one is
//!   negotiated, with exponential backoff while the server stays unreachable.
//!   A `Close` from the server (it is shutting down) triggers the same at once.
//! - **Rekey.** After `rekey_after`, or well before either direction can
//!   exhaust its nonce space, a new handshake runs on a new socket while the
//!   old session keeps carrying traffic; the new one takes over when the
//!   server confirms it (make-before-break). Each handshake yields fresh
//!   ML-KEM-768 + X25519 secrets, so keys do not outlive `rekey_after`.
//!
//! While no session is up, outbound packets are dropped (counted), never sent
//! anywhere else: the OS still routes them into the tunnel interface.

use crate::client::{ClientConfig, SessionClosed, SessionInfo, Tunnel, TunnelStats};
use crate::reconnect::Backoff;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, watch};

/// Received packets buffered between the socket and the consumer.
const RX_QUEUE: usize = 1024;

/// Called before every reconnection attempt (e.g. to re-point the host route
/// to the server after the network changed).
pub type BeforeConnect = Arc<dyn Fn() + Send + Sync>;

/// What a [`ManagedTunnel`] needs.
#[derive(Clone)]
pub struct SupervisorConfig {
    pub tunnel: ClientConfig,
    /// Ping interval.
    pub keepalive: Duration,
    /// Declare the session dead after this long without an authenticated packet.
    pub dead_after: Duration,
    /// Replace the session with a fresh handshake after this long.
    pub rekey_after: Duration,
    pub backoff_base: Duration,
    pub backoff_max: Duration,
    pub before_connect: Option<BeforeConnect>,
}

impl SupervisorConfig {
    /// Defaults: ping every 10 s, dead after 35 s of silence, rekey every 20
    /// minutes, reconnect backoff 0.5 s → 30 s.
    pub fn new(tunnel: ClientConfig) -> Self {
        SupervisorConfig {
            tunnel,
            keepalive: Duration::from_secs(10),
            dead_after: Duration::from_secs(35),
            rekey_after: Duration::from_secs(20 * 60),
            backoff_base: Duration::from_millis(500),
            backoff_max: Duration::from_secs(30),
            before_connect: None,
        }
    }
}

/// Where the link is in its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    /// A confirmed session is carrying traffic.
    Connected,
    /// The last session failed; negotiating a new one.
    Reconnecting,
    /// Stopped by the user.
    Stopped,
}

/// A snapshot for status displays.
#[derive(Clone, Debug)]
pub struct Status {
    pub state: LinkState,
    /// The current session's parameters (the last one's while reconnecting).
    pub info: SessionInfo,
    /// The server's identity id, as matched against the pinned keys.
    pub server_identity: [u8; 16],
    /// The server's UDP address, as resolved for the current (or last) session.
    pub server_addr: std::net::SocketAddr,
    /// Since when the link has been continuously up (rekeys do not reset it).
    pub up_since: Option<SystemTime>,
    /// Smoothed keepalive round-trip time of the current session.
    pub rtt: Option<Duration>,
    /// Totals across every session of this link.
    pub stats: TunnelStats,
    /// Outbound packets dropped because no session was up.
    pub dropped_offline: u64,
    /// Sessions re-established after a failure.
    pub reconnects: u32,
    /// Sessions replaced by a scheduled rekey.
    pub rekeys: u32,
    /// Why the last session ended, or why the last attempt failed.
    pub last_error: Option<String>,
}

enum Failure {
    Closed,
    Error(String),
}

struct Meta {
    state: LinkState,
    info: SessionInfo,
    server_identity: [u8; 16],
    server_addr: std::net::SocketAddr,
    up_since: Option<SystemTime>,
    finished: TunnelStats,
    reconnects: u32,
    rekeys: u32,
    last_error: Option<String>,
}

struct Shared {
    current: RwLock<Option<(u64, Arc<Tunnel>)>>,
    generation: watch::Sender<u64>,
    meta: Mutex<Meta>,
    changes: watch::Sender<u64>,
    stop: watch::Sender<bool>,
    rx_tx: mpsc::Sender<Vec<u8>>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    fail_tx: mpsc::UnboundedSender<(u64, Failure)>,
    reported: AtomicU64,
    dropped_offline: AtomicU64,
}

enum Installed {
    First,
    Reconnect,
    Rekey,
}

impl Shared {
    fn current(&self) -> Option<(u64, Arc<Tunnel>)> {
        self.current.read().expect("current lock").clone()
    }

    fn bump_changes(&self) {
        self.changes.send_modify(|c| *c += 1);
    }

    fn install(self: &Arc<Self>, t: Arc<Tunnel>, how: Installed) {
        let gen = {
            let mut cur = self.current.write().expect("current lock");
            let gen = *self.generation.borrow() + 1;
            if let Some((_, old)) = cur.replace((gen, t.clone())) {
                let mut m = self.meta.lock().expect("meta lock");
                m.finished = m.finished + old.stats();
            }
            gen
        };
        self.generation.send_replace(gen);
        {
            let mut m = self.meta.lock().expect("meta lock");
            if m.state != LinkState::Connected {
                m.up_since = Some(SystemTime::now());
            }
            m.state = LinkState::Connected;
            m.info = t.info();
            m.server_identity = t.server_identity();
            m.server_addr = t.server_addr();
            match how {
                Installed::First => {}
                Installed::Reconnect => m.reconnects += 1,
                Installed::Rekey => m.rekeys += 1,
            }
        }
        self.spawn_reader(gen, t);
        self.bump_changes();
    }

    fn uninstall(&self, state: LinkState, why: Option<String>) {
        if let Some((_, old)) = self.current.write().expect("current lock").take() {
            let mut m = self.meta.lock().expect("meta lock");
            m.finished = m.finished + old.stats();
        }
        self.generation.send_modify(|g| *g += 1);
        {
            let mut m = self.meta.lock().expect("meta lock");
            m.state = state;
            m.up_since = None;
            if why.is_some() {
                m.last_error = why;
            }
        }
        self.bump_changes();
    }

    fn set_error(&self, e: String) {
        self.meta.lock().expect("meta lock").last_error = Some(e);
        self.bump_changes();
    }

    /// Report a failure of generation `gen` once.
    fn report(&self, gen: u64, f: Failure) {
        if self.reported.swap(gen, Ordering::AcqRel) != gen {
            let _ = self.fail_tx.send((gen, f));
        }
    }

    /// Forward the session's packets to the consumer until it fails or is
    /// superseded.
    fn spawn_reader(self: &Arc<Self>, gen: u64, t: Arc<Tunnel>) {
        let shared = self.clone();
        let mut generation = self.generation.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    r = t.recv() => match r {
                        Ok(pkt) => {
                            if shared.rx_tx.send(pkt).await.is_err() {
                                return;
                            }
                        }
                        Err(e) => {
                            let f = if e.downcast_ref::<SessionClosed>().is_some() {
                                Failure::Closed
                            } else {
                                Failure::Error(format!("{e:#}"))
                            };
                            shared.report(gen, f);
                            return;
                        }
                    },
                    _ = superseded(&mut generation, gen) => return,
                }
            }
        });
    }
}

/// A tunnel that stays up: see the module docs.
pub struct ManagedTunnel {
    shared: Arc<Shared>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ManagedTunnel {
    /// Connect, and once the server confirms the first session, keep the link
    /// up in the background. The first attempt's error is returned as is
    /// (wrong pins, not admitted, unreachable), so a misconfiguration fails
    /// fast instead of retrying forever. Must be called inside a tokio runtime.
    pub async fn start(cfg: SupervisorConfig) -> anyhow::Result<ManagedTunnel> {
        let first = Arc::new(Tunnel::connect(cfg.tunnel.clone()).await?);
        let (rx_tx, rx) = mpsc::channel(RX_QUEUE);
        let (fail_tx, fail_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            current: RwLock::new(None),
            generation: watch::channel(0).0,
            meta: Mutex::new(Meta {
                state: LinkState::Reconnecting,
                info: first.info(),
                server_identity: first.server_identity(),
                server_addr: first.server_addr(),
                up_since: None,
                finished: TunnelStats::default(),
                reconnects: 0,
                rekeys: 0,
                last_error: None,
            }),
            changes: watch::channel(0).0,
            stop: watch::channel(false).0,
            rx_tx,
            rx: tokio::sync::Mutex::new(rx),
            fail_tx,
            reported: AtomicU64::new(0),
            dropped_offline: AtomicU64::new(0),
        });
        tracing::info!(
            conn_id = format!("{:#018x}", first.conn_id()),
            assigned = ?first.info().assigned_v4,
            "tunnel up: the server confirmed the session"
        );
        shared.install(first.clone(), Installed::First);
        let task = tokio::spawn(supervise(shared.clone(), cfg, first, fail_rx));
        Ok(ManagedTunnel {
            shared,
            task: Mutex::new(Some(task)),
        })
    }

    /// Send one IP packet through the current session. With no session up the
    /// packet is dropped (and counted); a send error triggers a reconnect. It
    /// never fails, so a packet pump can call it in a loop.
    pub async fn send(&self, ip_packet: &[u8]) {
        match self.shared.current() {
            Some((gen, t)) => {
                if let Err(e) = t.send(ip_packet).await {
                    self.shared.report(gen, Failure::Error(format!("send failed: {e:#}")));
                }
            }
            None => {
                self.shared.dropped_offline.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// The next IP packet from the server, across reconnects. Fails only once
    /// the link is stopped.
    pub async fn recv(&self) -> anyhow::Result<Vec<u8>> {
        let mut stop = self.shared.stop.subscribe();
        let mut rx = self.shared.rx.lock().await;
        tokio::select! {
            p = rx.recv() => p.ok_or_else(|| anyhow::anyhow!("tunnel stopped")),
            _ = stopped(&mut stop) => anyhow::bail!("tunnel stopped"),
        }
    }

    /// The current status (cheap; poll it for a display).
    pub fn status(&self) -> Status {
        let current = self.shared.current();
        let m = self.shared.meta.lock().expect("meta lock");
        let live = current.as_ref().map(|(_, t)| t.stats()).unwrap_or_default();
        Status {
            state: m.state,
            info: m.info,
            server_identity: m.server_identity,
            server_addr: m.server_addr,
            up_since: m.up_since,
            rtt: current.as_ref().and_then(|(_, t)| t.rtt()),
            stats: m.finished + live,
            dropped_offline: self.shared.dropped_offline.load(Ordering::Relaxed),
            reconnects: m.reconnects,
            rekeys: m.rekeys,
            last_error: m.last_error.clone(),
        }
    }

    /// Abandon the current session and negotiate a new one now — e.g. when
    /// the device moved to another network, where the old session's UDP
    /// flow can no longer reach the server and waiting for the dead-peer
    /// timer would leave the user offline for `dead_after`.
    pub fn reconnect_now(&self, why: &str) {
        if let Some((gen, _)) = self.shared.current() {
            self.shared.report(gen, Failure::Error(why.to_string()));
        }
    }

    /// A receiver that changes whenever the state, the session, or the last
    /// error does (RTT and counters change continuously; poll [`status`]).
    ///
    /// [`status`]: ManagedTunnel::status
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.shared.changes.subscribe()
    }

    /// Close the session (telling the server) and stop supervising.
    pub async fn stop(&self) {
        self.shared.stop.send_replace(true);
        let task = self.task.lock().expect("task lock").take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }
}

impl Drop for ManagedTunnel {
    fn drop(&mut self) {
        // The supervisor sees this, sends Close and exits.
        self.shared.stop.send_replace(true);
    }
}

/// Resolves once the link is told to stop (the guard `wait_for` returns is
/// not `Send`, so it must not live in a `select!` that awaits elsewhere).
async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|s| *s).await;
}

/// Resolves once a newer session has replaced generation `gen`.
async fn superseded(generation: &mut watch::Receiver<u64>, gen: u64) {
    let _ = generation.wait_for(|g| *g != gen).await;
}

enum End {
    Stop,
    Rekey,
    Failed(String),
}

async fn supervise(
    shared: Arc<Shared>,
    cfg: SupervisorConfig,
    mut tunnel: Arc<Tunnel>,
    mut fail_rx: mpsc::UnboundedReceiver<(u64, Failure)>,
) {
    let mut stop = shared.stop.subscribe();
    let mut backoff = Backoff::new(
        cfg.backoff_base.as_millis() as u64,
        cfg.backoff_max.as_millis() as u64,
    );
    let mut rekey_after = cfg.rekey_after;
    loop {
        let gen = *shared.generation.borrow();
        match run_session(&cfg, &tunnel, gen, rekey_after, &mut fail_rx, &mut stop).await {
            End::Stop => {
                tunnel.close().await;
                shared.uninstall(LinkState::Stopped, None);
                tracing::info!("tunnel stopped; the session was closed");
                return;
            }
            End::Rekey => {
                let next = tokio::select! {
                    r = Tunnel::connect(cfg.tunnel.clone()) => r,
                    _ = stopped(&mut stop) => continue, // run_session sees the stop
                };
                match next {
                    Ok(t) => {
                        let t = Arc::new(t);
                        tracing::info!(conn_id = format!("{:#018x}", t.conn_id()), "rekeyed: a fresh handshake replaced the session");
                        shared.install(t.clone(), Installed::Rekey);
                        tunnel = t;
                        rekey_after = cfg.rekey_after;
                    }
                    Err(e) if !tunnel.sequence_exhausting() => {
                        // The old session still works; keep it and retry soon.
                        tracing::warn!(error = %format!("{e:#}"), "rekey handshake failed; keeping the current session");
                        shared.set_error(format!("rekey failed: {e:#}"));
                        rekey_after = tunnel.age() + Duration::from_secs(30);
                    }
                    Err(e) => {
                        let why = format!("rekey failed with the session key exhausted: {e:#}");
                        match reconnect(&shared, &cfg, &mut backoff, &mut stop, why).await {
                            Some(t) => {
                                tunnel = t;
                                rekey_after = cfg.rekey_after;
                            }
                            None => return,
                        }
                    }
                }
            }
            End::Failed(why) => match reconnect(&shared, &cfg, &mut backoff, &mut stop, why).await {
                Some(t) => {
                    tunnel = t;
                    rekey_after = cfg.rekey_after;
                }
                None => return,
            },
        }
    }
}

/// Run one session until it fails, is due for a rekey, or the user stops.
async fn run_session(
    cfg: &SupervisorConfig,
    t: &Tunnel,
    gen: u64,
    rekey_after: Duration,
    fail_rx: &mut mpsc::UnboundedReceiver<(u64, Failure)>,
    stop: &mut watch::Receiver<bool>,
) -> End {
    let mut tick = tokio::time::interval(cfg.keepalive);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let rekey_at = tokio::time::Instant::now() + rekey_after.saturating_sub(t.age());
    let rekey = tokio::time::sleep_until(rekey_at);
    tokio::pin!(rekey);
    loop {
        tokio::select! {
            _ = stopped(stop) => return End::Stop,
            _ = &mut rekey => return End::Rekey,
            f = fail_rx.recv() => match f {
                Some((g, _)) if g != gen => {} // a superseded session
                Some((_, Failure::Closed)) => return End::Failed(SessionClosed.to_string()),
                Some((_, Failure::Error(e))) => return End::Failed(e),
                None => return End::Stop,
            },
            _ = tick.tick() => {
                if t.sequence_exhausting() {
                    return End::Rekey;
                }
                if t.info().keepalive {
                    let idle = t.idle_for();
                    if idle > cfg.dead_after {
                        return End::Failed(format!("no answer from the server for {}s", idle.as_secs()));
                    }
                    if let Err(e) = t.ping().await {
                        return End::Failed(format!("keepalive failed: {e:#}"));
                    }
                }
            }
        }
    }
}

/// Negotiate a new session after a failure, backing off while the server is
/// unreachable. `None` if the user stopped the link meanwhile.
async fn reconnect(
    shared: &Arc<Shared>,
    cfg: &SupervisorConfig,
    backoff: &mut Backoff,
    stop: &mut watch::Receiver<bool>,
    why: String,
) -> Option<Arc<Tunnel>> {
    tracing::warn!(reason = %why, "session lost; reconnecting");
    shared.uninstall(LinkState::Reconnecting, Some(why));
    loop {
        if *stop.borrow() {
            shared.uninstall(LinkState::Stopped, None);
            return None;
        }
        if let Some(hook) = &cfg.before_connect {
            hook();
        }
        let attempt = tokio::select! {
            r = Tunnel::connect(cfg.tunnel.clone()) => r,
            _ = stopped(stop) => {
                shared.uninstall(LinkState::Stopped, None);
                return None;
            }
        };
        match attempt {
            Ok(t) => {
                backoff.reset();
                let t = Arc::new(t);
                tracing::info!(
                    conn_id = format!("{:#018x}", t.conn_id()),
                    assigned = ?t.info().assigned_v4,
                    "reconnected: the server confirmed a new session"
                );
                shared.install(t.clone(), Installed::Reconnect);
                return Some(t);
            }
            Err(e) => {
                let delay = backoff.next_delay();
                tracing::warn!(error = %format!("{e:#}"), retry_in_ms = delay.as_millis() as u64, "reconnect attempt failed");
                shared.set_error(format!("{e:#}"));
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = stopped(stop) => {
                        shared.uninstall(LinkState::Stopped, None);
                        return None;
                    }
                }
            }
        }
    }
}
