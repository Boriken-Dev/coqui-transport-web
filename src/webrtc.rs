//! One UDP port for WebTransport and WebRTC data channels, and the ladder that climbs a WebSocket channel onto it.
//!
//! A [`Port`] owns a UDP socket and reads the first byte of each packet (RFC 9443): QUIC goes through a loopback relay to an
//! unmodified `wtransport` listener, STUN and DTLS to a data channel. A WebSocket whose ends agreed to climb starts with its datagrams
//! inside the stream, offers a data channel over the channel it already has, and switches when that opens.
//!
//! See [`Datagrams`](crate::Datagrams) for what a caller sees.

mod climb;
mod sdp;
mod worker;

use alloc::sync::Arc;
use core::fmt;
use core::net::{IpAddr, SocketAddr};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::time::Duration;
use std::io;
use std::net::UdpSocket;
use std::sync::mpsc;
use std::sync::{Mutex, PoisonError};
use std::thread;

use mio::{Poll, Waker};

pub(crate) use climb::{Climb, Plan};

use crate::failure::Failure;
use worker::{Command, Relays, WAKER, Worker};

/// How an offer and its answer reach the other end.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Signaling {
    /// On the WebSocket itself, as tagged messages: TLS is all that protects them, as it is for the datagrams they lead to.
    #[default]
    OnChannel,
    /// By the caller, through `Channel::next_signal` and `Channel::deliver_signal`. Carried inside a sealed, proven link, the DTLS
    /// fingerprints are bound to that proof, so the data channel's datagrams are too. A signal arriving any other way is ignored.
    ByCaller,
}

/// How a channel climbs, and what a [`Port`] allows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Settings {
    /// Whether to try at all. Off, a channel asks for nothing more than plain datagrams and sends no signal.
    pub enabled: bool,
    /// How long a data channel may take to open before the channel stays on the WebSocket for good. Only the attempt is lost.
    pub attempt: Duration,
    /// The largest IP packet the path is known to carry. It caps a data channel's datagrams, since a fragmented one is lost whenever
    /// any fragment is.
    pub path_mtu: usize,
    /// The address a [`Port`] names in its one candidate. Unset, it names the address the WebSocket connection arrived at, with the
    /// UDP port's number. Behind a proxy or NAT that is wrong, and it tells the peer an address it had no other way to learn.
    pub public_address: Option<SocketAddr>,
    /// Lets a dialer use a candidate at another address than the WebSocket's peer. Off, an answer naming another address is refused,
    /// so a peer cannot point this side's connectivity checks somewhere else.
    pub any_candidate: bool,
    /// How offers and answers travel.
    pub signaling: Signaling,
    /// Data channels a [`Port`] holds at once, past which an offer is refused.
    pub max_sessions: usize,
    /// QUIC sources a [`Port`] relays at once. A new one past this replaces the oldest that has never completed a handshake, or is
    /// dropped when every one has.
    pub max_relays: usize,
    /// Silence after which a relay ends. A source returning later gets a new one, which QUIC reads as a changed address. It should
    /// outlast the QUIC idle timeout.
    pub relay_idle: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            attempt: Duration::from_secs(5),
            path_mtu: 1280,
            public_address: None,
            any_candidate: false,
            signaling: Signaling::OnChannel,
            max_sessions: 256,
            max_relays: 1024,
            relay_idle: Duration::from_secs(120),
        }
    }
}

impl Settings {
    /// Sets whether to try.
    #[must_use]
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Sets how long a data channel may take to open.
    #[must_use]
    pub const fn with_attempt(mut self, limit: Duration) -> Self {
        self.attempt = limit;
        self
    }

    /// Sets the largest IP packet the path is known to carry.
    #[must_use]
    pub const fn with_path_mtu(mut self, bytes: usize) -> Self {
        self.path_mtu = bytes;
        self
    }

    /// Sets the address named in a [`Port`]'s candidate.
    #[must_use]
    pub const fn with_public_address(mut self, address: SocketAddr) -> Self {
        self.public_address = Some(address);
        self
    }

    /// Lets a dialer use a candidate at another address than the WebSocket's peer.
    #[must_use]
    pub const fn with_any_candidate(mut self) -> Self {
        self.any_candidate = true;
        self
    }

    /// Sets how offers and answers travel.
    #[must_use]
    pub const fn with_signaling(mut self, signaling: Signaling) -> Self {
        self.signaling = signaling;
        self
    }

    /// Sets how many data channels a [`Port`] holds at once.
    #[must_use]
    pub const fn with_max_sessions(mut self, sessions: usize) -> Self {
        self.max_sessions = sessions;
        self
    }

    /// Sets how many QUIC sources a [`Port`] relays at once.
    #[must_use]
    pub const fn with_max_relays(mut self, relays: usize) -> Self {
        self.max_relays = relays;
        self
    }

    /// Sets the silence after which a relay ends.
    #[must_use]
    pub const fn with_relay_idle(mut self, limit: Duration) -> Self {
        self.relay_idle = limit;
        self
    }
}

/// A UDP port shared by a WebTransport listener and data channels. One worker thread serves it and sleeps while nothing is due.
///
/// Clones share it. It ends when the last clone, and every listener and channel using it, has gone: then the socket and every relay
/// are closed and the thread has been joined.
#[derive(Clone)]
pub struct Port {
    inner: Arc<Inner>,
}

struct Inner {
    address: SocketAddr,
    settings: Settings,
    commands: mpsc::Sender<Command>,
    waker: Arc<Waker>,
    relays: Relays,
    next_session: AtomicU64,
    open_sessions: Arc<AtomicUsize>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}

impl fmt::Debug for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Port")
            .field("address", &self.inner.address)
            .field("settings", &self.inner.settings)
            .finish_non_exhaustive()
    }
}

impl Port {
    /// Binds a UDP `address`. A port number of 0 picks one, which [`local_addr`](Self::local_addr) says.
    ///
    /// # Errors
    ///
    /// [`Failure::Permission`] when the address is taken or not allowed; otherwise [`Failure::Unsupported`].
    pub fn bind(address: SocketAddr, settings: Settings) -> Result<Self, Failure> {
        let socket = UdpSocket::bind(address).map_err(|error| match error.kind() {
            io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied => Failure::Permission,
            _ => Failure::Unsupported,
        })?;
        Self::start(socket, settings, false)
    }

    /// A port for one dialer's data channel, on the address its WebSocket connection already uses, so an offer names nothing new.
    fn dialing(local: IpAddr, settings: Settings) -> Result<Self, Failure> {
        let socket =
            UdpSocket::bind(SocketAddr::new(local, 0)).map_err(|_| Failure::Unsupported)?;
        Self::start(socket, settings, true)
    }

    fn start(socket: UdpSocket, settings: Settings, dialing: bool) -> Result<Self, Failure> {
        let address = socket.local_addr().map_err(|_| Failure::Unsupported)?;
        socket
            .set_nonblocking(true)
            .map_err(|_| Failure::Unsupported)?;
        let poll = Poll::new().map_err(|_| Failure::Unsupported)?;
        let waker = Arc::new(Waker::new(poll.registry(), WAKER).map_err(|_| Failure::Unsupported)?);
        let (commands, inbound) = mpsc::channel();
        let relays = Relays::default();
        let open_sessions = Arc::new(AtomicUsize::new(0));
        let worker = Worker::new(
            mio::net::UdpSocket::from_std(socket),
            poll,
            inbound,
            settings,
            relays.clone(),
            Arc::clone(&open_sessions),
            dialing,
        )
        .map_err(|_| Failure::Unsupported)?;
        let worker = thread::Builder::new()
            .name("coqui-web-port".into())
            .spawn(move || worker.run())
            .map_err(|_| Failure::Unsupported)?;
        Ok(Self {
            inner: Arc::new(Inner {
                address,
                settings,
                commands,
                waker,
                relays,
                next_session: AtomicU64::new(0),
                open_sessions,
                worker: Mutex::new(Some(worker)),
            }),
        })
    }

    /// The address it is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.address
    }

    /// QUIC sources being relayed now.
    #[must_use]
    pub fn relays(&self) -> usize {
        self.inner.relays.len()
    }

    /// Data channels held now, opening or open.
    #[must_use]
    pub fn data_channels(&self) -> usize {
        self.inner.open_sessions.load(Ordering::SeqCst)
    }

    pub(crate) fn settings(&self) -> Settings {
        self.inner.settings
    }

    /// Sends QUIC packets to this address from now on.
    pub(crate) fn relay_to(&self, quic: SocketAddr) {
        self.command(Command::Quic(quic));
    }

    /// The source a relay's address stands for. `None` for an address no relay holds, which reached the listener some other way.
    pub(crate) fn source_of(&self, relay: SocketAddr) -> Option<SocketAddr> {
        self.inner.relays.source_of(relay)
    }

    fn new_session(&self) -> u64 {
        self.inner.next_session.fetch_add(1, Ordering::Relaxed)
    }

    fn command(&self, command: Command) {
        if self.inner.commands.send(command).is_ok() {
            let _ = self.inner.waker.wake();
        }
    }

    fn wake(&self) {
        let _ = self.inner.waker.wake();
    }

    /// The candidate a channel arriving at `local` is told about.
    pub(crate) fn candidate_for(&self, local: SocketAddr) -> SocketAddr {
        self.inner
            .settings
            .public_address
            .unwrap_or_else(|| SocketAddr::new(local.ip().to_canonical(), self.local_addr().port()))
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if self.commands.send(Command::Stop).is_ok() {
            let _ = self.waker.wake();
        }
        let worker = self
            .worker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(worker) = worker
            && worker.thread().id() != thread::current().id()
        {
            let _ = worker.join();
        }
    }
}
