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
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::time::Duration;
use std::io;
use std::net::UdpSocket;
use std::sync::mpsc;
use std::sync::{Mutex, PoisonError};
use std::thread;

use mio::{Poll, Waker};

pub(crate) use climb::{Climb, Plan};

use coqui_transport::Failure;
use worker::{Command, Relays, WAKER, Worker};

/// How an offer and its answer reach the other end.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    guatiao::ToValue,
    guatiao::FromValue,
    guatiao::Schema,
)]
#[map(rename_all = "kebab-case")]
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
///
/// A guatiao value (`from_value`, `to_value`, `schema`) a file fills: every key is optional (an absent one is its default),
/// an unknown key is refused, a duration is a number of seconds, `[secs, nanos]` or `{secs, nanos}`, and `signaling` is
/// `on-channel` or `by-caller`. It is `#[non_exhaustive]`: start from [`Default`] and assign the fields.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, guatiao::ToValue, guatiao::FromValue, guatiao::Schema,
)]
#[map(deny_unknown_fields)]
#[non_exhaustive]
pub struct Settings {
    /// Whether to try at all. Off, a channel asks for nothing more than plain datagrams and sends no signal.
    #[map(default = Settings::default().enabled)]
    pub enabled: bool,
    /// How long a data channel may take to open before the channel stays on the WebSocket for good. Only the attempt is lost.
    #[map(default = Settings::default().attempt)]
    pub attempt: Duration,
    /// The largest IP packet the path is known to carry. It caps a data channel's datagrams, since a fragmented one is lost whenever
    /// any fragment is.
    #[map(default = Settings::default().path_mtu)]
    pub path_mtu: usize,
    /// The address a [`Port`] names in its one candidate. Unset, it names the address the WebSocket connection arrived at, with the
    /// UDP port's number. Behind a proxy or NAT that is wrong, and it tells the peer an address it had no other way to learn.
    pub public_address: Option<SocketAddr>,
    /// Lets the other end's path be at another address than the WebSocket's peer. Off, a dialer refuses an answer naming another
    /// address, and a [`Port`] answers checks only from the WebSocket peer's address, so neither end can point the other's traffic
    /// somewhere else. Behind a proxy the WebSocket peer is the proxy, so a `Port` there needs this on, and each data channel is then
    /// held to the one source its peer nominated.
    #[map(default = Settings::default().any_candidate)]
    pub any_candidate: bool,
    /// How offers and answers travel.
    #[map(default = Settings::default().signaling)]
    pub signaling: Signaling,
    /// Data channels a [`Port`] holds at once, past which an offer is refused.
    #[map(default = Settings::default().max_sessions)]
    pub max_sessions: usize,
    /// QUIC sources a [`Port`] relays at once, each a socket, so keep this well below the process's limit on them. A new source past
    /// this replaces the oldest that has completed no handshake in half a second, and is dropped if there is none.
    #[map(default = Settings::default().max_relays)]
    pub max_relays: usize,
    /// QUIC sources, and data channels, one IP address holds at once. Behind a proxy every WebSocket client has the proxy's
    /// address, which this then limits.
    #[map(default = Settings::default().max_per_address)]
    pub max_per_address: usize,
    /// Silence after which a relay ends. A source returning later gets a new one, which QUIC reads as a changed address. It should
    /// outlast the QUIC idle timeout.
    #[map(default = Settings::default().relay_idle)]
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
            max_relays: 512,
            max_per_address: 64,
            relay_idle: Duration::from_secs(120),
        }
    }
}

impl Settings {
    /// Whether these leave room for a datagram, a time to try in and something to hold.
    pub(crate) fn check(&self) -> Result<(), Failure> {
        let usable = self.path_mtu > climb::OVERHEAD
            && !self.attempt.is_zero()
            && !self.relay_idle.is_zero()
            && self.max_sessions > 0
            && self.max_relays > 0
            && self.max_per_address > 0;
        if usable {
            Ok(())
        } else {
            Err(Failure::Unsupported)
        }
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
    quic_taken: AtomicBool,
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
    /// [`Failure::Permission`] when the address is taken or not allowed; [`Failure::Unsupported`] for settings that leave no room
    /// for a datagram, a time to try in or anything to hold, or when the socket or thread could not start.
    pub fn bind(address: SocketAddr, settings: Settings) -> Result<Self, Failure> {
        settings.check()?;
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
                quic_taken: AtomicBool::new(false),
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

    /// Takes the port's one place for a QUIC listener, if it is free.
    pub(crate) fn take_quic(&self) -> bool {
        !self.inner.quic_taken.swap(true, Ordering::SeqCst)
    }

    /// The relay at this address carried a finished handshake.
    pub(crate) fn prove(&self, relay: SocketAddr) {
        self.command(Command::Proven(relay));
    }

    /// The connection through the relay at this address has ended.
    pub(crate) fn release(&self, relay: SocketAddr) {
        self.command(Command::Released(relay));
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

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    /// A port with room for two relays, and a socket standing in for the QUIC listener.
    fn port() -> (Port, UdpSocket) {
        port_for(2)
    }

    fn port_for(relays: usize) -> (Port, UdpSocket) {
        port_with(Settings {
            max_relays: relays,
            ..Settings::default()
        })
    }

    fn port_with(settings: Settings) -> (Port, UdpSocket) {
        let quic = UdpSocket::bind("127.0.0.1:0").unwrap();
        quic.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let port = Port::bind("127.0.0.1:0".parse().unwrap(), settings).unwrap();
        port.relay_to(quic.local_addr().unwrap());
        (port, quic)
    }

    fn client() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").unwrap()
    }

    /// Sends what a new client sends, and answers where it reached the listener from.
    fn first_packet(from: &UdpSocket, port: &Port, quic: &UdpSocket) -> SocketAddr {
        from.send_to(&[0xc0; 1200], port.local_addr()).unwrap();
        let mut buffer = [0_u8; 2048];
        quic.recv_from(&mut buffer).unwrap().1
    }

    fn holds(port: &Port, source: &UdpSocket) -> bool {
        let source = source.local_addr().unwrap();
        port.inner
            .relays
            .0
            .lock()
            .unwrap()
            .values()
            .any(|held| *held == source)
    }

    fn nothing_arrives(quic: &UdpSocket) -> bool {
        quic.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buffer = [0_u8; 2048];
        let quiet = quic.recv_from(&mut buffer).is_err();
        quic.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        quiet
    }

    #[test]
    fn a_new_relay_cannot_be_replaced_before_it_has_had_its_chance() {
        let (port, quic) = port();
        let (one, two, three) = (client(), client(), client());
        let started = Instant::now();
        first_packet(&one, &port, &quic);
        first_packet(&two, &port, &quic);
        three.send_to(&[0xc0; 1200], port.local_addr()).unwrap();
        assert!(nothing_arrives(&quic));
        assert!(started.elapsed() < worker_young(), "too slow to say");
        assert!(holds(&port, &one) && holds(&port, &two) && !holds(&port, &three));

        std::thread::sleep(worker_young());
        first_packet(&three, &port, &quic);
        assert!(!holds(&port, &one), "the oldest should have gone");
        assert!(holds(&port, &two) && holds(&port, &three));
        assert_eq!(port.relays(), 2);
    }

    #[test]
    fn a_reply_however_large_proves_nothing() {
        let (port, quic) = port();
        let (one, two, three) = (client(), client(), client());
        let relay = first_packet(&one, &port, &quic);
        first_packet(&two, &port, &quic);
        // A handshake's first flight, which a source gets before it has finished anything.
        quic.send_to(&[0xc0; 600], relay).unwrap();
        one.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buffer = [0_u8; 2048];
        assert_eq!(one.recv(&mut buffer).unwrap(), 600);

        std::thread::sleep(worker_young());
        first_packet(&three, &port, &quic);
        assert!(
            !holds(&port, &one),
            "a reply was taken for a finished handshake"
        );
        assert!(holds(&port, &two) && holds(&port, &three));
    }

    #[test]
    fn a_finished_handshake_is_never_replaced() {
        let (port, quic) = port();
        let (one, two, three, four) = (client(), client(), client(), client());
        let relay = first_packet(&one, &port, &quic);
        first_packet(&two, &port, &quic);
        port.prove(relay);
        std::thread::sleep(worker_young());
        first_packet(&three, &port, &quic);
        assert!(holds(&port, &one), "a finished handshake was replaced");
        assert!(!holds(&port, &two));
        std::thread::sleep(worker_young());
        first_packet(&four, &port, &quic);
        assert!(holds(&port, &one), "a finished handshake was replaced");
        assert!(holds(&port, &four) && !holds(&port, &three));
    }

    #[test]
    fn a_relay_ends_with_its_connection() {
        let (port, quic) = port();
        let one = client();
        let relay = first_packet(&one, &port, &quic);
        port.prove(relay);
        port.release(relay);
        let deadline = Instant::now() + Duration::from_secs(5);
        while holds(&port, &one) {
            assert!(Instant::now() < deadline, "a relay outlived its connection");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn what_a_closed_connection_still_sends_starts_no_relay() {
        let (port, quic) = port_for(4);
        let one = client();
        let relay = first_packet(&one, &port, &quic);
        port.prove(relay);
        port.release(relay);
        let deadline = Instant::now() + Duration::from_secs(5);
        while holds(&port, &one) {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        // The connection's last packets, after its end: a short header, which there is room for.
        one.send_to(&[0x40; 64], port.local_addr()).unwrap();
        assert!(
            nothing_arrives(&quic),
            "a closed connection's straggler made a relay"
        );
        assert!(!holds(&port, &one));
        // A new connection from the same source starts as any other.
        first_packet(&one, &port, &quic);
        assert!(holds(&port, &one));
    }

    #[test]
    fn a_source_cannot_keep_its_relay_alive_by_sending() {
        let (port, quic) = port_with(Settings {
            max_relays: 4,
            relay_idle: Duration::from_millis(300),
            ..Settings::default()
        });
        let one = client();
        let first = first_packet(&one, &port, &quic);
        let mut relays = std::collections::HashSet::from([first]);
        let started = Instant::now();
        let mut buffer = [0_u8; 2048];
        quic.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        while started.elapsed() < Duration::from_millis(1500) {
            one.send_to(&[0x40; 64], port.local_addr()).unwrap();
            if let Ok((_, relay)) = quic.recv_from(&mut buffer) {
                relays.insert(relay);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // Gone quiet on the listener's side, it ended, and the next packet from the source got a new one.
        assert!(relays.len() >= 2, "one relay throughout: {relays:?}");
    }

    #[test]
    fn one_address_holds_no_more_than_its_share() {
        let (port, quic) = port_with(Settings {
            max_relays: 8,
            max_per_address: 2,
            ..Settings::default()
        });
        let (one, two, three) = (client(), client(), client());
        first_packet(&one, &port, &quic);
        first_packet(&two, &port, &quic);
        three.send_to(&[0xc0; 1200], port.local_addr()).unwrap();
        assert!(nothing_arrives(&quic));
        assert!(!holds(&port, &three));
        if let Ok(elsewhere) = UdpSocket::bind("127.0.0.2:0") {
            first_packet(&elsewhere, &port, &quic);
            assert!(holds(&port, &elsewhere));
        }
        // Its oldest makes way for it once that has had its chance.
        std::thread::sleep(worker_young());
        first_packet(&three, &port, &quic);
        assert!(holds(&port, &three) && !holds(&port, &one));
    }

    #[test]
    fn only_a_client_first_packet_can_take_the_last_of_the_room() {
        let (port, quic) = port_for(4);
        let (one, stray) = (client(), client());
        // With plenty of room a short header gets a relay, as a client whose address changed needs.
        stray.send_to(&[0x40; 64], port.local_addr()).unwrap();
        let mut buffer = [0_u8; 2048];
        quic.recv_from(&mut buffer).unwrap();
        assert!(holds(&port, &stray));
        first_packet(&one, &port, &quic);
        let late = client();
        late.send_to(&[0x40; 64], port.local_addr()).unwrap();
        assert!(nothing_arrives(&quic));
        assert!(!holds(&port, &late));
        // Under the least a first packet may be.
        late.send_to(&[0xc0; 1199], port.local_addr()).unwrap();
        assert!(nothing_arrives(&quic));
        assert_eq!(port.relays(), 2);
        // What a client sends first still gets in, while there is room.
        first_packet(&late, &port, &quic);
        assert_eq!(port.relays(), 3);
    }

    fn worker_young() -> Duration {
        worker::YOUNG + Duration::from_millis(50)
    }
}
