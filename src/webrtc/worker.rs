//! The thread behind a [`Port`](super::Port): reads its socket, relays QUIC, and drives every data channel on it.
//!
//! It sleeps until a socket is ready, a caller wakes it or a timer is due. str0m does no I/O and asks for the time it next wants, so
//! nothing here ticks of its own.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::net::{Ipv4Addr, SocketAddr};
use core::panic::AssertUnwindSafe;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::collections::HashMap;
use std::io;
use std::net::UdpSocket as StdSocket;
use std::panic::catch_unwind;
use std::sync::mpsc::{self, TryRecvError};
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token};
use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc};

use super::Settings;
use super::climb::{ANSWER, OFFER, Path, REFUSED};

pub(super) const WAKER: Token = Token(0);
const PUBLIC: Token = Token(1);
const FIRST_RELAY: usize = 2;

/// Packets handled in one turn, so a flood on one socket cannot keep the others or the timers waiting.
const BUDGET: usize = 256;
/// A UDP datagram cannot be larger.
const BUFFER: usize = 64 * 1024;
/// How long a source that has completed no handshake keeps its relay with nothing happening. QUIC's handshake limit is this long.
const UNPROVEN_IDLE: Duration = Duration::from_secs(10);
/// A reply this large is no Retry, so the listener accepted the source's address: only a source that can read what it was sent gets one.
const PROVEN_REPLY: usize = 512;
/// Datagrams taken from one session's queue in one turn.
const SENDS_PER_TURN: usize = 64;
const CHANNEL_LABEL: &str = "coqui-web-datagrams";

/// Which relay stands for which source, shared with whoever must judge a QUIC source.
#[derive(Clone, Default)]
pub(super) struct Relays(Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>);

impl Relays {
    pub(super) fn len(&self) -> usize {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).len()
    }

    pub(super) fn source_of(&self, relay: SocketAddr) -> Option<SocketAddr> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&relay)
            .copied()
    }

    fn insert(&self, relay: SocketAddr, source: SocketAddr) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(relay, source);
    }

    fn remove(&self, relay: SocketAddr) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&relay);
    }
}

/// What a caller asks of the worker.
pub(super) enum Command {
    /// Where QUIC goes.
    Quic(SocketAddr),
    /// Starts a session.
    Open(Box<Opening>),
    /// The peer's answer to this session's offer, and where it said to send.
    Answer {
        id: u64,
        sdp: String,
        candidate: SocketAddr,
    },
    /// Ends a session.
    Close(u64),
    /// Ends everything.
    Stop,
}

/// One session to start.
pub(super) struct Opening {
    pub(super) id: u64,
    pub(super) path: Arc<Path>,
    pub(super) to_send: mpsc::Receiver<Vec<u8>>,
    pub(super) role: Role,
    pub(super) attempt: Duration,
}

/// Which end of the offer this is.
pub(super) enum Role {
    /// Answers `offer`, naming one candidate.
    Answer {
        offer: String,
        candidate: SocketAddr,
    },
    /// Makes an offer. The socket's own address is the one candidate.
    Offer,
}

struct Relay {
    socket: UdpSocket,
    address: SocketAddr,
    source: SocketAddr,
    last: Instant,
    proven: bool,
}

struct Session {
    rtc: Rtc,
    /// The candidate this side named: str0m matches what arrives to it, whatever the socket is bound to.
    local: SocketAddr,
    path: Arc<Path>,
    to_send: mpsc::Receiver<Vec<u8>>,
    channel: Option<ChannelId>,
    /// Until the channel opens, past which the attempt is over.
    deadline: Option<Instant>,
    due: Instant,
    /// Something happened, so it must be asked what it wants next.
    stirred: bool,
    pending: Option<SdpPendingOffer>,
    /// A dialer hears only from where the answer said.
    only_from: Option<SocketAddr>,
}

pub(super) struct Worker {
    public: UdpSocket,
    local: SocketAddr,
    poll: Poll,
    inbound: mpsc::Receiver<Command>,
    settings: Settings,
    relays: Relays,
    quic: Option<SocketAddr>,
    relay_by_source: HashMap<SocketAddr, Token>,
    relay_by_token: HashMap<Token, Relay>,
    // Oldest first; holds tokens that may since have gone or been proven.
    unproven: VecDeque<Token>,
    next_token: usize,
    next_sweep: Option<Instant>,
    sessions: HashMap<u64, Session>,
    buffer: Vec<u8>,
    // Sockets that had more to read when a turn's budget ran out.
    unfinished: Vec<Token>,
    // A dialer's port is for one session, and its socket and thread go when that does.
    dialing: bool,
    opened_one: bool,
    open_sessions: Arc<AtomicUsize>,
}

fn is_quic(first: u8) -> bool {
    matches!(first, 64..=127 | 192..=255)
}

fn is_stun_or_dtls(first: u8) -> bool {
    matches!(first, 0..=3 | 20..=63)
}

impl Worker {
    pub(super) fn new(
        mut public: UdpSocket,
        poll: Poll,
        inbound: mpsc::Receiver<Command>,
        settings: Settings,
        relays: Relays,
        open_sessions: Arc<AtomicUsize>,
        dialing: bool,
    ) -> io::Result<Self> {
        poll.registry()
            .register(&mut public, PUBLIC, Interest::READABLE)?;
        let local = public.local_addr()?;
        Ok(Self {
            public,
            local,
            poll,
            inbound,
            settings,
            relays,
            quic: None,
            relay_by_source: HashMap::new(),
            relay_by_token: HashMap::new(),
            unproven: VecDeque::new(),
            next_token: FIRST_RELAY,
            next_sweep: None,
            sessions: HashMap::new(),
            buffer: vec![0; BUFFER],
            unfinished: Vec::new(),
            open_sessions,
            dialing,
            opened_one: false,
        })
    }

    pub(super) fn run(mut self) {
        let mut events = Events::with_capacity(64);
        let mut ready: Vec<Token> = Vec::new();
        loop {
            if !self.take_commands()
                || (self.dialing && self.opened_one && self.sessions.is_empty())
            {
                break;
            }
            self.send_queued();
            ready.append(&mut self.unfinished);
            for token in ready.drain(..) {
                let more = if token == PUBLIC {
                    self.read_public()
                } else {
                    self.read_relay(token)
                };
                if more {
                    self.unfinished.push(token);
                }
            }
            let now = Instant::now();
            self.sweep(now);
            let timer = self.drive_sessions(now);
            self.open_sessions
                .store(self.sessions.len(), Ordering::SeqCst);
            let limit = if self.unfinished.is_empty() {
                self.sleep_for(timer)
            } else {
                Some(Duration::ZERO)
            };
            if let Err(error) = self.poll.poll(&mut events, limit)
                && error.kind() != io::ErrorKind::Interrupted
            {
                break;
            }
            for event in &events {
                if event.token() != WAKER && !self.unfinished.contains(&event.token()) {
                    ready.push(event.token());
                }
            }
        }
        for session in self.sessions.values_mut() {
            session.close(&self.public);
        }
    }

    fn sleep_for(&self, timer: Option<Instant>) -> Option<Duration> {
        let next = match (timer, self.next_sweep) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }?;
        // A timer already due has been handled: this keeps a timer asking for now from spinning.
        Some(
            next.saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1)),
        )
    }

    fn take_commands(&mut self) -> bool {
        loop {
            match self.inbound.try_recv() {
                Ok(Command::Quic(address)) => {
                    // Every relay is connected to where QUIC was.
                    let tokens: Vec<Token> = self.relay_by_token.keys().copied().collect();
                    for token in tokens {
                        self.remove_relay(token);
                    }
                    self.quic = Some(address);
                }
                Ok(Command::Open(opening)) => self.open(*opening),
                Ok(Command::Answer { id, sdp, candidate }) => self.answer(id, &sdp, candidate),
                Ok(Command::Close(id)) => {
                    if let Some(mut session) = self.sessions.remove(&id) {
                        session.close(&self.public);
                    }
                }
                Ok(Command::Stop) | Err(TryRecvError::Disconnected) => return false,
                Err(TryRecvError::Empty) => return true,
            }
        }
    }

    fn open(&mut self, opening: Opening) {
        let Opening {
            id,
            path,
            to_send,
            role,
            attempt,
        } = opening;
        if self.sessions.len() >= self.settings.max_sessions {
            path.signal(REFUSED, "");
            return;
        }
        let now = Instant::now();
        let built = catch_unwind(AssertUnwindSafe(|| match role {
            Role::Answer { offer, candidate } => answering(now, &offer, candidate),
            Role::Offer => offering(now, self.local),
        }));
        let Ok(Some((rtc, local, description, pending))) = built else {
            path.signal(REFUSED, "");
            return;
        };
        path.signal(if pending.is_some() { OFFER } else { ANSWER }, &description);
        self.opened_one = true;
        self.sessions.insert(
            id,
            Session {
                rtc,
                local,
                path,
                to_send,
                channel: None,
                deadline: Some(now + attempt),
                due: now,
                stirred: true,
                pending,
                only_from: None,
            },
        );
    }

    fn answer(&mut self, id: u64, sdp: &str, candidate: SocketAddr) {
        let Some(session) = self.sessions.get_mut(&id) else {
            return;
        };
        let Some(pending) = session.pending.take() else {
            return;
        };
        let accepted = catch_unwind(AssertUnwindSafe(|| {
            SdpAnswer::from_sdp_string(sdp)
                .ok()
                .and_then(|answer| session.rtc.sdp_api().accept_answer(pending, answer).ok())
        }));
        if matches!(accepted, Ok(Some(()))) {
            session.only_from = Some(candidate);
            session.stirred = true;
        } else {
            self.sessions.remove(&id);
        }
    }

    fn send_queued(&mut self) {
        for session in self.sessions.values_mut() {
            let Some(channel) = session.channel else {
                continue;
            };
            for _ in 0..SENDS_PER_TURN {
                let Ok(datagram) = session.to_send.try_recv() else {
                    break;
                };
                let written = session
                    .rtc
                    .channel(channel)
                    .is_some_and(|mut open| open.write(true, &datagram).unwrap_or(false));
                if !written {
                    session.path.count_dropped();
                }
                session.stirred = true;
            }
        }
    }

    fn read_public(&mut self) -> bool {
        for _ in 0..BUDGET {
            match self.public.recv_from(&mut self.buffer) {
                Ok((count, source)) => self.arrived(count, source),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return false,
                // Windows reports an earlier send's ICMP port-unreachable here, on a socket that is fine.
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return false,
            }
        }
        true
    }

    fn arrived(&mut self, count: usize, source: SocketAddr) {
        match self.buffer.first().filter(|_| count > 0).copied() {
            Some(first) if is_quic(first) => self.relay_quic(count, source),
            Some(first) if is_stun_or_dtls(first) => self.deliver_to_session(count, source),
            _ => {}
        }
    }

    /// Only a session that accepts a packet ever hears of it, and one accepts STUN only with its credentials. Anything else gets no
    /// reply of any kind, so an unproven source can neither learn this port is here nor use it to reflect anything.
    fn deliver_to_session(&mut self, count: usize, source: SocketAddr) {
        let now = Instant::now();
        let buffer = &self.buffer[..count];
        let mut failed = None;
        for (id, session) in &mut self.sessions {
            if session.only_from.is_some_and(|only| only != source) {
                continue;
            }
            let Ok(receive) = Receive::new(Protocol::Udp, source, session.local, buffer) else {
                // The same bytes will parse for no session.
                return;
            };
            let input = Input::Receive(now, receive);
            match catch_unwind(AssertUnwindSafe(|| {
                session
                    .rtc
                    .accepts(&input)
                    .then(|| session.rtc.handle_input(input))
            })) {
                Ok(None) => continue,
                Ok(Some(Ok(()))) => session.stirred = true,
                Ok(Some(Err(_))) | Err(_) => failed = Some(*id),
            }
            break;
        }
        if let Some(id) = failed
            && let Some(session) = self.sessions.remove(&id)
        {
            session.path.ended();
        }
    }

    fn relay_quic(&mut self, count: usize, source: SocketAddr) {
        let Some(quic) = self.quic else {
            return;
        };
        let now = Instant::now();
        let token = match self.relay_by_source.get(&source) {
            Some(token) => *token,
            None => match self.new_relay(source, quic, now) {
                Some(token) => token,
                None => return,
            },
        };
        if let Some(relay) = self.relay_by_token.get_mut(&token) {
            relay.last = now;
            let _ = relay.socket.send(&self.buffer[..count]);
        }
    }

    fn new_relay(&mut self, source: SocketAddr, quic: SocketAddr, now: Instant) -> Option<Token> {
        if self.relay_by_token.len() >= self.settings.max_relays && !self.evict_unproven() {
            return None;
        }
        let socket = StdSocket::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
        socket.connect(quic).ok()?;
        socket.set_nonblocking(true).ok()?;
        let address = socket.local_addr().ok()?;
        let mut socket = UdpSocket::from_std(socket);
        let token = Token(self.next_token);
        self.next_token += 1;
        self.poll
            .registry()
            .register(&mut socket, token, Interest::READABLE)
            .ok()?;
        self.relays.insert(address, source);
        self.relay_by_source.insert(source, token);
        self.relay_by_token.insert(
            token,
            Relay {
                socket,
                address,
                source,
                last: now,
                proven: false,
            },
        );
        self.unproven.push_back(token);
        let end = now + UNPROVEN_IDLE.min(self.settings.relay_idle);
        self.next_sweep = Some(self.next_sweep.map_or(end, |next| next.min(end)));
        Some(token)
    }

    fn evict_unproven(&mut self) -> bool {
        while let Some(token) = self.unproven.pop_front() {
            if self
                .relay_by_token
                .get(&token)
                .is_some_and(|relay| !relay.proven)
            {
                self.remove_relay(token);
                return true;
            }
        }
        false
    }

    fn remove_relay(&mut self, token: Token) {
        if let Some(mut relay) = self.relay_by_token.remove(&token) {
            let _ = self.poll.registry().deregister(&mut relay.socket);
            self.relays.remove(relay.address);
            self.relay_by_source.remove(&relay.source);
        }
    }

    fn read_relay(&mut self, token: Token) -> bool {
        let now = Instant::now();
        let Some(relay) = self.relay_by_token.get_mut(&token) else {
            return false;
        };
        for _ in 0..BUDGET {
            match relay.socket.recv(&mut self.buffer) {
                Ok(count) => {
                    relay.last = now;
                    relay.proven |= count >= PROVEN_REPLY;
                    let _ = self.public.send_to(&self.buffer[..count], relay.source);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return false,
                // The listener has gone. Its port-unreachable arrives here on Windows.
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return false,
            }
        }
        true
    }

    /// Ends relays gone quiet, when the first of them is due: nothing wakes for this while none is.
    fn sweep(&mut self, now: Instant) {
        if self.next_sweep.is_none_or(|next| now < next) {
            return;
        }
        let mut gone = Vec::new();
        let mut next: Option<Instant> = None;
        for (token, relay) in &self.relay_by_token {
            let idle = if relay.proven {
                self.settings.relay_idle
            } else {
                UNPROVEN_IDLE.min(self.settings.relay_idle)
            };
            let end = relay.last + idle;
            if end <= now {
                gone.push(*token);
            } else {
                next = Some(next.map_or(end, |soonest| soonest.min(end)));
            }
        }
        for token in gone {
            self.remove_relay(token);
        }
        self.next_sweep = next;
        if self.unproven.len() > self.relay_by_token.len().saturating_mul(2) + BUDGET {
            let relays = &self.relay_by_token;
            self.unproven
                .retain(|token| relays.get(token).is_some_and(|relay| !relay.proven));
        }
    }

    /// Lets each session due act, and answers when the next one wants the time.
    fn drive_sessions(&mut self, now: Instant) -> Option<Instant> {
        let public = &self.public;
        let mut ended = Vec::new();
        let mut soonest: Option<Instant> = None;
        for (id, session) in &mut self.sessions {
            if session.deadline.is_some_and(|deadline| deadline <= now) {
                ended.push(*id);
                continue;
            }
            if session.stirred || session.due <= now {
                session.stirred = false;
                if session.drive(public, now).is_none() {
                    ended.push(*id);
                    continue;
                }
            }
            let mut due = session.due;
            if let Some(deadline) = session.deadline {
                due = due.min(deadline);
            }
            soonest = Some(soonest.map_or(due, |next| next.min(due)));
        }
        for id in &ended {
            if let Some(mut session) = self.sessions.remove(id) {
                session.close(public);
                session.path.ended();
            }
        }
        // A dialer's last session ending leaves it nothing to wait for.
        if self.dialing && !ended.is_empty() && self.sessions.is_empty() {
            return Some(now);
        }
        soonest
    }
}

fn provider() -> Arc<str0m::config::CryptoProvider> {
    Arc::new(str0m::crypto::from_feature_flags())
}

type Built = (Rtc, SocketAddr, String, Option<SdpPendingOffer>);

fn answering(now: Instant, offer: &str, candidate: SocketAddr) -> Option<Built> {
    let offer = SdpOffer::from_sdp_string(offer).ok()?;
    let mut rtc = Rtc::builder()
        .set_crypto_provider(provider())
        .set_ice_lite(true)
        .build(now);
    rtc.add_local_candidate(Candidate::host(candidate, "udp").ok()?)?;
    let answer = rtc.sdp_api().accept_offer(offer).ok()?;
    Some((rtc, candidate, answer.to_sdp_string(), None))
}

fn offering(now: Instant, local: SocketAddr) -> Option<Built> {
    let mut rtc = Rtc::builder().set_crypto_provider(provider()).build(now);
    rtc.add_local_candidate(Candidate::host(local, "udp").ok()?)?;
    let mut api = rtc.sdp_api();
    api.add_channel_with_config(ChannelConfig {
        label: CHANNEL_LABEL.into(),
        ordered: false,
        reliability: Reliability::MaxRetransmits { retransmits: 0 },
        ..ChannelConfig::default()
    });
    let (offer, pending) = api.apply()?;
    Some((rtc, local, offer.to_sdp_string(), Some(pending)))
}

impl Session {
    fn close(&mut self, public: &UdpSocket) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if self.rtc.close().is_ok() {
                while self.rtc.is_alive() {
                    match self.rtc.poll_output() {
                        Ok(Output::Transmit(transmit)) => {
                            let _ = public.send_to(&transmit.contents, transmit.destination);
                        }
                        Ok(Output::Event(_)) => {}
                        Ok(Output::Timeout(_)) | Err(_) => break,
                    }
                }
            }
        }));
    }

    /// Hands str0m the time and does what it asks, until it wants nothing but to be called again. `None` means this session is over.
    fn drive(&mut self, public: &UdpSocket, now: Instant) -> Option<()> {
        catch_unwind(AssertUnwindSafe(|| {
            self.rtc.handle_input(Input::Timeout(now)).ok()?;
            loop {
                match self.rtc.poll_output().ok()? {
                    Output::Timeout(due) => {
                        self.due = due;
                        return self.rtc.is_alive().then_some(());
                    }
                    Output::Transmit(transmit) => {
                        let _ = public.send_to(&transmit.contents, transmit.destination);
                    }
                    Output::Event(event) => self.handle(event)?,
                }
            }
        }))
        .ok()
        .flatten()
    }

    fn handle(&mut self, event: Event) -> Option<()> {
        match event {
            Event::ChannelOpen(id, _) => {
                // A channel is unordered with no retransmits, or it is not what this side agreed to carry.
                let lossy = self.rtc.channel(id)?.config().is_some_and(|config| {
                    !config.ordered
                        && config.reliability == (Reliability::MaxRetransmits { retransmits: 0 })
                });
                if !lossy || self.channel.is_some() {
                    return None;
                }
                self.channel = Some(id);
                self.deadline = None;
                self.path.opened();
            }
            Event::ChannelData(data) if Some(data.id) == self.channel => {
                self.path.arrive(data.data);
            }
            Event::ChannelClose(id) if Some(id) == self.channel => return None,
            Event::IceConnectionStateChange(IceConnectionState::Disconnected) => return None,
            _ => {}
        }
        Some(())
    }
}
