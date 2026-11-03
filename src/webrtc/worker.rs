//! The thread behind a [`Port`](super::Port): reads its socket, relays QUIC, and drives every data channel on it.
//!
//! It sleeps until a socket is ready, a caller wakes it or a timer is due. str0m does no I/O and asks for the time it next wants, so
//! nothing here ticks of its own.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
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
use str0m::ice::StunMessage;
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, IceCreds, Input, Output, Rtc};

use super::Settings;
use super::climb::{ANSWER, OFFER, Path, REFUSED};

pub(super) const WAKER: Token = Token(0);
const PUBLIC: Token = Token(1);
const FIRST_RELAY: usize = 2;

/// Packets handled in one turn, so a flood on one socket cannot keep the others or the timers waiting.
const BUDGET: usize = 256;
/// A UDP datagram cannot be larger.
const BUFFER: usize = 64 * 1024;
/// How long a source that has completed no handshake keeps its relay with nothing from the listener. QUIC's handshake limit is this
/// long.
const UNPROVEN_IDLE: Duration = Duration::from_secs(10);
/// How long a new relay is safe from being replaced: long enough for a Retry and the answer to it. Replaced sooner, a flood would
/// keep every real client out, since a Retry's token names the relay and a replaced one starts again with another.
pub(super) const YOUNG: Duration = Duration::from_millis(500);
/// QUIC's least for a client's first datagram (RFC 9000 section 14.1), so a forged source costs a flood this much.
const LEAST_INITIAL: usize = 1200;
/// Sources a listening session answers checks from before its peer nominates one. A browser checks from each of its addresses.
const CHECKED: usize = 8;
/// Datagrams taken from one session's queue in one turn.
const SENDS_PER_TURN: usize = 64;
const CHANNEL_LABEL: &str = "coqui-web-datagrams";

/// Which relay stands for which source, shared with whoever must judge a QUIC source.
#[derive(Clone, Default)]
pub(super) struct Relays(pub(super) Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>);

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
    /// The relay at this address carried a finished handshake.
    Proven(SocketAddr),
    /// The connection through the relay at this address has ended.
    Released(SocketAddr),
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
    /// Answers `offer`, naming one candidate, for a WebSocket peer at `peer`.
    Answer {
        offer: String,
        candidate: SocketAddr,
        peer: IpAddr,
    },
    /// Makes an offer. The socket's own address is the one candidate.
    Offer,
}

struct Relay {
    socket: UdpSocket,
    address: SocketAddr,
    source: SocketAddr,
    last: Instant,
    born: Instant,
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
    /// This side's ICE username fragment, which a check names and so routes by.
    ufrag: String,
    /// A listener's WebSocket peer, the only address checks may come from unless the settings allow any.
    peer: Option<IpAddr>,
    /// The one source this session hears from: where a dialer's answer said, or what a listener's peer nominated.
    pinned: Option<SocketAddr>,
    /// Sources that passed a check before the nomination.
    checked: Vec<SocketAddr>,
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
    // A check routes by the fragment it names, anything else by where it came from; neither can be claimed from another session.
    by_ufrag: HashMap<String, u64>,
    by_source: HashMap<SocketAddr, u64>,
    relays_per_address: HashMap<IpAddr, usize>,
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
            by_ufrag: HashMap::new(),
            by_source: HashMap::new(),
            relays_per_address: HashMap::new(),
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
                Ok(Command::Proven(relay)) => {
                    if let Some(relay) = self
                        .relay_by_token
                        .values_mut()
                        .find(|held| held.address == relay)
                    {
                        relay.proven = true;
                    }
                }
                Ok(Command::Released(relay)) => {
                    let token = self
                        .relay_by_token
                        .iter()
                        .find_map(|(token, held)| (held.address == relay).then_some(*token));
                    if let Some(token) = token {
                        self.remove_relay(token);
                    }
                }
                Ok(Command::Open(opening)) => self.open(*opening),
                Ok(Command::Answer { id, sdp, candidate }) => self.answer(id, &sdp, candidate),
                Ok(Command::Close(id)) => {
                    if let Some(mut session) = self.remove_session(id) {
                        session.close(&self.public);
                    }
                }
                Ok(Command::Stop) | Err(TryRecvError::Disconnected) => return false,
                Err(TryRecvError::Empty) => return true,
            }
        }
    }

    fn remove_session(&mut self, id: u64) -> Option<Session> {
        let session = self.sessions.remove(&id)?;
        self.by_ufrag.remove(&session.ufrag);
        self.by_source.retain(|_, owner| *owner != id);
        Some(session)
    }

    fn open(&mut self, opening: Opening) {
        let Opening {
            id,
            path,
            to_send,
            role,
            attempt,
        } = opening;
        let peer = match &role {
            Role::Answer { peer, .. } => Some(peer.to_canonical()),
            Role::Offer => None,
        };
        let held = peer.map_or(0, |peer| {
            self.sessions
                .values()
                .filter(|session| session.peer == Some(peer))
                .count()
        });
        if self.sessions.len() >= self.settings.max_sessions
            || held >= self.settings.max_per_address
        {
            path.signal(REFUSED, "");
            return;
        }
        let now = Instant::now();
        // A fragment of its own, so no two sessions here can be told apart only by the order they are tried in.
        let mut credentials = IceCreds::new();
        credentials.ufrag = format!("{}{id:x}", credentials.ufrag);
        let ufrag = credentials.ufrag.clone();
        let built = catch_unwind(AssertUnwindSafe(|| match role {
            Role::Answer {
                offer, candidate, ..
            } => answering(now, &offer, candidate, credentials),
            Role::Offer => offering(now, self.local, credentials),
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
                ufrag: ufrag.clone(),
                peer,
                pinned: None,
                checked: Vec::new(),
            },
        );
        self.by_ufrag.insert(ufrag, id);
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
            session.pinned = Some(candidate);
            session.stirred = true;
            self.by_source.insert(candidate, id);
        } else {
            self.remove_session(id);
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
                let written = catch_unwind(AssertUnwindSafe(|| {
                    session
                        .rtc
                        .channel(channel)
                        .is_some_and(|mut open| open.write(true, &datagram).unwrap_or(false))
                }))
                .unwrap_or(false);
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
                // Readiness is reported once, so a socket left before it would block could go deaf: an error, such as the
                // port-unreachable Windows reports for an earlier send, is read past.
                Err(_) => {}
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

    /// A packet goes to one session at most: a check to the one whose fragment it names, anything else to the one its source belongs
    /// to. That session takes it only from where it may hear, and str0m only with its credentials. Anything else gets no reply of any
    /// kind, so a source with no credentials can neither learn a session is here nor use it to reflect anything.
    fn deliver_to_session(&mut self, count: usize, source: SocketAddr) {
        let now = Instant::now();
        let packet = &self.buffer[..count];
        let mut check = None;
        let owner = if packet[0] <= 3 {
            let Ok(Some((ufrag, nominates))) = catch_unwind(|| {
                let message = StunMessage::parse(packet).ok()?;
                let ufrag = message.split_username().map(|(local, _)| local.to_owned());
                Some((
                    ufrag,
                    message.is_binding_request() && message.use_candidate(),
                ))
            }) else {
                return;
            };
            match ufrag {
                Some(ufrag) => {
                    check = Some(nominates);
                    self.by_ufrag.get(&ufrag).copied()
                }
                None => self.by_source.get(&source).copied(),
            }
        } else {
            self.by_source.get(&source).copied()
        };
        let Some(id) = owner else {
            return;
        };
        let Some(session) = self.sessions.get_mut(&id) else {
            return;
        };
        let may_hear = match session.pinned {
            Some(pinned) => pinned == source,
            None => {
                (self.settings.any_candidate
                    || session
                        .peer
                        .is_none_or(|peer| peer == source.ip().to_canonical()))
                    && self.by_source.get(&source).is_none_or(|owner| *owner == id)
            }
        };
        if !may_hear {
            return;
        }
        let handled = catch_unwind(AssertUnwindSafe(|| {
            let receive = Receive::new(Protocol::Udp, source, session.local, packet).ok()?;
            let input = Input::Receive(now, receive);
            Some(
                session
                    .rtc
                    .accepts(&input)
                    .then(|| session.rtc.handle_input(input).is_ok()),
            )
        }));
        match handled {
            Ok(None | Some(None)) => {}
            Ok(Some(Some(true))) => {
                session.stirred = true;
                // An authenticated check: its source may now send this session the rest, and a nomination is the only one it
                // will hear from again.
                if let Some(nominates) = check
                    && session.pinned.is_none()
                {
                    if nominates {
                        session.pinned = Some(source);
                        let others = core::mem::take(&mut session.checked);
                        for other in others.into_iter().filter(|other| *other != source) {
                            self.by_source.remove(&other);
                        }
                        self.by_source.insert(source, id);
                    } else if !session.checked.contains(&source) && session.checked.len() < CHECKED
                    {
                        session.checked.push(source);
                        self.by_source.insert(source, id);
                    }
                }
            }
            Ok(Some(Some(false))) | Err(_) => {
                if let Some(session) = self.remove_session(id) {
                    session.path.ended();
                }
            }
        }
    }

    fn relay_quic(&mut self, count: usize, source: SocketAddr) {
        let Some(quic) = self.quic else {
            return;
        };
        let now = Instant::now();
        let token = match self.relay_by_source.get(&source) {
            Some(token) => *token,
            None if !self.may_start_relay(count) => return,
            None => match self.new_relay(source, quic, now) {
                Some(token) => token,
                None => return,
            },
        };
        // Only the listener's side keeps a relay alive: a source cannot, by sending.
        if let Some(relay) = self.relay_by_token.get(&token) {
            let _ = relay.socket.send(&self.buffer[..count]);
        }
    }

    /// A client's first packet is a long header of [`LEAST_INITIAL`]. Anything else from a new source is a client whose address
    /// changed mid-connection, which is let in only while there is plenty of room.
    fn may_start_relay(&self, count: usize) -> bool {
        (self.buffer[0] >= 192 && count >= LEAST_INITIAL)
            || self.relay_by_token.len() < self.settings.max_relays / 2
    }

    /// A relay's address is a loopback port the system hands out, so one can come back for another source. A Retry token names the
    /// address and lasts seconds: to use one there, a source must have been sent another's, which went only to that other.
    fn new_relay(&mut self, source: SocketAddr, quic: SocketAddr, now: Instant) -> Option<Token> {
        let address = source.ip().to_canonical();
        if self.relays_per_address.get(&address).copied().unwrap_or(0)
            >= self.settings.max_per_address
            && !self.evict_unproven_from(address, now)
        {
            return None;
        }
        if self.relay_by_token.len() >= self.settings.max_relays && !self.evict_unproven(now) {
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
        *self
            .relays_per_address
            .entry(source.ip().to_canonical())
            .or_default() += 1;
        self.relay_by_token.insert(
            token,
            Relay {
                socket,
                address,
                source,
                last: now,
                born: now,
                proven: false,
            },
        );
        self.unproven.push_back(token);
        let end = now + UNPROVEN_IDLE.min(self.settings.relay_idle);
        self.next_sweep = Some(self.next_sweep.map_or(end, |next| next.min(end)));
        Some(token)
    }

    /// Replaces the oldest relay that has completed no handshake, if it has had its chance to.
    fn evict_unproven(&mut self, now: Instant) -> bool {
        while let Some(token) = self.unproven.front().copied() {
            match self.relay_by_token.get(&token) {
                Some(relay) if !relay.proven => {
                    if now.saturating_duration_since(relay.born) < YOUNG {
                        return false;
                    }
                    self.unproven.pop_front();
                    self.remove_relay(token);
                    return true;
                }
                _ => {
                    self.unproven.pop_front();
                }
            }
        }
        false
    }

    /// Replaces the oldest relay of `address` that has completed no handshake, if it has had its chance to.
    fn evict_unproven_from(&mut self, address: IpAddr, now: Instant) -> bool {
        let oldest = self
            .relay_by_token
            .iter()
            .filter(|(_, relay)| {
                !relay.proven
                    && relay.source.ip().to_canonical() == address
                    && now.saturating_duration_since(relay.born) >= YOUNG
            })
            .min_by_key(|(_, relay)| relay.born)
            .map(|(token, _)| *token);
        oldest.is_some_and(|token| {
            self.remove_relay(token);
            true
        })
    }

    fn remove_relay(&mut self, token: Token) {
        if let Some(mut relay) = self.relay_by_token.remove(&token) {
            let _ = self.poll.registry().deregister(&mut relay.socket);
            self.relays.remove(relay.address);
            self.relay_by_source.remove(&relay.source);
            let address = relay.source.ip().to_canonical();
            if let Some(held) = self.relays_per_address.get_mut(&address) {
                *held -= 1;
                if *held == 0 {
                    self.relays_per_address.remove(&address);
                }
            }
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
                    let _ = self.public.send_to(&self.buffer[..count], relay.source);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return false,
                // Read past, as on the public socket: the listener's port-unreachable, if it has gone, arrives here on Windows.
                Err(_) => {}
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
            if let Some(mut session) = self.remove_session(*id) {
                session.close(&self.public);
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

fn answering(
    now: Instant,
    offer: &str,
    candidate: SocketAddr,
    credentials: IceCreds,
) -> Option<Built> {
    let offer = SdpOffer::from_sdp_string(offer).ok()?;
    let mut rtc = Rtc::builder()
        .set_crypto_provider(provider())
        .set_local_ice_credentials(credentials)
        .set_ice_lite(true)
        .build(now);
    rtc.add_local_candidate(Candidate::host(candidate, "udp").ok()?)?;
    let answer = rtc.sdp_api().accept_offer(offer).ok()?;
    Some((rtc, candidate, answer.to_sdp_string(), None))
}

fn offering(now: Instant, local: SocketAddr, credentials: IceCreds) -> Option<Built> {
    let mut rtc = Rtc::builder()
        .set_crypto_provider(provider())
        .set_local_ice_credentials(credentials)
        .build(now);
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
