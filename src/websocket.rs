//! A blocking WebSocket dialer and listener.
//!
//! A worker thread owns each socket, so the channel can be read and written from different
//! threads, and sleeps until the socket is ready or a caller wakes it. TLS comes from the caller's
//! `rustls` configuration: this crate holds no trust roots and decides nothing about identity. A
//! plain socket beyond loopback is refused unless the caller chooses it.

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::mem;
use core::net::SocketAddr;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering, fence};
use core::time::Duration;
use std::io::{self, IoSlice, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Condvar, Mutex, PoisonError};
use std::thread;
use std::time::Instant;

use mio::{Events, Interest, Poll, Registry, Token, Waker};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, StreamOwned};
use tungstenite::client::IntoClientRequest;
use tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tungstenite::http::{HeaderName, HeaderValue, StatusCode};
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tungstenite::{HandshakeError, Message, WebSocket};
use url::Url;

use crate::channel::{self, Datagrams, Delivery, Kind};
use crate::failure::Failure;
use crate::frame::{self, WS_DATAGRAMS_PROTOCOL, WsPart};
use crate::pump::{
    Abandon, Admission, Cancel, Inbox, Limits, ReceiveBound, Received, bind_failure,
};
#[cfg(feature = "webrtc")]
use crate::webrtc::{Climb, Plan, Port, Settings};

/// How often a listener looks for a connection, and an ending worker for room in a full inbox to report in.
const POLL: Duration = Duration::from_millis(10);
/// What wakes a worker: its socket, or a caller with something for it.
const SOCKET: Token = Token(0);
const CALLER: Token = Token(1);
/// Messages queued for sending, after which `send` reports the channel as not progressing.
const OUTGOING: usize = 256;

/// How messages appear on the wire.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Frames {
    /// One UTF-8 text message per WebSocket message: what a JSON-RPC peer expects. Anything else
    /// is a protocol failure.
    #[default]
    Text,
    /// Binary WebSocket messages; text messages are also delivered, as their bytes.
    Binary,
}

/// The TCP socket under a stream, and when a byte last left through it.
///
/// It blocks through the handshake, which has a deadline and ends if that passes. A worker then reads
/// it only when it is ready and never with `SO_RCVTIMEO`: Windows says a connection is in an
/// indeterminate state after that timeout, and bytes can be lost to it
/// (<https://learn.microsoft.com/en-us/windows/win32/winsock/sol-socket-socket-options>).
struct Transport {
    socket: Socket,
    wrote: Instant,
    // Whether the last write found no room: only then is a wait for room to write worth asking for.
    write_blocked: bool,
}

enum Socket {
    Blocking(TcpStream),
    Ready(mio::net::TcpStream),
    Closed,
}

impl Transport {
    fn new(tcp: TcpStream) -> Self {
        Self {
            socket: Socket::Blocking(tcp),
            wrote: Instant::now(),
            write_blocked: false,
        }
    }

    /// Hands the socket to `registry`: from here on it never blocks. A socket that already waited on readiness must have left
    /// its last registry first.
    fn register(&mut self, registry: &Registry) -> io::Result<()> {
        let mut tcp = match mem::replace(&mut self.socket, Socket::Closed) {
            Socket::Blocking(tcp) => {
                tcp.set_read_timeout(None)?;
                tcp.set_write_timeout(None)?;
                tcp.set_nonblocking(true)?;
                mio::net::TcpStream::from_std(tcp)
            }
            Socket::Ready(tcp) => tcp,
            Socket::Closed => return Err(io::ErrorKind::NotConnected.into()),
        };
        tcp.set_nodelay(true)?;
        registry.register(&mut tcp, SOCKET, Interest::READABLE)?;
        self.socket = Socket::Ready(tcp);
        self.wrote = Instant::now();
        Ok(())
    }

    /// Asks to hear about room to write only while something waits for it. Asked for all the time, Windows reports a
    /// writable socket again after every read that would block, and an idle worker would never sleep.
    fn watch(&mut self, registry: &Registry, writing: bool) -> io::Result<()> {
        let interest = if writing {
            Interest::READABLE | Interest::WRITABLE
        } else {
            Interest::READABLE
        };
        match &mut self.socket {
            Socket::Ready(tcp) => registry.reregister(tcp, SOCKET, interest),
            _ => Err(io::ErrorKind::NotConnected.into()),
        }
    }

    fn noted(&mut self, written: io::Result<usize>) -> io::Result<usize> {
        if written.as_ref().is_ok_and(|bytes| *bytes > 0) {
            self.wrote = Instant::now();
        }
        self.write_blocked = written
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock);
        written
    }

    /// Takes the socket from `registry`, so another can have it.
    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        match &mut self.socket {
            Socket::Ready(tcp) => registry.deregister(tcp),
            _ => Err(io::ErrorKind::NotConnected.into()),
        }
    }
}

impl Read for Transport {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match &mut self.socket {
            Socket::Blocking(tcp) => tcp.read(buffer),
            Socket::Ready(tcp) => tcp.read(buffer),
            Socket::Closed => Err(io::ErrorKind::NotConnected.into()),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let written = match &mut self.socket {
            Socket::Blocking(tcp) => tcp.write(data),
            Socket::Ready(tcp) => tcp.write(data),
            Socket::Closed => Err(io::ErrorKind::NotConnected.into()),
        };
        self.noted(written)
    }

    fn write_vectored(&mut self, parts: &[IoSlice<'_>]) -> io::Result<usize> {
        let written = match &mut self.socket {
            Socket::Blocking(tcp) => tcp.write_vectored(parts),
            Socket::Ready(tcp) => tcp.write_vectored(parts),
            Socket::Closed => Err(io::ErrorKind::NotConnected.into()),
        };
        self.noted(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.socket {
            Socket::Blocking(tcp) => tcp.flush(),
            Socket::Ready(tcp) => tcp.flush(),
            Socket::Closed => Err(io::ErrorKind::NotConnected.into()),
        }
    }
}

/// Either stream a socket can run over.
enum Stream {
    Plain(Transport),
    Client(Box<StreamOwned<ClientConnection, Transport>>),
    Server(Box<StreamOwned<ServerConnection, Transport>>),
}

impl Stream {
    fn transport(&self) -> &Transport {
        match self {
            Self::Plain(transport) => transport,
            Self::Client(stream) => &stream.sock,
            Self::Server(stream) => &stream.sock,
        }
    }

    fn transport_mut(&mut self) -> &mut Transport {
        match self {
            Self::Plain(transport) => transport,
            Self::Client(stream) => &mut stream.sock,
            Self::Server(stream) => &mut stream.sock,
        }
    }

    /// Bytes TLS has accepted and the socket has not.
    fn holds_unsent(&self) -> bool {
        match self {
            Self::Plain(_) => false,
            Self::Client(stream) => stream.conn.wants_write(),
            Self::Server(stream) => stream.conn.wants_write(),
        }
    }

    /// Whether TLS read something off the socket that nobody has read from it. It reads while it waits to write, and
    /// the socket has nothing more to say about those bytes.
    fn holds_unread(&self) -> bool {
        match self {
            Self::Plain(_) => false,
            Self::Client(stream) => !stream.conn.wants_read(),
            Self::Server(stream) => !stream.conn.wants_read(),
        }
    }

    /// The chain TLS accepted from the peer, once its handshake is done.
    fn peer_certificates(&self) -> Option<Vec<Vec<u8>>> {
        let chain = match self {
            Self::Plain(_) => None,
            Self::Client(stream) => stream.conn.peer_certificates(),
            Self::Server(stream) => stream.conn.peer_certificates(),
        }?;
        (!chain.is_empty()).then(|| chain.iter().map(|der| der.to_vec()).collect())
    }
}

impl Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buffer),
            Self::Client(stream) => stream.read(buffer),
            Self::Server(stream) => stream.read(buffer),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let written = match self {
            Self::Plain(stream) => return stream.write(data),
            Self::Client(stream) => stream.write(data)?,
            Self::Server(stream) => stream.write(data)?,
        };
        // A TLS buffer that is full takes nothing, which tungstenite would read as a reset connection.
        if written == 0 && !data.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Client(stream) => stream.flush(),
            Self::Server(stream) => stream.flush(),
        }
    }
}

fn interrupted(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// A rejected certificate will not fix itself, which a caller may act on by stopping. Any other TLS error may be one
/// forged record, so it must not read that way. Neither may read as a path problem, which is what permits a fallback.
fn tls_failure(error: &rustls::Error) -> Failure {
    use rustls::AlertDescription as Alert;
    match error {
        rustls::Error::InvalidCertificate(_)
        | rustls::Error::NoCertificatesPresented
        | rustls::Error::AlertReceived(
            Alert::BadCertificate
            | Alert::UnsupportedCertificate
            | Alert::CertificateRevoked
            | Alert::CertificateExpired
            | Alert::CertificateUnknown
            | Alert::CertificateRequired
            | Alert::UnknownCA
            | Alert::AccessDenied,
        ) => Failure::Certificate,
        _ => Failure::Protocol,
    }
}

fn io_failure(error: &io::Error) -> Failure {
    if let Some(tls) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        return tls_failure(tls);
    }
    if interrupted(error) {
        Failure::Timeout
    } else {
        Failure::PathLost
    }
}

fn ws_failure(error: &tungstenite::Error) -> Failure {
    match error {
        tungstenite::Error::Io(error) => io_failure(error),
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => {
            Failure::PathLost
        }
        tungstenite::Error::Http(_) => Failure::Permission,
        // It was asked for datagrams and did not agree, which is a peer that does not offer them.
        tungstenite::Error::Protocol(
            tungstenite::error::ProtocolError::SecWebSocketSubProtocolError(_),
        ) => Failure::Unsupported,
        _ => Failure::Protocol,
    }
}

fn config(limits: Limits) -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(limits.max_message))
        .max_frame_size(Some(limits.max_message))
}

/// Where a sender waits for room in the queue. The worker wakes it when it takes a message or ends, and only while
/// someone waits, so an idle channel does no work for it.
#[derive(Default)]
struct Room {
    waiting: AtomicUsize,
    lock: Mutex<()>,
    freed: Condvar,
    // What it left queued still counts against the budget, so this is how a sender learns the worker is gone.
    ended: AtomicBool,
    // Why, when the wire or the peer said so; set before the worker lets go of the queue.
    failure: Mutex<Option<Failure>>,
}

impl Room {
    fn end_with(&self, failure: Failure) {
        *self.failure.lock().unwrap_or_else(PoisonError::into_inner) = Some(failure);
    }

    /// What a sender meets once the worker has ended.
    fn why(&self) -> Failure {
        self.failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .unwrap_or(Failure::PathLost)
    }

    /// Called after room was made: a waiter counts itself before it looks, under the lock this takes, so none misses it.
    fn made(&self) {
        if self.waiting.load(Ordering::SeqCst) > 0 {
            let _held = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
            self.freed.notify_all();
        }
    }
}

/// A WebSocket channel. Reads and writes happen on the worker thread that owns the socket.
pub struct Channel {
    inbox: Inbox,
    outgoing: Mutex<Option<SyncSender<Vec<u8>>>>,
    queued: Arc<AtomicUsize>,
    queued_limit: usize,
    room: Arc<Room>,
    waker: Arc<Waker>,
    // Set by a worker that found the inbox full.
    behind: Arc<AtomicBool>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
    frames: Frames,
    // The largest message read, by position; the worker applies it.
    max_message: Arc<ReceiveBound>,
    max_send: AtomicUsize,
    datagrams: Option<WsDatagrams>,
    peer_certificates: Option<Vec<Vec<u8>>>,
}

/// Datagrams as tagged messages on the socket, for a channel whose ends agreed to them.
struct WsDatagrams {
    outgoing: SyncSender<Vec<u8>>,
    waker: Arc<Waker>,
    inbox: Inbox,
    dropped: Arc<AtomicU64>,
    wanted: Arc<AtomicBool>,
    max_size: usize,
    #[cfg(feature = "webrtc")]
    climb: Option<Arc<Climb>>,
}

impl WsDatagrams {
    /// The data channel, while one is open.
    #[cfg(feature = "webrtc")]
    fn climbed(&self) -> Option<&Climb> {
        self.climb.as_deref().filter(|climb| climb.is_open())
    }
}

impl Datagrams for WsDatagrams {
    fn max_size(&self) -> Option<usize> {
        #[cfg(feature = "webrtc")]
        if let Some(climb) = self.climbed() {
            return Some(climb.max_size());
        }
        Some(self.max_size)
    }

    fn send(&self, payload: &[u8]) -> Result<(), Failure> {
        #[cfg(feature = "webrtc")]
        if let Some(climb) = self.climbed() {
            return climb.send(payload);
        }
        if payload.len() > self.max_size {
            return Err(Failure::Protocol);
        }
        match self.outgoing.try_send(payload.to_vec()) {
            Ok(()) => {
                let _ = self.waker.wake();
                Ok(())
            }
            // A datagram holds up nothing, so it waits for no room: this is what may happen to one.
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(TrySendError::Disconnected(_)) => Err(Failure::PathLost),
        }
    }

    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
        self.inbox.receive(timeout)
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn delivery(&self) -> Delivery {
        #[cfg(feature = "webrtc")]
        if self.climbed().is_some() {
            return Delivery::Unreliable;
        }
        Delivery::OverStream
    }

    #[cfg(feature = "webrtc")]
    fn path_changes(&self) -> Option<mpsc::Receiver<Delivery>> {
        self.climb.as_ref().map(|climb| climb.changes())
    }
}

/// The worker's end of [`WsDatagrams`].
struct WorkerDatagrams {
    outgoing: mpsc::Receiver<Vec<u8>>,
    inbox: SyncSender<Received>,
    dropped: Arc<AtomicU64>,
    wanted: Arc<AtomicBool>,
    max_size: usize,
    #[cfg(feature = "webrtc")]
    climb: Option<WorkerClimb>,
}

/// What a worker has to do for a channel that climbs: send its signals, and hear the peer's.
#[cfg(feature = "webrtc")]
struct WorkerClimb {
    climb: Arc<Climb>,
    signals: mpsc::Receiver<Vec<u8>>,
}

impl WorkerDatagrams {
    /// Holds one only once someone has asked for them: a peer that has proved nothing must not be able to fill memory that way.
    fn arrived(&self, body: &[u8]) {
        #[cfg(feature = "webrtc")]
        if self
            .climb
            .as_ref()
            .is_some_and(|climb| climb.climb.sealed())
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let kept = self.wanted.load(Ordering::SeqCst)
            && body.len() <= self.max_size
            && self.inbox.try_send(Ok(body.to_vec())).is_ok();
        if !kept {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// As many sent in one turn of the worker, so they cannot keep it from a channel's messages.
const DATAGRAMS_PER_TURN: usize = 16;
/// Message bytes taken from the queue in one turn, past which it reads before taking more: a peer's close or ping is heard
/// within one turn even while large messages keep coming. One message larger than this still goes whole.
const BYTES_PER_TURN: usize = 256 * 1024;

impl fmt::Debug for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Channel")
            .field("frames", &self.frames)
            .field("max_message", &self.max_message.current())
            .field("max_send", &self.max_send.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Channel {
    fn start(
        mut socket: WebSocket<Stream>,
        limits: Limits,
        frames: Frames,
        tagged: bool,
        #[cfg(feature = "webrtc")] plan: Option<Plan>,
    ) -> Result<Self, Failure> {
        let peer_certificates = socket.get_ref().peer_certificates();
        let poll = Poll::new().map_err(|e| io_failure(&e))?;
        socket
            .get_mut()
            .transport_mut()
            .register(poll.registry())
            .map_err(|e| io_failure(&e))?;
        let waker = Arc::new(Waker::new(poll.registry(), CALLER).map_err(|e| io_failure(&e))?);
        let (to_reader, inbox) = mpsc::sync_channel::<Received>(limits.pending.max(1));
        let (to_worker, outgoing) = mpsc::sync_channel::<Vec<u8>>(OUTGOING);
        let queued = Arc::new(AtomicUsize::new(0));
        let draining = Arc::clone(&queued);
        let room = Arc::new(Room::default());
        let making_room = Arc::clone(&room);
        let behind = Arc::new(AtomicBool::new(false));
        let noting = Arc::clone(&behind);
        let max_message = Arc::new(ReceiveBound::new(limits.max_message));
        let current = Arc::clone(&max_message);
        let (datagrams, for_worker) = if tagged {
            let pending = limits.pending_datagrams.max(1);
            let (send, to_send) = mpsc::sync_channel(pending);
            let (arrived, inbox) = mpsc::sync_channel(pending);
            let dropped = Arc::new(AtomicU64::new(0));
            let wanted = Arc::new(AtomicBool::new(false));
            #[cfg(feature = "webrtc")]
            let (climb, worker_climb) = match plan {
                Some(plan) => {
                    // An offer, an answer or a refusal: never more than one on its way.
                    let (signals, for_worker) = mpsc::sync_channel(2);
                    let waking = Arc::clone(&waker);
                    let climb = Arc::new(Climb::new(
                        plan,
                        arrived.clone(),
                        Arc::clone(&dropped),
                        pending,
                        signals,
                        Box::new(move || {
                            let _ = waking.wake();
                        }),
                    ));
                    (
                        Some(Arc::clone(&climb)),
                        Some(WorkerClimb {
                            climb,
                            signals: for_worker,
                        }),
                    )
                }
                None => (None, None),
            };
            (
                Some(WsDatagrams {
                    outgoing: send,
                    waker: Arc::clone(&waker),
                    inbox: Inbox::new(inbox),
                    dropped: Arc::clone(&dropped),
                    wanted: Arc::clone(&wanted),
                    max_size: limits.websocket_datagram,
                    #[cfg(feature = "webrtc")]
                    climb,
                }),
                Some(WorkerDatagrams {
                    outgoing: to_send,
                    inbox: arrived,
                    dropped,
                    wanted,
                    max_size: limits.websocket_datagram,
                    #[cfg(feature = "webrtc")]
                    climb: worker_climb,
                }),
            )
        } else {
            (None, None)
        };
        let worker = thread::Builder::new()
            .name("coqui-web-websocket".into())
            .spawn(move || {
                Worker {
                    socket,
                    poll,
                    events: Events::with_capacity(8),
                    inbox: to_reader,
                    behind: noting,
                    outgoing,
                    frames,
                    queued: draining,
                    room: Arc::clone(&making_room),
                    limits,
                    max_message: current,
                    applied: limits.max_message,
                    read: 0,
                    datagrams: for_worker,
                    waiting: None,
                    heard: Instant::now(),
                    pinged: false,
                    unsent: None,
                    watching_writes: false,
                    reads: Reads::Frames,
                }
                .run();
                // The queue is gone with the worker: a sender still waiting finds that out now.
                making_room.ended.store(true, Ordering::SeqCst);
                making_room.made();
            })
            .map_err(|_| Failure::Unsupported)?;
        Ok(Self {
            inbox: Inbox::new(inbox),
            outgoing: Mutex::new(Some(to_worker)),
            queued,
            queued_limit: limits.queued_bytes,
            room,
            waker,
            behind,
            worker: Mutex::new(Some(worker)),
            frames,
            max_message,
            max_send: AtomicUsize::new(limits.max_message),
            datagrams,
            peer_certificates,
        })
    }
}

impl Channel {
    fn check(&self, message: &[u8]) -> Result<(), Failure> {
        if message.is_empty() || message.len() > self.max_send.load(Ordering::SeqCst) {
            return Err(Failure::Protocol);
        }
        if self.frames == Frames::Text && core::str::from_utf8(message).is_err() {
            return Err(Failure::Protocol);
        }
        Ok(())
    }

    /// Queues a checked message, or answers that there is no room for it now.
    fn queue(&self, message: &[u8]) -> Result<bool, Failure> {
        let outgoing = self.outgoing.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(queue) = outgoing.as_ref() else {
            return Err(Failure::Cancelled);
        };
        if self.room.ended.load(Ordering::SeqCst) {
            return Err(self.room.why());
        }
        if self
            .queued
            .load(Ordering::SeqCst)
            .saturating_add(message.len())
            > self.queued_limit
        {
            return Ok(false);
        }
        self.queued.fetch_add(message.len(), Ordering::SeqCst);
        if let Err(error) = queue.try_send(message.to_vec()) {
            self.queued.fetch_sub(message.len(), Ordering::SeqCst);
            return match error {
                TrySendError::Full(_) => Ok(false),
                TrySendError::Disconnected(_) => Err(self.room.why()),
            };
        }
        let _ = self.waker.wake();
        Ok(true)
    }
}

impl channel::Channel for Channel {
    fn send(&self, message: &[u8]) -> Result<(), Failure> {
        self.check(message)?;
        match self.queue(message)? {
            true => Ok(()),
            false => Err(Failure::NoProgress),
        }
    }

    fn send_timeout(&self, message: &[u8], timeout: Option<Duration>) -> Result<(), Failure> {
        self.check(message)?;
        // Room for more than the whole budget never comes.
        if message.len() > self.queued_limit {
            return Err(Failure::NoProgress);
        }
        let deadline = timeout.map(|limit| Instant::now() + limit);
        let mut held = self
            .room
            .lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.room.waiting.fetch_add(1, Ordering::SeqCst);
        let sent = loop {
            match self.queue(message) {
                Ok(true) => break Ok(()),
                Ok(false) => {}
                Err(failure) => break Err(failure),
            }
            held = match deadline {
                None => self
                    .room
                    .freed
                    .wait(held)
                    .unwrap_or_else(PoisonError::into_inner),
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        break Err(Failure::Timeout);
                    }
                    self.room
                        .freed
                        .wait_timeout(held, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
            };
        };
        self.room.waiting.fetch_sub(1, Ordering::SeqCst);
        sent
    }

    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
        let next = self.inbox.receive(timeout);
        if matches!(next, Ok(Some(_))) {
            self.max_message.taken();
        }
        // Pairs with the worker's fence in `deliver`: either it sees the room this take made, or this sees it behind.
        fence(Ordering::SeqCst);
        if self.behind.swap(false, Ordering::SeqCst) {
            let _ = self.waker.wake();
        }
        next
    }

    fn set_max_message(&self, bytes: usize) {
        self.set_max_receive(bytes);
        self.set_max_send(bytes);
    }

    fn set_max_receive(&self, bytes: usize) {
        self.max_message.set(bytes);
    }

    fn set_max_receive_after(&self, messages: usize, bytes: usize) -> Result<(), Failure> {
        self.max_message.stage(messages, bytes);
        Ok(())
    }

    fn set_max_send(&self, bytes: usize) {
        self.max_send.store(bytes, Ordering::SeqCst);
    }

    fn datagrams(&self) -> Option<&dyn Datagrams> {
        let datagrams = self.datagrams.as_ref()?;
        datagrams.wanted.store(true, Ordering::SeqCst);
        #[cfg(feature = "webrtc")]
        if let Some(climb) = &datagrams.climb {
            climb.start();
        }
        Some(datagrams)
    }

    fn peer_certificates(&self) -> Option<&[Vec<u8>]> {
        self.peer_certificates.as_deref()
    }

    fn close(&self) {
        // The worker sends what is queued, then the close frame, then releases the socket. Waiting for it means a
        // process that closes and exits has not lost what it sent.
        drop(
            self.outgoing
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
        let _ = self.waker.wake();
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
        #[cfg(feature = "webrtc")]
        if let Some(climb) = self.datagrams.as_ref().and_then(|d| d.climb.as_ref()) {
            climb.close();
        }
    }
}

#[cfg(feature = "webrtc")]
impl Channel {
    /// The next offer or answer for a caller to carry to the peer, with
    /// [`Signaling::ByCaller`](crate::webrtc::Signaling::ByCaller). `None` once the channel has ended.
    ///
    /// # Errors
    ///
    /// [`Failure::Timeout`] when there was none within `timeout`; [`Failure::Unsupported`] on a channel that does not climb this way.
    pub fn next_signal(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
        self.climb()
            .ok_or(Failure::Unsupported)?
            .next_signal(timeout)
    }

    /// An offer or answer the peer sent through the caller.
    ///
    /// # Errors
    ///
    /// [`Failure::Unsupported`] on a channel that does not climb this way.
    pub fn deliver_signal(&self, signal: &[u8]) -> Result<(), Failure> {
        self.climb()
            .ok_or(Failure::Unsupported)?
            .deliver_signal(signal)
    }

    fn climb(&self) -> Option<&Climb> {
        self.datagrams.as_ref()?.climb.as_deref()
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        channel::Channel::close(self);
    }
}

/// The system giving up on a peer ends the channel. Reported as such, since a caller treats `Failure::Timeout` from
/// `receive` as a quiet moment.
fn ended(error: &tungstenite::Error) -> Failure {
    match ws_failure(error) {
        Failure::Timeout => Failure::NoProgress,
        failure => failure,
    }
}

fn would_block(error: &tungstenite::Error) -> bool {
    matches!(error, tungstenite::Error::Io(error) if error.kind() == io::ErrorKind::WouldBlock)
}

/// The close code that tells the peer why its messages ended the channel.
fn close_code(error: &tungstenite::Error) -> CloseCode {
    match error {
        tungstenite::Error::Capacity(_) => CloseCode::Size,
        tungstenite::Error::Utf8(_) => CloseCode::Invalid,
        tungstenite::Error::Protocol(_) => CloseCode::Protocol,
        _ => CloseCode::Error,
    }
}

/// A peer closing with one of these says something this side sent broke its wire format or its bounds.
fn refused(frame: Option<&CloseFrame>) -> bool {
    matches!(
        frame.map(|frame| frame.code),
        Some(CloseCode::Protocol | CloseCode::Unsupported | CloseCode::Invalid | CloseCode::Size)
    )
}

/// What a worker may still read from its socket.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Reads {
    Frames,
    /// tungstenite's reader failed and may not be called again (a refused frame header is consumed and its body is not),
    /// but the stream under it is sound: bytes are read and discarded, so closing leaves none unread to reset the connection.
    Bytes,
    Nothing,
}

/// How a worker stops.
enum Stop {
    /// Reports this and drops the socket.
    Failed(Failure),
    /// Reports this, then closes in order with this code.
    FailedClosing(Failure, CloseCode),
    /// Nobody will send any more: closes in order.
    Closing,
    /// The peer closed, and what is left to send ends with the reply.
    Replying,
    /// The peer closed refusing what this side sent: reports this, then replies.
    Refused(Failure),
    /// The socket is finished with.
    Gone,
}

/// Owns the socket: writes what is queued, reads what arrived, pings a silent peer, and stops reading while the reader
/// is behind, which is the back-pressure a peer feels.
///
/// Readiness only says that something changed, so each turn tries everything, and a worker sleeps only once reading has
/// said it would block. A frame `WebSocket::write` was given stays in its buffer when that write says it would block,
/// and `flush` picks it up: never written again here, and nothing more is taken from the queue until it has gone.
struct Worker {
    socket: WebSocket<Stream>,
    poll: Poll,
    events: Events,
    inbox: SyncSender<Received>,
    behind: Arc<AtomicBool>,
    outgoing: mpsc::Receiver<Vec<u8>>,
    frames: Frames,
    queued: Arc<AtomicUsize>,
    room: Arc<Room>,
    limits: Limits,
    max_message: Arc<ReceiveBound>,
    // What the socket was built with: the shared value may already have moved on.
    applied: usize,
    // Messages read for the reader: the position of the next.
    read: u64,
    datagrams: Option<WorkerDatagrams>,
    waiting: Option<Received>,
    heard: Instant,
    pinged: bool,
    // When the socket stopped taking what there is to send.
    unsent: Option<Instant>,
    watching_writes: bool,
    reads: Reads,
}

impl Worker {
    #[cfg(feature = "webrtc")]
    fn climbs(&self) -> bool {
        self.datagrams.as_ref().is_some_and(|d| d.climb.is_some())
    }

    /// Agreeing to datagrams adds a tag to every binary message, which a limit on what it holds does not count.
    fn tag(&self) -> usize {
        usize::from(self.datagrams.is_some())
    }

    fn run(mut self) {
        let tag = self.tag();
        if tag > 0 {
            let limit = self.applied + tag;
            self.socket.set_config(|config| {
                config.max_message_size = Some(limit);
                config.max_frame_size = Some(limit);
            });
        }
        let stop = loop {
            if let Err(stop) = self.turn() {
                break stop;
            }
        };
        #[cfg(feature = "webrtc")]
        if let Some(climb) = self.datagrams.as_ref().and_then(|d| d.climb.as_ref()) {
            climb.climb.close();
        }
        match stop {
            Stop::Failed(failure) => self.report(failure),
            Stop::FailedClosing(failure, code) => {
                self.room.end_with(failure);
                self.report(failure);
                self.finish(Some(code));
            }
            Stop::Closing => self.finish(None),
            Stop::Replying => {
                let _ = self.drained();
            }
            Stop::Refused(failure) => {
                self.room.end_with(failure);
                self.report(failure);
                let _ = self.drained();
            }
            Stop::Gone => {}
        }
    }

    fn turn(&mut self) -> Result<(), Stop> {
        let more = self.write_queued()?;
        // Writing stops when the socket is full, and if that has passed, nothing will say so.
        let was_unsent = self.unsent.is_some();
        let behind = self.deliver()?;
        self.keep_alive(behind)?;
        let read = !behind && self.read_one()?;
        let retry = self.flush()?;
        let room = was_unsent && self.unsent.is_none();
        if more || read || retry || room || (!behind && self.socket.get_ref().holds_unread()) {
            return Ok(());
        }
        self.wait()
    }

    fn write(&mut self, message: Message) -> Result<(), Stop> {
        match self.socket.write(message) {
            Ok(()) => Ok(()),
            Err(error) if would_block(&error) => {
                self.unsent.get_or_insert_with(Instant::now);
                Ok(())
            }
            Err(error) => Err(Stop::Failed(ended(&error))),
        }
    }

    /// Takes nothing while the socket is full, so what waits stays counted against the caller's bounds. Takes a bounded
    /// number and size otherwise, so a busy sender cannot keep this from reading, and answers whether more may be waiting: nothing
    /// will wake this for what is already queued. Datagrams go first: a few at most, and a message sent after one follows it.
    fn write_queued(&mut self) -> Result<bool, Stop> {
        #[cfg(feature = "webrtc")]
        while self.unsent.is_none() {
            let signal = self
                .datagrams
                .as_ref()
                .and_then(|d| d.climb.as_ref())
                .and_then(|climb| climb.signals.try_recv().ok());
            let Some(signal) = signal else { break };
            self.write(Message::binary(frame::ws_signal(&signal)))?;
        }
        let mut more = false;
        if self.datagrams.is_some() {
            more = true;
            for _ in 0..DATAGRAMS_PER_TURN {
                if self.unsent.is_some() {
                    return Ok(false);
                }
                let Some(Ok(datagram)) = self.datagrams.as_ref().map(|d| d.outgoing.try_recv())
                else {
                    more = false;
                    break;
                };
                self.write(Message::binary(frame::ws_datagram(&datagram)))?;
            }
        }
        let mut taken = 0;
        for _ in 0..OUTGOING {
            if self.unsent.is_some() {
                return Ok(false);
            }
            if taken >= BYTES_PER_TURN {
                return Ok(true);
            }
            let message = match self.outgoing.try_recv() {
                Ok(message) => message,
                Err(mpsc::TryRecvError::Empty) => return Ok(more),
                Err(mpsc::TryRecvError::Disconnected) => return Err(Stop::Closing),
            };
            self.queued.fetch_sub(message.len(), Ordering::SeqCst);
            self.room.made();
            taken += message.len();
            let framed = match self.frames {
                Frames::Text => match core::str::from_utf8(&message) {
                    Ok(text) => Message::text(text.to_string()),
                    Err(_) => continue,
                },
                Frames::Binary if self.tag() > 0 => Message::binary(frame::ws_message(&message)),
                Frames::Binary => Message::binary(message),
            };
            self.write(framed)?;
        }
        Ok(true)
    }

    fn keep_alive(&mut self, behind: bool) -> Result<(), Stop> {
        // Not reading, it cannot hear the peer, so that silence says nothing; a ping each idle period lets the peer hear it.
        if behind {
            if self.heard.elapsed() >= self.limits.idle {
                self.heard = Instant::now();
                self.pinged = false;
                let _ = self.socket.write(Message::Ping(Vec::new().into()));
            }
            return Ok(());
        }
        let silent = self.heard.elapsed();
        if silent >= self.limits.idle.saturating_mul(2) {
            return Err(Stop::Failed(Failure::NoProgress));
        }
        if silent >= self.limits.idle && !self.pinged {
            self.pinged = true;
            let _ = self.socket.write(Message::Ping(Vec::new().into()));
        }
        Ok(())
    }

    /// Whether the reader is still behind, and the message it has not taken still waits here.
    fn deliver(&mut self) -> Result<bool, Stop> {
        let Some(held) = self.waiting.take() else {
            return Ok(false);
        };
        let held = match self.inbox.try_send(held) {
            Ok(()) => return Ok(false),
            Err(TrySendError::Full(held)) => held,
            Err(TrySendError::Disconnected(_)) => return Err(Stop::Closing),
        };
        // Said before looking again, so a reader taking one from here on wakes this worker, which can then sleep until it does.
        self.behind.store(true, Ordering::SeqCst);
        fence(Ordering::SeqCst);
        match self.inbox.try_send(held) {
            Ok(()) => Ok(false),
            Err(TrySendError::Full(held)) => {
                self.waiting = Some(held);
                Ok(true)
            }
            Err(TrySendError::Disconnected(_)) => Err(Stop::Closing),
        }
    }

    /// Whether a message came in, in which case there may be another.
    fn read_one(&mut self) -> Result<bool, Stop> {
        // Looked at after this turn's writes: a peer answering one of them meets the limit its sender had set. A frame read now
        // belongs to the next message, whose position fixes its bound.
        let wanted = self.max_message.at(self.read);
        if wanted != self.applied {
            self.applied = wanted;
            let limit = wanted + self.tag();
            self.socket.set_config(|config| {
                config.max_message_size = Some(limit);
                config.max_frame_size = Some(limit);
            });
        }
        let message = match self.socket.read() {
            Ok(message) => message,
            Err(tungstenite::Error::ConnectionClosed) => return Err(Stop::Replying),
            Err(error) if would_block(&error) => return Ok(false),
            Err(error) => {
                self.reads = match error {
                    tungstenite::Error::Io(_) | tungstenite::Error::Tls(_) => Reads::Nothing,
                    _ => Reads::Bytes,
                };
                return Err(Stop::FailedClosing(ended(&error), close_code(&error)));
            }
        };
        self.heard = Instant::now();
        self.pinged = false;
        match message {
            Message::Text(text) => self.arrived(text.as_bytes().to_vec()),
            #[cfg(feature = "webrtc")]
            Message::Binary(body) if self.climbs() && frame::ws_signal_part(&body).is_some() => {
                if let (Some(climb), Some(signal)) = (
                    self.datagrams.as_ref().and_then(|d| d.climb.as_ref()),
                    frame::ws_signal_part(&body),
                ) {
                    climb.climb.signal_from_channel(signal);
                }
            }
            Message::Binary(body) if self.datagrams.is_some() => match frame::ws_part(&body) {
                Ok(WsPart::Datagram(datagram)) => {
                    if let Some(datagrams) = &self.datagrams {
                        datagrams.arrived(datagram);
                    }
                }
                Ok(WsPart::Message(message)) if self.frames == Frames::Binary => {
                    self.arrived(message.to_vec());
                }
                _ => return Err(Stop::FailedClosing(Failure::Protocol, CloseCode::Protocol)),
            },
            Message::Binary(body) if self.frames == Frames::Binary => {
                self.arrived(body.to_vec());
            }
            Message::Binary(_) => {
                return Err(Stop::FailedClosing(
                    Failure::Protocol,
                    CloseCode::Unsupported,
                ));
            }
            Message::Close(frame) if refused(frame.as_ref()) => {
                return Err(Stop::Refused(Failure::Protocol));
            }
            // An orderly close: the reader sees the end when this sender drops.
            Message::Close(_) => return Err(Stop::Replying),
            _ => {}
        }
        Ok(true)
    }

    fn arrived(&mut self, message: Vec<u8>) {
        self.waiting = Some(Ok(message));
        self.read += 1;
    }

    /// Sends what it can. A peer that takes nothing for `Limits::send` while there is something to send ends the channel.
    /// Answers whether to look again at once: TLS can still hold bytes after a flush that returned early.
    fn flush(&mut self) -> Result<bool, Stop> {
        let retry = match self.socket.flush() {
            Ok(()) if !self.socket.get_ref().holds_unsent() => {
                self.unsent = None;
                return Ok(false);
            }
            Ok(()) => true,
            Err(error) if would_block(&error) => false,
            Err(tungstenite::Error::ConnectionClosed) => return Err(Stop::Gone),
            Err(error) => return Err(Stop::Failed(ended(&error))),
        };
        self.unsent.get_or_insert_with(Instant::now);
        if self.send_left().is_some_and(|left| left.is_zero()) {
            return Err(Stop::Failed(Failure::NoProgress));
        }
        Ok(retry)
    }

    /// How long the peer has left to take something, if there is anything for it to take.
    fn send_left(&self) -> Option<Duration> {
        let since = self.unsent?.max(self.socket.get_ref().transport().wrote);
        Some(self.limits.send.saturating_sub(since.elapsed()))
    }

    /// Sleeps until the socket or a caller has something, or until the next thing that is due. While the reader is behind,
    /// that reader taking a message is what wakes it.
    fn wait(&mut self) -> Result<(), Stop> {
        let silence = if self.pinged {
            self.limits.idle.saturating_mul(2)
        } else {
            self.limits.idle
        };
        let mut limit = silence.saturating_sub(self.heard.elapsed());
        if let Some(left) = self.send_left() {
            limit = limit.min(left);
        }
        self.sleep(Some(limit))
            .map_err(|_| Stop::Failed(Failure::PathLost))
    }

    fn sleep(&mut self, limit: Option<Duration>) -> io::Result<()> {
        let writing = self.unsent.is_some();
        if writing != self.watching_writes {
            self.socket
                .get_mut()
                .transport_mut()
                .watch(self.poll.registry(), writing)?;
            self.watching_writes = writing;
        }
        match self.poll.poll(&mut self.events, limit) {
            Err(error) if error.kind() != io::ErrorKind::Interrupted => Err(error),
            _ => Ok(()),
        }
    }

    /// What came in before the failure, then the failure, for a reader that may be behind. A channel being closed has
    /// no reader left to wait for.
    fn report(&mut self, failure: Failure) {
        let held = self.waiting.take();
        for item in held.into_iter().chain([Err(failure)]) {
            let mut item = item;
            while let Err(TrySendError::Full(back)) = self.inbox.try_send(item) {
                item = back;
                loop {
                    match self.outgoing.try_recv() {
                        Ok(_) => {}
                        Err(mpsc::TryRecvError::Empty) => break,
                        Err(mpsc::TryRecvError::Disconnected) => return,
                    }
                }
                if self.sleep(Some(POLL)).is_err() {
                    return;
                }
            }
        }
    }

    /// Whether everything got to the socket, for as long as the peer keeps taking it.
    fn drained(&mut self) -> bool {
        loop {
            match self.flush() {
                Ok(true) => {}
                Ok(false) if self.unsent.is_none() => return true,
                Ok(false) => {
                    let left = self.send_left();
                    if self.sleep(left).is_err() {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
    }

    /// Starts the closing handshake and leaves it a moment to finish, then the socket drops anyway.
    fn finish(&mut self, code: Option<CloseCode>) {
        // The close frame is queued whatever this returns, and `drained` sends it.
        let _ = self.socket.close(code.map(|code| CloseFrame {
            code,
            reason: "".into(),
        }));
        if !self.drained() {
            return;
        }
        let until = Instant::now() + Duration::from_millis(500);
        let mut discarded = Vec::new();
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            let waiting = match self.reads {
                Reads::Frames => match self.socket.read() {
                    Ok(_) => false,
                    Err(error) if would_block(&error) => true,
                    Err(_) => return,
                },
                Reads::Bytes => {
                    discarded.resize(64 * 1024, 0);
                    match self.socket.get_mut().read(&mut discarded) {
                        Ok(0) => return,
                        Ok(_) => false,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => true,
                        Err(_) => return,
                    }
                }
                Reads::Nothing => return,
            };
            if waiting && self.sleep(Some(left)).is_err() {
                return;
            }
        }
    }
}

fn endpoint_is_loopback(endpoint: &Url) -> bool {
    match endpoint.host() {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

/// Dials WebSocket endpoints.
#[derive(Clone, Default)]
pub struct Dialer {
    headers: Vec<(alloc::string::String, alloc::string::String)>,
    tls: Option<Arc<ClientConfig>>,
    limits: Limits,
    frames: Frames,
    datagrams: bool,
    plain_beyond_loopback: bool,
    local: Option<SocketAddr>,
    #[cfg(feature = "webrtc")]
    webrtc: Option<Settings>,
}

impl fmt::Debug for Dialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dialer")
            .field("tls", &self.tls.is_some())
            .field("limits", &self.limits)
            .field("frames", &self.frames)
            .field("headers", &self.headers.len())
            .field("plain_beyond_loopback", &self.plain_beyond_loopback)
            .field("local", &self.local)
            .finish()
    }
}

impl Dialer {
    /// A dialer with no TLS configuration, which can reach only `ws://`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lets this dialer open `ws://` beyond loopback: unencrypted and unauthenticated, so anyone on the path reads and changes
    /// it. A weakening of the default, which [`plain_beyond_loopback`](Self::plain_beyond_loopback) reports.
    #[must_use]
    pub const fn with_plain_beyond_loopback(mut self) -> Self {
        self.plain_beyond_loopback = true;
        self
    }

    /// Whether this dialer may open `ws://` beyond loopback, so a host can show that weakening.
    #[must_use]
    pub const fn plain_beyond_loopback(&self) -> bool {
        self.plain_beyond_loopback
    }

    /// The TLS configuration `wss://` uses. It decides which certificates are trusted.
    #[must_use]
    pub fn with_tls(mut self, tls: Arc<ClientConfig>) -> Self {
        self.tls = Some(tls);
        self
    }

    /// The bounds of channels this dialer opens.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Binds each connection's socket to `address` before it connects, rather than to what the system picks, so a listener sees
    /// the connection come from there. Give port 0 for any free port. Only endpoint addresses of its family are tried; an address
    /// this host cannot bind, or an endpoint with none of its family, fails the dial with [`Failure::Unsupported`], or
    /// [`Failure::Permission`] when the address is taken or not allowed.
    #[must_use]
    pub const fn with_local_addr(mut self, address: SocketAddr) -> Self {
        self.local = Some(address);
        self
    }

    /// How messages appear on the wire.
    #[must_use]
    pub const fn with_frames(mut self, frames: Frames) -> Self {
        self.frames = frames;
        self
    }

    /// Asks the listener to agree to datagrams on this channel, so [`Channel::datagrams`](channel::Channel::datagrams) answers. A
    /// server that does not agree makes the dial fail with [`Failure::Unsupported`], so try again without this for one that may
    /// not offer them.
    #[must_use]
    pub const fn with_datagrams(mut self) -> Self {
        self.datagrams = true;
        self
    }

    /// Asks the listener to agree to datagrams on this channel, as [`with_datagrams`](Self::with_datagrams) does, and to let them climb
    /// onto a data channel on the same address when it can. A listener that cannot still gives plain datagrams, and an attempt that
    /// fails leaves them where they are. The attempt starts when [`datagrams`](channel::Channel::datagrams) is first called.
    #[cfg(feature = "webrtc")]
    #[must_use]
    pub const fn with_webrtc(mut self, settings: Settings) -> Self {
        self.datagrams = true;
        self.webrtc = Some(settings);
        self
    }

    /// Adds a header to the opening request. A value may be a credential: it is never printed. A header
    /// authenticates nothing by itself and does not replace proving the peer.
    #[must_use]
    pub fn with_header(
        mut self,
        name: impl Into<alloc::string::String>,
        value: impl Into<alloc::string::String>,
    ) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn protocols_asked(&self) -> &'static str {
        #[cfg(feature = "webrtc")]
        if self.webrtc.is_some_and(|settings| settings.enabled) {
            return LADDER_OR_DATAGRAMS;
        }
        WS_DATAGRAMS_PROTOCOL
    }

    fn open_tcp(
        url: &Url,
        deadline: Instant,
        local: Option<SocketAddr>,
    ) -> Result<TcpStream, Failure> {
        let host = url.host_str().ok_or(Failure::Protocol)?;
        let port = url.port_or_known_default().ok_or(Failure::Protocol)?;
        // IPv6 hosts come bracketed from the URL; a resolver wants them bare.
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let addresses = (host, port)
            .to_socket_addrs()
            .map_err(|_| Failure::PathLost)?;
        let mut last = Failure::PathLost;
        let mut tried = false;
        for address in addresses {
            if local.is_some_and(|local| local.is_ipv4() != address.is_ipv4()) {
                continue;
            }
            tried = true;
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Failure::Timeout);
            }
            let connected = match local {
                Some(local) => connect_from(local, address, left)?,
                None => TcpStream::connect_timeout(&address, left),
            };
            match connected {
                Ok(stream) => return Ok(stream),
                Err(error) => last = io_failure(&error),
            }
        }
        if !tried {
            return Err(Failure::Unsupported);
        }
        Err(last)
    }
}

/// A socket bound to `local`, connecting to `address`. A failure to bind is this host's and ends the dial; one to connect is the
/// path's, and the next address may still be tried.
fn connect_from(
    local: SocketAddr,
    address: SocketAddr,
    limit: Duration,
) -> Result<io::Result<TcpStream>, Failure> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(
        Domain::for_address(local),
        Type::STREAM,
        Some(Protocol::TCP),
    )
    .map_err(|_| Failure::Unsupported)?;
    socket.bind(&local.into()).map_err(|e| bind_failure(&e))?;
    Ok(socket
        .connect_timeout(&address.into(), limit)
        .map(|()| TcpStream::from(socket)))
}

/// What a dialer that climbs offers, the one it prefers first.
#[cfg(feature = "webrtc")]
const LADDER_OR_DATAGRAMS: &str = "coqui-web-ladder.1, coqui-web-datagrams.1";

#[cfg(feature = "webrtc")]
fn agreed_to_ladder(headers: &tungstenite::http::HeaderMap) -> bool {
    headers
        .get("sec-websocket-protocol")
        .is_some_and(|value| value.as_bytes() == frame::WS_LADDER_PROTOCOL.as_bytes())
}

impl channel::Dialer for Dialer {
    type Connection = Channel;

    fn dial(&mut self, kind: Kind, endpoint: &Url, timeout: Duration) -> Result<Channel, Failure> {
        if kind != Kind::WebSocket {
            return Err(Failure::Unsupported);
        }
        let timeout = timeout.min(self.limits.handshake);
        let deadline = Instant::now() + timeout;
        #[cfg(feature = "webrtc")]
        if let Some(settings) = self.webrtc.filter(|settings| settings.enabled) {
            settings.check()?;
        }
        if endpoint.scheme() == "ws"
            && !self.plain_beyond_loopback
            && !endpoint_is_loopback(endpoint)
        {
            return Err(Failure::Permission);
        }
        let tcp = Self::open_tcp(endpoint, deadline, self.local)?;
        #[cfg(feature = "webrtc")]
        let addresses = tcp
            .local_addr()
            .and_then(|local| Ok((local, tcp.peer_addr()?)));
        tcp.set_read_timeout(Some(timeout))
            .map_err(|e| io_failure(&e))?;
        tcp.set_write_timeout(Some(timeout))
            .map_err(|e| io_failure(&e))?;
        let stream = match endpoint.scheme() {
            "ws" => Stream::Plain(Transport::new(tcp)),
            "wss" => {
                let tls = self.tls.clone().ok_or(Failure::Certificate)?;
                let host = endpoint.host_str().ok_or(Failure::Protocol)?;
                let name = ServerName::try_from(
                    host.trim_start_matches('[')
                        .trim_end_matches(']')
                        .to_string(),
                )
                .map_err(|_| Failure::Protocol)?;
                let session = ClientConnection::new(tls, name).map_err(|_| Failure::Protocol)?;
                Stream::Client(Box::new(StreamOwned::new(session, Transport::new(tcp))))
            }
            _ => return Err(Failure::Unsupported),
        };
        let mut request = endpoint
            .as_str()
            .into_client_request()
            .map_err(|e| ws_failure(&e))?;
        for (name, value) in &self.headers {
            let name = HeaderName::try_from(name.as_str()).map_err(|_| Failure::Protocol)?;
            let value = HeaderValue::try_from(value.as_str()).map_err(|_| Failure::Protocol)?;
            request.headers_mut().append(name, value);
        }
        if self.datagrams {
            request.headers_mut().insert(
                "sec-websocket-protocol",
                HeaderValue::from_static(self.protocols_asked()),
            );
        }
        let (socket, _response) =
            tungstenite::client::client_with_config(request, stream, Some(config(self.limits)))
                .map_err(|error| match error {
                    HandshakeError::Interrupted(_) => Failure::Timeout,
                    HandshakeError::Failure(error) => ws_failure(&error),
                })?;
        #[cfg(feature = "webrtc")]
        let plan = match (self.webrtc, addresses) {
            (Some(settings), Ok((local, peer)))
                if settings.enabled && agreed_to_ladder(_response.headers()) =>
            {
                Some(Plan::Dialing {
                    settings,
                    local,
                    peer,
                })
            }
            _ => None,
        };
        Channel::start(
            socket,
            self.limits,
            self.frames,
            self.datagrams,
            #[cfg(feature = "webrtc")]
            plan,
        )
    }
}

/// Accepts WebSocket connections.
pub struct Listener {
    socket: TcpListener,
    tls: Option<Arc<ServerConfig>>,
    limits: Limits,
    frames: Frames,
    origins: Vec<alloc::string::String>,
    admission: Option<Admission>,
    #[cfg(feature = "webrtc")]
    webrtc: Option<Port>,
}

impl fmt::Debug for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Listener")
            .field("address", &self.socket.local_addr().ok())
            .field("tls", &self.tls.is_some())
            .field("limits", &self.limits)
            .field("frames", &self.frames)
            .field("origins", &self.origins)
            .field("plain_beyond_loopback", &self.plain_beyond_loopback())
            .finish()
    }
}

impl Listener {
    /// Binds `address`. With no TLS configuration only a loopback address is accepted: a plain
    /// socket on any other is refused, as plain WebSocket is for local development unless
    /// [`bind_plain`](Self::bind_plain) chooses otherwise.
    ///
    /// # Errors
    ///
    /// [`Failure::Permission`] for a plain socket beyond loopback; otherwise why it could not bind.
    pub fn bind(address: SocketAddr, tls: Option<Arc<ServerConfig>>) -> Result<Self, Failure> {
        if tls.is_none() && !address.ip().is_loopback() {
            return Err(Failure::Permission);
        }
        Self::open(address, tls)
    }

    /// Binds `address` with no TLS, loopback or not, such as `0.0.0.0` for a trusted network. Beyond loopback that is
    /// unencrypted and unauthenticated, so anyone on the path reads and changes it: a weakening of the default, which
    /// [`plain_beyond_loopback`](Self::plain_beyond_loopback) reports.
    ///
    /// # Errors
    ///
    /// Why it could not bind.
    pub fn bind_plain(address: SocketAddr) -> Result<Self, Failure> {
        Self::open(address, None)
    }

    /// Whether this listener serves plain WebSocket beyond loopback, so a host can show that weakening.
    #[must_use]
    pub fn plain_beyond_loopback(&self) -> bool {
        self.tls.is_none()
            && !self
                .socket
                .local_addr()
                .is_ok_and(|address| address.ip().is_loopback())
    }

    fn open(address: SocketAddr, tls: Option<Arc<ServerConfig>>) -> Result<Self, Failure> {
        let socket = TcpListener::bind(address).map_err(|e| io_failure(&e))?;
        socket.set_nonblocking(true).map_err(|e| io_failure(&e))?;
        Ok(Self {
            socket,
            tls,
            limits: Limits::default(),
            frames: Frames::default(),
            origins: Vec::new(),
            admission: None,
            #[cfg(feature = "webrtc")]
            webrtc: None,
        })
    }

    /// Lets a client that asks climb from its WebSocket onto a data channel on `port`. One with no use for that sees no change.
    #[cfg(feature = "webrtc")]
    #[must_use]
    pub fn with_webrtc(mut self, port: &Port) -> Self {
        self.webrtc = port.settings().enabled.then(|| port.clone());
        self
    }

    /// The bounds of channels this listener accepts.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// How messages appear on the wire.
    #[must_use]
    pub const fn with_frames(mut self, frames: Frames) -> Self {
        self.frames = frames;
        self
    }

    /// Refuses a browser whose `Origin` is not listed. A request with no `Origin` is not a browser
    /// and is unaffected. An empty list checks nothing; identity still has to be proven afterwards.
    #[must_use]
    pub fn with_origins(
        mut self,
        origins: impl IntoIterator<Item = alloc::string::String>,
    ) -> Self {
        self.origins = origins.into_iter().collect();
        self
    }

    /// Refuses a source address before any handshake, so a denied peer costs nothing. Decided on each connection.
    #[must_use]
    pub fn with_admission(
        mut self,
        admit: impl Fn(SocketAddr) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.admission = Some(Arc::new(admit));
        self
    }

    /// The address it is bound to.
    ///
    /// # Errors
    ///
    /// Why the operating system could not say.
    pub fn local_addr(&self) -> Result<SocketAddr, Failure> {
        self.socket.local_addr().map_err(|e| io_failure(&e))
    }

    /// Waits for one connection and completes its handshake within the handshake limit.
    ///
    /// # Errors
    ///
    /// [`Failure::Timeout`] when no connection arrived within `timeout`, or a handshake took too long;
    /// [`Failure::Permission`] for a refused origin; otherwise why the handshake failed.
    pub fn accept(&self, timeout: Option<Duration>) -> Result<Channel, Failure> {
        self.next(timeout)?.handshake()
    }

    /// Waits for one connection and returns it before its handshake, so a server can run handshakes on threads of its
    /// own and one slow peer cannot hold the others up. A source [`with_admission`](Self::with_admission) denies never appears.
    ///
    /// # Errors
    ///
    /// [`Failure::Timeout`] when no connection arrived within `timeout`.
    pub fn next(&self, timeout: Option<Duration>) -> Result<Pending, Failure> {
        let (tcp, peer) = self.next_socket(timeout)?;
        Ok(Pending {
            tcp,
            peer,
            cancel: Arc::default(),
            tls: self.tls.clone(),
            limits: self.limits,
            frames: self.frames,
            origins: self.origins.clone(),
            #[cfg(feature = "webrtc")]
            webrtc: self.webrtc.clone(),
        })
    }

    fn next_socket(&self, timeout: Option<Duration>) -> Result<(TcpStream, SocketAddr), Failure> {
        let deadline = timeout.map(|limit| Instant::now() + limit);
        loop {
            match self.socket.accept() {
                Ok((tcp, source)) => {
                    if self.admission.as_ref().is_none_or(|admit| admit(source)) {
                        return Ok((tcp, source));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        return Err(Failure::Timeout);
                    }
                    thread::sleep(POLL);
                }
                Err(error) => return Err(io_failure(&error)),
            }
        }
    }
}

/// A connection that has not done its handshake.
pub struct Pending {
    tcp: TcpStream,
    peer: SocketAddr,
    cancel: Arc<Abandon>,
    tls: Option<Arc<ServerConfig>>,
    limits: Limits,
    frames: Frames,
    origins: Vec<alloc::string::String>,
    #[cfg(feature = "webrtc")]
    webrtc: Option<Port>,
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending")
            .field("peer", &self.tcp.peer_addr().ok())
            .finish_non_exhaustive()
    }
}

impl Pending {
    /// The source address [`Listener::next`] admitted.
    #[must_use]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// A handle that abandons this handshake from another thread, before or while [`handshake`](Self::handshake) runs: it then
    /// returns [`Failure::Cancelled`] and the socket closes.
    #[must_use]
    pub fn canceller(&self) -> Cancel {
        self.cancel.handle()
    }

    /// Completes the handshake within the handshake limit in total: a peer sending a byte at a time gets no longer.
    ///
    /// # Errors
    ///
    /// [`Failure::Timeout`] past the limit; [`Failure::Permission`] for a refused origin; [`Failure::Cancelled`] once its
    /// [`canceller`](Self::canceller) has stopped it; otherwise why it failed.
    // tungstenite fixes the callback's error type, and it is large.
    #[allow(clippy::result_large_err)]
    pub fn handshake(self) -> Result<Channel, Failure> {
        let Self {
            tcp,
            peer: _,
            cancel,
            tls,
            limits,
            frames,
            origins,
            #[cfg(feature = "webrtc")]
            webrtc,
        } = self;
        if cancel.cancelled() {
            return Err(Failure::Cancelled);
        }
        let _finishing = cancel.finishing();
        #[cfg(feature = "webrtc")]
        let arrived_at = tcp
            .local_addr()
            .and_then(|local| Ok((local, tcp.peer_addr()?)));
        #[cfg(feature = "webrtc")]
        let can_climb = webrtc.is_some();
        // It waits on the socket's readiness, its deadline and a cancel at once: on Windows nothing but data, a reset or its
        // own read timeout ends a blocking read, so neither a deadline nor a cancel could end one from outside.
        let deadline = Instant::now() + limits.handshake;
        let mut poll = Poll::new().map_err(|e| io_failure(&e))?;
        // Held here until the handshake ends: on Linux a waker dropped right after waking closes its eventfd, and the wake
        // is lost before the poll collects it.
        let waker = Arc::new(Waker::new(poll.registry(), CALLER).map_err(|e| io_failure(&e))?);
        let waking = Arc::clone(&waker);
        cancel.interrupt_with(|| {
            Some(Box::new(move || {
                let _ = waking.wake();
            }))
        });
        if cancel.cancelled() {
            return Err(Failure::Cancelled);
        }
        tcp.set_nonblocking(true).map_err(|e| io_failure(&e))?;
        let mut transport = Transport {
            socket: Socket::Ready(mio::net::TcpStream::from_std(tcp)),
            wrote: Instant::now(),
            write_blocked: false,
        };
        transport
            .register(poll.registry())
            .map_err(|e| io_failure(&e))?;
        let stream = match &tls {
            None => Stream::Plain(transport),
            Some(tls) => {
                let session =
                    ServerConnection::new(Arc::clone(tls)).map_err(|_| Failure::Protocol)?;
                Stream::Server(Box::new(StreamOwned::new(session, transport)))
            }
        };
        let agreed = Arc::new(AtomicBool::new(false));
        let agreeing = Arc::clone(&agreed);
        #[cfg(feature = "webrtc")]
        let climbing = Arc::new(AtomicBool::new(false));
        #[cfg(feature = "webrtc")]
        let climbs = Arc::clone(&climbing);
        let check =
            move |request: &Request, mut response: Response| -> Result<Response, ErrorResponse> {
                let asked_for = |protocol: &str| {
                    request
                        .headers()
                        .get_all("sec-websocket-protocol")
                        .iter()
                        .filter_map(|value| value.to_str().ok())
                        .flat_map(|value| value.split(','))
                        .any(|name| name.trim() == protocol)
                };
                #[cfg(feature = "webrtc")]
                if can_climb && asked_for(frame::WS_LADDER_PROTOCOL) {
                    climbs.store(true, Ordering::SeqCst);
                    agreeing.store(true, Ordering::SeqCst);
                    response.headers_mut().insert(
                        "sec-websocket-protocol",
                        HeaderValue::from_static(frame::WS_LADDER_PROTOCOL),
                    );
                }
                if !agreeing.load(Ordering::SeqCst) && asked_for(WS_DATAGRAMS_PROTOCOL) {
                    agreeing.store(true, Ordering::SeqCst);
                    response.headers_mut().insert(
                        "sec-websocket-protocol",
                        HeaderValue::from_static(WS_DATAGRAMS_PROTOCOL),
                    );
                }
                let origin = request.headers().get("origin").map(HeaderValue::to_str);
                let allowed = origins.is_empty()
                    || match origin {
                        None => true,
                        Some(Ok(origin)) => origins.iter().any(|allowed| allowed == origin),
                        Some(Err(_)) => false,
                    };
                if allowed {
                    Ok(response)
                } else {
                    let mut refused = ErrorResponse::new(None);
                    *refused.status_mut() = StatusCode::FORBIDDEN;
                    Err(refused)
                }
            };
        let mut events = Events::with_capacity(4);
        let mut watching_writes = false;
        let mut attempt = tungstenite::accept_hdr_with_config(stream, check, Some(config(limits)));
        let socket = loop {
            let mut mid = match attempt {
                Ok(socket) => break Ok(socket),
                Err(HandshakeError::Failure(error)) => break Err(ws_failure(&error)),
                Err(HandshakeError::Interrupted(mid)) => mid,
            };
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break Err(Failure::Timeout);
            }
            // Asked for only after a write found no room: Windows reports room again after every read that would block.
            let transport = mid.get_mut().get_mut().transport_mut();
            if transport.write_blocked != watching_writes {
                watching_writes = transport.write_blocked;
                if let Err(error) = transport.watch(poll.registry(), watching_writes) {
                    break Err(io_failure(&error));
                }
            }
            match poll.poll(&mut events, Some(left)) {
                Err(error) if error.kind() != io::ErrorKind::Interrupted => {
                    break Err(io_failure(&error));
                }
                _ => {}
            }
            if cancel.cancelled() {
                break Err(Failure::Cancelled);
            }
            attempt = mid.handshake();
        };
        // A cancel wins over whatever the wait made of it.
        cancel.finish()?;
        let mut socket = socket?;
        socket
            .get_mut()
            .transport_mut()
            .deregister(poll.registry())
            .map_err(|e| io_failure(&e))?;
        #[cfg(feature = "webrtc")]
        let plan = match (webrtc, arrived_at) {
            (Some(port), Ok((local, peer))) if climbing.load(Ordering::SeqCst) => {
                let candidate = port.candidate_for(local);
                Some(Plan::Listening {
                    port,
                    candidate,
                    peer,
                })
            }
            _ => None,
        };
        Channel::start(
            socket,
            limits,
            frames,
            agreed.load(Ordering::SeqCst),
            #[cfg(feature = "webrtc")]
            plan,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_rejected_certificate_reads_as_one() {
        for rejected in [
            rustls::Error::NoCertificatesPresented,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
            rustls::Error::AlertReceived(rustls::AlertDescription::BadCertificate),
            rustls::Error::AlertReceived(rustls::AlertDescription::CertificateRequired),
        ] {
            assert_eq!(tls_failure(&rejected), Failure::Certificate, "{rejected:?}");
        }
        for forgeable in [
            rustls::Error::DecryptError,
            rustls::Error::AlertReceived(rustls::AlertDescription::DecodeError),
            rustls::Error::InvalidMessage(rustls::InvalidMessage::InvalidContentType),
        ] {
            assert_eq!(tls_failure(&forgeable), Failure::Protocol, "{forgeable:?}");
        }
    }
}
