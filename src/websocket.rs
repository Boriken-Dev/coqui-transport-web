//! A blocking WebSocket dialer and listener.
//!
//! A worker thread owns each socket, so the channel can be read and written from different
//! threads, and sleeps until the socket is ready or a caller wakes it. TLS comes from the caller's
//! `rustls` configuration: this crate holds no trust roots and decides nothing about identity. A
//! plain socket is refused beyond loopback.

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::mem;
use core::net::SocketAddr;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::time::Duration;
use std::io::{self, IoSlice, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::Instant;

use mio::{Events, Interest, Poll, Registry, Token, Waker};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, StreamOwned};
use tungstenite::client::IntoClientRequest;
use tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tungstenite::http::{HeaderName, HeaderValue, StatusCode};
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{HandshakeError, Message, WebSocket};
use url::Url;

use crate::channel::{self, Datagrams, Delivery, Kind};
use crate::failure::Failure;
use crate::frame::{self, WS_DATAGRAMS_PROTOCOL, WsPart};
use crate::pump::{Admission, Inbox, Limits, Received};

/// How often a listener looks for a connection, and a worker for room in a full inbox if a reader taking one has not said.
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
        }
    }

    /// Hands the socket to `registry`: from here on it never blocks.
    fn register(&mut self, registry: &Registry) -> io::Result<()> {
        let Socket::Blocking(tcp) = mem::replace(&mut self.socket, Socket::Closed) else {
            return Err(io::ErrorKind::NotConnected.into());
        };
        tcp.set_read_timeout(None)?;
        tcp.set_write_timeout(None)?;
        tcp.set_nodelay(true)?;
        tcp.set_nonblocking(true)?;
        let mut tcp = mio::net::TcpStream::from_std(tcp);
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
        written
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

/// A WebSocket channel. Reads and writes happen on the worker thread that owns the socket.
pub struct Channel {
    inbox: Inbox,
    outgoing: Mutex<Option<SyncSender<Vec<u8>>>>,
    queued: Arc<AtomicUsize>,
    queued_limit: usize,
    waker: Arc<Waker>,
    // Set by a worker that found the inbox full.
    behind: Arc<AtomicBool>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
    frames: Frames,
    max_message: Arc<AtomicUsize>,
    datagrams: Option<WsDatagrams>,
}

/// Datagrams as tagged messages on the socket, for a channel whose ends agreed to them.
struct WsDatagrams {
    outgoing: SyncSender<Vec<u8>>,
    waker: Arc<Waker>,
    inbox: Inbox,
    dropped: Arc<AtomicU64>,
    wanted: Arc<AtomicBool>,
    max_size: usize,
}

impl Datagrams for WsDatagrams {
    fn max_size(&self) -> Option<usize> {
        Some(self.max_size)
    }

    fn send(&self, payload: &[u8]) -> Result<(), Failure> {
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
        Delivery::OverStream
    }
}

/// The worker's end of [`WsDatagrams`].
struct WorkerDatagrams {
    outgoing: mpsc::Receiver<Vec<u8>>,
    inbox: SyncSender<Received>,
    dropped: Arc<AtomicU64>,
    wanted: Arc<AtomicBool>,
    max_size: usize,
}

impl WorkerDatagrams {
    /// Holds one only once someone has asked for them: a peer that has proved nothing must not be able to fill memory that way.
    fn arrived(&self, body: &[u8]) {
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

impl fmt::Debug for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Channel")
            .field("frames", &self.frames)
            .field("max_message", &self.max_message.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Channel {
    fn start(
        mut socket: WebSocket<Stream>,
        limits: Limits,
        frames: Frames,
        tagged: bool,
    ) -> Result<Self, Failure> {
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
        let behind = Arc::new(AtomicBool::new(false));
        let noting = Arc::clone(&behind);
        let max_message = Arc::new(AtomicUsize::new(limits.max_message));
        let current = Arc::clone(&max_message);
        let (datagrams, for_worker) = if tagged {
            let pending = limits.pending_datagrams.max(1);
            let (send, to_send) = mpsc::sync_channel(pending);
            let (arrived, inbox) = mpsc::sync_channel(pending);
            let dropped = Arc::new(AtomicU64::new(0));
            let wanted = Arc::new(AtomicBool::new(false));
            (
                Some(WsDatagrams {
                    outgoing: send,
                    waker: Arc::clone(&waker),
                    inbox: Inbox::new(inbox),
                    dropped: Arc::clone(&dropped),
                    wanted: Arc::clone(&wanted),
                    max_size: limits.websocket_datagram,
                }),
                Some(WorkerDatagrams {
                    outgoing: to_send,
                    inbox: arrived,
                    dropped,
                    wanted,
                    max_size: limits.websocket_datagram,
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
                    limits,
                    max_message: current,
                    applied: limits.max_message,
                    datagrams: for_worker,
                    waiting: None,
                    heard: Instant::now(),
                    pinged: false,
                    unsent: None,
                    watching_writes: false,
                }
                .run();
            })
            .map_err(|_| Failure::Unsupported)?;
        Ok(Self {
            inbox: Inbox::new(inbox),
            outgoing: Mutex::new(Some(to_worker)),
            queued,
            queued_limit: limits.queued_bytes,
            waker,
            behind,
            worker: Mutex::new(Some(worker)),
            frames,
            max_message,
            datagrams,
        })
    }
}

impl channel::Channel for Channel {
    fn send(&self, message: &[u8]) -> Result<(), Failure> {
        if message.is_empty() || message.len() > self.max_message.load(Ordering::SeqCst) {
            return Err(Failure::Protocol);
        }
        if self.frames == Frames::Text && core::str::from_utf8(message).is_err() {
            return Err(Failure::Protocol);
        }
        let outgoing = self.outgoing.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(queue) = outgoing.as_ref() else {
            return Err(Failure::Cancelled);
        };
        if self
            .queued
            .load(Ordering::SeqCst)
            .saturating_add(message.len())
            > self.queued_limit
        {
            return Err(Failure::NoProgress);
        }
        self.queued.fetch_add(message.len(), Ordering::SeqCst);
        queue.try_send(message.to_vec()).map_err(|error| {
            self.queued.fetch_sub(message.len(), Ordering::SeqCst);
            match error {
                TrySendError::Full(_) => Failure::NoProgress,
                TrySendError::Disconnected(_) => Failure::PathLost,
            }
        })?;
        let _ = self.waker.wake();
        Ok(())
    }

    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
        let next = self.inbox.receive(timeout);
        if self.behind.swap(false, Ordering::SeqCst) {
            let _ = self.waker.wake();
        }
        next
    }

    fn set_max_message(&self, bytes: usize) {
        self.max_message.store(bytes, Ordering::SeqCst);
    }

    fn datagrams(&self) -> Option<&dyn Datagrams> {
        let datagrams = self.datagrams.as_ref()?;
        datagrams.wanted.store(true, Ordering::SeqCst);
        Some(datagrams)
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

/// How a worker stops.
enum Stop {
    /// Reports this and drops the socket.
    Failed(Failure),
    /// Reports this, then closes in order.
    FailedClosing(Failure),
    /// Nobody will send any more: closes in order.
    Closing,
    /// The peer closed, and what is left to send ends with the reply.
    Replying,
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
    limits: Limits,
    max_message: Arc<AtomicUsize>,
    // What the socket was built with: the shared value may already have moved on.
    applied: usize,
    datagrams: Option<WorkerDatagrams>,
    waiting: Option<Received>,
    heard: Instant,
    pinged: bool,
    // When the socket stopped taking what there is to send.
    unsent: Option<Instant>,
    watching_writes: bool,
}

impl Worker {
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
        match stop {
            Stop::Failed(failure) => self.report(failure),
            Stop::FailedClosing(failure) => {
                self.report(failure);
                self.finish();
            }
            Stop::Closing => self.finish(),
            Stop::Replying => {
                let _ = self.drained();
            }
            Stop::Gone => {}
        }
    }

    fn turn(&mut self) -> Result<(), Stop> {
        let more = self.write_queued()?;
        self.keep_alive()?;
        // Writing stops when the socket is full, and if that has passed, nothing will say so.
        let was_unsent = self.unsent.is_some();
        let behind = self.deliver()?;
        let read = !behind && self.read_one()?;
        let retry = self.flush()?;
        let room = was_unsent && self.unsent.is_none();
        if more || read || retry || room || (!behind && self.socket.get_ref().holds_unread()) {
            return Ok(());
        }
        self.wait(behind)
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
    /// number otherwise, so a busy sender cannot keep this from reading, and answers whether more may be waiting: nothing
    /// will wake this for what is already queued. Datagrams go first: a few at most, and a message sent after one follows it.
    fn write_queued(&mut self) -> Result<bool, Stop> {
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
        for _ in 0..OUTGOING {
            if self.unsent.is_some() {
                return Ok(false);
            }
            let message = match self.outgoing.try_recv() {
                Ok(message) => message,
                Err(mpsc::TryRecvError::Empty) => return Ok(more),
                Err(mpsc::TryRecvError::Disconnected) => return Err(Stop::Closing),
            };
            self.queued.fetch_sub(message.len(), Ordering::SeqCst);
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

    fn keep_alive(&mut self) -> Result<(), Stop> {
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
        match self.inbox.try_send(held) {
            Ok(()) => Ok(false),
            Err(TrySendError::Full(held)) => {
                self.waiting = Some(held);
                self.behind.store(true, Ordering::SeqCst);
                Ok(true)
            }
            Err(TrySendError::Disconnected(_)) => Err(Stop::Closing),
        }
    }

    /// Whether a message came in, in which case there may be another.
    fn read_one(&mut self) -> Result<bool, Stop> {
        // Looked at after this turn's writes: a peer answering one of them meets the limit its sender had set.
        let wanted = self.max_message.load(Ordering::SeqCst);
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
            Err(error) => return Err(Stop::FailedClosing(ended(&error))),
        };
        self.heard = Instant::now();
        self.pinged = false;
        match message {
            Message::Text(text) => self.waiting = Some(Ok(text.as_bytes().to_vec())),
            Message::Binary(body) if self.datagrams.is_some() => match frame::ws_part(&body) {
                Ok(WsPart::Datagram(datagram)) => {
                    if let Some(datagrams) = &self.datagrams {
                        datagrams.arrived(datagram);
                    }
                }
                Ok(WsPart::Message(message)) if self.frames == Frames::Binary => {
                    self.waiting = Some(Ok(message.to_vec()));
                }
                _ => return Err(Stop::FailedClosing(Failure::Protocol)),
            },
            Message::Binary(body) if self.frames == Frames::Binary => {
                self.waiting = Some(Ok(body.to_vec()));
            }
            Message::Binary(_) => return Err(Stop::FailedClosing(Failure::Protocol)),
            // An orderly close: the reader sees the end when this sender drops.
            Message::Close(_) => return Err(Stop::Replying),
            _ => {}
        }
        Ok(true)
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

    /// Sleeps until the socket or a caller has something, or until the next thing that is due.
    fn wait(&mut self, behind: bool) -> Result<(), Stop> {
        let silence = if self.pinged {
            self.limits.idle.saturating_mul(2)
        } else {
            self.limits.idle
        };
        let mut limit = silence.saturating_sub(self.heard.elapsed());
        if let Some(left) = self.send_left() {
            limit = limit.min(left);
        }
        if behind {
            limit = limit.min(POLL);
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
    fn finish(&mut self) {
        // The close frame is queued whatever this returns, and `drained` sends it.
        let _ = self.socket.close(None);
        if !self.drained() {
            return;
        }
        let until = Instant::now() + Duration::from_millis(500);
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            match self.socket.read() {
                Ok(_) => {}
                Err(error) if would_block(&error) => {
                    if self.sleep(Some(left)).is_err() {
                        return;
                    }
                }
                Err(_) => return,
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
}

impl fmt::Debug for Dialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dialer")
            .field("tls", &self.tls.is_some())
            .field("limits", &self.limits)
            .field("frames", &self.frames)
            .field("headers", &self.headers.len())
            .finish()
    }
}

impl Dialer {
    /// A dialer with no TLS configuration, which can reach only `ws://`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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

    fn open_tcp(url: &Url, deadline: Instant) -> Result<TcpStream, Failure> {
        let host = url.host_str().ok_or(Failure::Protocol)?;
        let port = url.port_or_known_default().ok_or(Failure::Protocol)?;
        // IPv6 hosts come bracketed from the URL; a resolver wants them bare.
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let addresses = (host, port)
            .to_socket_addrs()
            .map_err(|_| Failure::PathLost)?;
        let mut last = Failure::PathLost;
        for address in addresses {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Failure::Timeout);
            }
            match TcpStream::connect_timeout(&address, left) {
                Ok(stream) => return Ok(stream),
                Err(error) => last = io_failure(&error),
            }
        }
        Err(last)
    }
}

impl channel::Dialer for Dialer {
    type Connection = Channel;

    fn dial(&mut self, kind: Kind, endpoint: &Url, timeout: Duration) -> Result<Channel, Failure> {
        if kind != Kind::WebSocket {
            return Err(Failure::Unsupported);
        }
        let timeout = timeout.min(self.limits.handshake);
        let deadline = Instant::now() + timeout;
        let tcp = Self::open_tcp(endpoint, deadline)?;
        tcp.set_read_timeout(Some(timeout))
            .map_err(|e| io_failure(&e))?;
        tcp.set_write_timeout(Some(timeout))
            .map_err(|e| io_failure(&e))?;
        let stream = match endpoint.scheme() {
            "ws" if endpoint_is_loopback(endpoint) => Stream::Plain(Transport::new(tcp)),
            "ws" => return Err(Failure::Permission),
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
                HeaderValue::from_static(WS_DATAGRAMS_PROTOCOL),
            );
        }
        let (socket, _) =
            tungstenite::client::client_with_config(request, stream, Some(config(self.limits)))
                .map_err(|error| match error {
                    HandshakeError::Interrupted(_) => Failure::Timeout,
                    HandshakeError::Failure(error) => ws_failure(&error),
                })?;
        Channel::start(socket, self.limits, self.frames, self.datagrams)
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
}

impl fmt::Debug for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Listener")
            .field("address", &self.socket.local_addr().ok())
            .field("tls", &self.tls.is_some())
            .field("limits", &self.limits)
            .field("frames", &self.frames)
            .field("origins", &self.origins)
            .finish()
    }
}

impl Listener {
    /// Binds `address`. With no TLS configuration only a loopback address is accepted: a plain
    /// socket on any other is refused, as plain WebSocket is for local development only.
    ///
    /// # Errors
    ///
    /// [`Failure::Permission`] for a plain socket beyond loopback; otherwise why it could not bind.
    pub fn bind(address: SocketAddr, tls: Option<Arc<ServerConfig>>) -> Result<Self, Failure> {
        if tls.is_none() && !address.ip().is_loopback() {
            return Err(Failure::Permission);
        }
        let socket = TcpListener::bind(address).map_err(|e| io_failure(&e))?;
        socket.set_nonblocking(true).map_err(|e| io_failure(&e))?;
        Ok(Self {
            socket,
            tls,
            limits: Limits::default(),
            frames: Frames::default(),
            origins: Vec::new(),
            admission: None,
        })
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
        Ok(Pending {
            tcp: self.next_socket(timeout)?,
            tls: self.tls.clone(),
            limits: self.limits,
            frames: self.frames,
            origins: self.origins.clone(),
        })
    }

    fn next_socket(&self, timeout: Option<Duration>) -> Result<TcpStream, Failure> {
        let deadline = timeout.map(|limit| Instant::now() + limit);
        loop {
            match self.socket.accept() {
                Ok((tcp, source)) => {
                    if self.admission.as_ref().is_none_or(|admit| admit(source)) {
                        return Ok(tcp);
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
    tls: Option<Arc<ServerConfig>>,
    limits: Limits,
    frames: Frames,
    origins: Vec<alloc::string::String>,
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending")
            .field("peer", &self.tcp.peer_addr().ok())
            .finish_non_exhaustive()
    }
}

impl Pending {
    /// Completes the handshake within the handshake limit in total: a peer sending a byte at a time gets no longer.
    ///
    /// # Errors
    ///
    /// [`Failure::Timeout`] past the limit; [`Failure::Permission`] for a refused origin; otherwise why it failed.
    // tungstenite fixes the callback's error type, and it is large.
    #[allow(clippy::result_large_err)]
    pub fn handshake(self) -> Result<Channel, Failure> {
        let Self {
            tcp,
            tls,
            limits,
            frames,
            origins,
        } = self;
        tcp.set_nonblocking(false).map_err(|e| io_failure(&e))?;
        tcp.set_read_timeout(Some(limits.handshake))
            .map_err(|e| io_failure(&e))?;
        tcp.set_write_timeout(Some(limits.handshake))
            .map_err(|e| io_failure(&e))?;
        // Per-read timeouts alone let a slow peer stretch this: a watchdog ends the socket at the total limit.
        let watched = tcp.try_clone().map_err(|e| io_failure(&e))?;
        let (done, finished) = mpsc::channel::<()>();
        let watchdog = thread::Builder::new()
            .name("coqui-web-handshake".into())
            .spawn(move || {
                if finished.recv_timeout(limits.handshake) == Err(mpsc::RecvTimeoutError::Timeout) {
                    let _ = watched.shutdown(std::net::Shutdown::Both);
                }
            })
            .map_err(|_| Failure::Unsupported)?;
        let stream = match &tls {
            None => Stream::Plain(Transport::new(tcp)),
            Some(tls) => {
                let session =
                    ServerConnection::new(Arc::clone(tls)).map_err(|_| Failure::Protocol)?;
                Stream::Server(Box::new(StreamOwned::new(session, Transport::new(tcp))))
            }
        };
        let agreed = Arc::new(AtomicBool::new(false));
        let agreeing = Arc::clone(&agreed);
        let check =
            move |request: &Request, mut response: Response| -> Result<Response, ErrorResponse> {
                let asked = request
                    .headers()
                    .get_all("sec-websocket-protocol")
                    .iter()
                    .filter_map(|value| value.to_str().ok())
                    .flat_map(|value| value.split(','))
                    .any(|name| name.trim() == WS_DATAGRAMS_PROTOCOL);
                if asked {
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
        let started = Instant::now();
        let socket = tungstenite::accept_hdr_with_config(stream, check, Some(config(limits)));
        drop(done);
        let _ = watchdog.join();
        let socket = socket.map_err(|error| match error {
            HandshakeError::Interrupted(_) => Failure::Timeout,
            HandshakeError::Failure(_) if started.elapsed() >= limits.handshake => Failure::Timeout,
            HandshakeError::Failure(error) => ws_failure(&error),
        })?;
        Channel::start(socket, limits, frames, agreed.load(Ordering::SeqCst))
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
