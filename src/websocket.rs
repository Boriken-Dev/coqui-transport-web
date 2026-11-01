//! A blocking WebSocket dialer and listener.
//!
//! A worker thread owns each socket, so the channel can be read and written from different
//! threads. TLS comes from the caller's `rustls` configuration: this crate holds no trust roots
//! and decides nothing about identity. A plain socket is refused beyond loopback.

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::net::SocketAddr;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::Instant;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, StreamOwned};
use tungstenite::client::IntoClientRequest;
use tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tungstenite::http::{HeaderName, HeaderValue, StatusCode};
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{HandshakeError, Message, WebSocket};
use url::Url;

use crate::channel::{self, Kind};
use crate::failure::Failure;
use crate::pump::{Admission, Inbox, Limits, Received};

/// How long a worker waits on a silent socket before it looks for something to send.
const POLL: Duration = Duration::from_millis(10);
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

/// Either stream a socket can run over.
enum Stream {
    Plain(TcpStream),
    Client(Box<StreamOwned<ClientConnection, TcpStream>>),
    Server(Box<StreamOwned<ServerConnection, TcpStream>>),
}

impl Stream {
    fn tcp(&self) -> &TcpStream {
        match self {
            Self::Plain(stream) => stream,
            Self::Client(stream) => &stream.sock,
            Self::Server(stream) => &stream.sock,
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
        match self {
            Self::Plain(stream) => stream.write(data),
            Self::Client(stream) => stream.write(data),
            Self::Server(stream) => stream.write(data),
        }
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
    worker: Mutex<Option<thread::JoinHandle<()>>>,
    frames: Frames,
    max_message: Arc<AtomicUsize>,
}

impl fmt::Debug for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Channel")
            .field("frames", &self.frames)
            .field("max_message", &self.max_message.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Channel {
    fn start(socket: WebSocket<Stream>, limits: Limits, frames: Frames) -> Result<Self, Failure> {
        socket
            .get_ref()
            .tcp()
            .set_read_timeout(Some(POLL))
            .map_err(|e| io_failure(&e))?;
        socket
            .get_ref()
            .tcp()
            .set_write_timeout(Some(limits.send))
            .map_err(|e| io_failure(&e))?;
        socket
            .get_ref()
            .tcp()
            .set_nodelay(true)
            .map_err(|e| io_failure(&e))?;
        let (to_reader, inbox) = mpsc::sync_channel::<Received>(limits.pending.max(1));
        let (to_worker, outgoing) = mpsc::sync_channel::<Vec<u8>>(OUTGOING);
        let queued = Arc::new(AtomicUsize::new(0));
        let draining = Arc::clone(&queued);
        let max_message = Arc::new(AtomicUsize::new(limits.max_message));
        let current = Arc::clone(&max_message);
        let worker = thread::Builder::new()
            .name("coqui-web-websocket".into())
            .spawn(move || {
                worker(
                    socket, &to_reader, &outgoing, frames, &draining, limits, &current,
                )
            })
            .map_err(|_| Failure::Unsupported)?;
        Ok(Self {
            inbox: Inbox::new(inbox),
            outgoing: Mutex::new(Some(to_worker)),
            queued,
            queued_limit: limits.queued_bytes,
            worker: Mutex::new(Some(worker)),
            frames,
            max_message,
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
        })
    }

    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
        self.inbox.receive(timeout)
    }

    fn set_max_message(&self, bytes: usize) {
        self.max_message.store(bytes, Ordering::SeqCst);
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

/// A write that times out has not gone anywhere: the peer has stopped reading, which ends the channel. Reported as
/// such, since a caller treats `Failure::Timeout` from `receive` as a quiet moment.
fn ended(error: &tungstenite::Error) -> Failure {
    match ws_failure(error) {
        Failure::Timeout => Failure::NoProgress,
        failure => failure,
    }
}

/// Owns the socket: writes what is queued, reads what arrived, pings a silent peer, and stops reading while the reader
/// is behind, which is the back-pressure a peer feels.
fn worker(
    mut socket: WebSocket<Stream>,
    inbox: &SyncSender<Received>,
    outgoing: &mpsc::Receiver<Vec<u8>>,
    frames: Frames,
    queued: &AtomicUsize,
    limits: Limits,
    max_message: &AtomicUsize,
) {
    // What the socket was built with: the shared value may already have moved on.
    let mut applied = limits.max_message;
    let idle = limits.idle;
    let mut waiting: Option<Received> = None;
    let mut heard = Instant::now();
    let mut pinged = false;
    loop {
        loop {
            match outgoing.try_recv() {
                Ok(message) => {
                    queued.fetch_sub(message.len(), Ordering::SeqCst);
                    let framed = match frames {
                        Frames::Text => match core::str::from_utf8(&message) {
                            Ok(text) => Message::text(text.to_string()),
                            Err(_) => continue,
                        },
                        Frames::Binary => Message::binary(message),
                    };
                    match socket.write(framed) {
                        Ok(()) => {}
                        Err(tungstenite::Error::Io(error)) if interrupted(&error) => {
                            let _ = inbox.send(Err(Failure::NoProgress));
                            return;
                        }
                        Err(error) => {
                            let _ = inbox.send(Err(ended(&error)));
                            return;
                        }
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    finish(&mut socket);
                    return;
                }
            }
        }
        if heard.elapsed() >= idle.saturating_mul(2) {
            let _ = inbox.send(Err(Failure::NoProgress));
            return;
        }
        if heard.elapsed() >= idle && !pinged {
            pinged = true;
            let _ = socket.write(Message::Ping(Vec::new().into()));
        }
        match socket.flush() {
            Ok(()) => {}
            Err(tungstenite::Error::Io(error)) if interrupted(&error) => {}
            Err(tungstenite::Error::ConnectionClosed) => return,
            Err(error) => {
                let _ = inbox.send(Err(ended(&error)));
                return;
            }
        }
        if let Some(held) = waiting.take() {
            match inbox.try_send(held) {
                Ok(()) => {}
                Err(TrySendError::Full(held)) => {
                    waiting = Some(held);
                    thread::sleep(POLL);
                    continue;
                }
                Err(TrySendError::Disconnected(_)) => {
                    finish(&mut socket);
                    return;
                }
            }
        }
        // Looked at after this turn's writes: a peer answering one of them meets the limit its sender had set.
        let wanted = max_message.load(Ordering::SeqCst);
        if wanted != applied {
            applied = wanted;
            socket.set_config(|config| {
                config.max_message_size = Some(wanted);
                config.max_frame_size = Some(wanted);
            });
        }
        match socket.read() {
            Ok(message) => {
                heard = Instant::now();
                pinged = false;
                match message {
                    Message::Text(text) => waiting = Some(Ok(text.as_bytes().to_vec())),
                    Message::Binary(body) if frames == Frames::Binary => {
                        waiting = Some(Ok(body.to_vec()))
                    }
                    Message::Binary(_) => {
                        let _ = inbox.send(Err(Failure::Protocol));
                        finish(&mut socket);
                        return;
                    }
                    Message::Close(_) => {
                        // An orderly close: the reader sees the end when this sender drops.
                        let _ = socket.flush();
                        return;
                    }
                    _ => {}
                }
            }
            Err(tungstenite::Error::ConnectionClosed) => {
                let _ = socket.flush();
                return;
            }
            Err(tungstenite::Error::Io(error)) if interrupted(&error) => {}
            Err(error) => {
                let _ = inbox.send(Err(ended(&error)));
                finish(&mut socket);
                return;
            }
        }
    }
}

/// Starts the closing handshake and leaves it a moment to finish, then the socket drops anyway.
fn finish(socket: &mut WebSocket<Stream>) {
    let _ = socket.close(None);
    let until = Instant::now() + Duration::from_millis(500);
    while Instant::now() < until {
        match socket.read() {
            Ok(_) => {}
            Err(tungstenite::Error::Io(error)) if interrupted(&error) => {}
            Err(_) => return,
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
            "ws" if endpoint_is_loopback(endpoint) => Stream::Plain(tcp),
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
                Stream::Client(Box::new(StreamOwned::new(session, tcp)))
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
        let (socket, _) =
            tungstenite::client::client_with_config(request, stream, Some(config(self.limits)))
                .map_err(|error| match error {
                    HandshakeError::Interrupted(_) => Failure::Timeout,
                    HandshakeError::Failure(error) => ws_failure(&error),
                })?;
        Channel::start(socket, self.limits, self.frames)
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
            None => Stream::Plain(tcp),
            Some(tls) => {
                let session =
                    ServerConnection::new(Arc::clone(tls)).map_err(|_| Failure::Protocol)?;
                Stream::Server(Box::new(StreamOwned::new(session, tcp)))
            }
        };
        let check =
            move |request: &Request, response: Response| -> Result<Response, ErrorResponse> {
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
        Channel::start(socket, limits, frames)
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
