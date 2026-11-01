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

fn io_failure(error: &io::Error) -> Failure {
    // Any TLS error is a security failure, whichever verifier raised it: it must never read as a path
    // problem, which is what permits a fallback.
    if error
        .get_ref()
        .is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some())
    {
        return Failure::Certificate;
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
    frames: Frames,
    max_message: usize,
}

impl fmt::Debug for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Channel")
            .field("frames", &self.frames)
            .field("max_message", &self.max_message)
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
            .set_nodelay(true)
            .map_err(|e| io_failure(&e))?;
        let (to_reader, inbox) = mpsc::sync_channel::<Received>(limits.pending.max(1));
        let (to_worker, outgoing) = mpsc::sync_channel::<Vec<u8>>(OUTGOING);
        thread::Builder::new()
            .name("coqui-web-websocket".into())
            .spawn(move || worker(socket, &to_reader, &outgoing, frames))
            .map_err(|_| Failure::Unsupported)?;
        Ok(Self {
            inbox: Inbox::new(inbox),
            outgoing: Mutex::new(Some(to_worker)),
            frames,
            max_message: limits.max_message,
        })
    }
}

impl channel::Channel for Channel {
    fn send(&self, message: &[u8]) -> Result<(), Failure> {
        if message.is_empty() || message.len() > self.max_message {
            return Err(Failure::Protocol);
        }
        if self.frames == Frames::Text && core::str::from_utf8(message).is_err() {
            return Err(Failure::Protocol);
        }
        let outgoing = self.outgoing.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(queue) = outgoing.as_ref() else {
            return Err(Failure::Cancelled);
        };
        queue
            .try_send(message.to_vec())
            .map_err(|error| match error {
                TrySendError::Full(_) => Failure::NoProgress,
                TrySendError::Disconnected(_) => Failure::PathLost,
            })
    }

    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
        self.inbox.receive(timeout)
    }

    fn close(&self) {
        // The worker sees its queue end, sends the close frame and releases the socket.
        drop(
            self.outgoing
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        channel::Channel::close(self);
    }
}

/// Owns the socket: writes what is queued, reads what arrived, and stops reading while the reader
/// is behind, which is the back-pressure a peer feels.
fn worker(
    mut socket: WebSocket<Stream>,
    inbox: &SyncSender<Received>,
    outgoing: &mpsc::Receiver<Vec<u8>>,
    frames: Frames,
) {
    let mut waiting: Option<Received> = None;
    loop {
        loop {
            match outgoing.try_recv() {
                Ok(message) => {
                    let framed = match frames {
                        Frames::Text => match core::str::from_utf8(&message) {
                            Ok(text) => Message::text(text.to_string()),
                            Err(_) => continue,
                        },
                        Frames::Binary => Message::binary(message),
                    };
                    if let Err(error) = socket.write(framed) {
                        let _ = inbox.send(Err(ws_failure(&error)));
                        return;
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    finish(&mut socket);
                    return;
                }
            }
        }
        match socket.flush() {
            Ok(()) => {}
            Err(tungstenite::Error::Io(error)) if interrupted(&error) => {}
            Err(tungstenite::Error::ConnectionClosed) => return,
            Err(error) => {
                let _ = inbox.send(Err(ws_failure(&error)));
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
        match socket.read() {
            Ok(Message::Text(text)) => waiting = Some(Ok(text.as_bytes().to_vec())),
            Ok(Message::Binary(body)) if frames == Frames::Binary => {
                waiting = Some(Ok(body.to_vec()))
            }
            Ok(Message::Binary(_)) => {
                let _ = inbox.send(Err(Failure::Protocol));
                finish(&mut socket);
                return;
            }
            Ok(Message::Close(_)) | Err(tungstenite::Error::ConnectionClosed) => {
                // An orderly close: the reader sees the end when this sender drops.
                let _ = socket.flush();
                return;
            }
            Ok(_) => {}
            Err(tungstenite::Error::Io(error)) if interrupted(&error) => {}
            Err(error) => {
                let _ = inbox.send(Err(ws_failure(&error)));
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
            "ws" => Stream::Plain(tcp),
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

    /// Waits for one connection and completes its handshake within the handshake limit. A peer that
    /// fails the handshake holds this up for no longer than that.
    ///
    /// # Errors
    ///
    /// [`Failure::Timeout`] when no connection arrived within `timeout`, or a handshake took too long;
    /// [`Failure::Permission`] for a refused origin; otherwise why the handshake failed.
    // tungstenite fixes the callback's error type, and it is large.
    #[allow(clippy::result_large_err)]
    pub fn accept(&self, timeout: Option<Duration>) -> Result<Channel, Failure> {
        let tcp = self.next_socket(timeout)?;
        tcp.set_nonblocking(false).map_err(|e| io_failure(&e))?;
        tcp.set_read_timeout(Some(self.limits.handshake))
            .map_err(|e| io_failure(&e))?;
        tcp.set_write_timeout(Some(self.limits.handshake))
            .map_err(|e| io_failure(&e))?;
        let stream = match &self.tls {
            None => Stream::Plain(tcp),
            Some(tls) => {
                let session =
                    ServerConnection::new(Arc::clone(tls)).map_err(|_| Failure::Protocol)?;
                Stream::Server(Box::new(StreamOwned::new(session, tcp)))
            }
        };
        let origins = self.origins.clone();
        let check = move |request: &Request,
                          response: Response|
              -> Result<Response, ErrorResponse> {
            let origin = request.headers().get("origin").map(HeaderValue::to_str);
            match origin {
                Some(Ok(origin))
                    if !origins.is_empty() && !origins.iter().any(|allowed| allowed == origin) =>
                {
                    let mut refused = ErrorResponse::new(None);
                    *refused.status_mut() = StatusCode::FORBIDDEN;
                    Err(refused)
                }
                Some(Err(_)) if !origins.is_empty() => {
                    let mut refused = ErrorResponse::new(None);
                    *refused.status_mut() = StatusCode::FORBIDDEN;
                    Err(refused)
                }
                _ => Ok(response),
            }
        };
        let socket = tungstenite::accept_hdr_with_config(stream, check, Some(config(self.limits)))
            .map_err(|error| match error {
                HandshakeError::Interrupted(_) => Failure::Timeout,
                HandshakeError::Failure(error) => ws_failure(&error),
            })?;
        Channel::start(socket, self.limits, self.frames)
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
