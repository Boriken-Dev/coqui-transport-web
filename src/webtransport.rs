//! A WebTransport dialer and listener: one bidirectional stream, framed by [`frame`], and raw datagrams beside it.
//!
//! QUIC needs an async runtime, so each dialer and listener runs a small one inside. Nothing async
//! crosses this API and the caller needs no runtime of its own. Its calls block, so a caller already
//! inside an async runtime makes them through that runtime's blocking pool.

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::net::SocketAddr;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::time::Duration;
use std::io;
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Mutex, OnceLock, PoisonError};

use rustls::{ClientConfig, ServerConfig};
use tokio::runtime::{Builder, Handle, Runtime};
use tokio::sync::Notify;
use tokio::task::AbortHandle;
use tokio::time::timeout as within;
use url::Url;
use wtransport::config::{DnsLookupFuture, DnsResolver};
use wtransport::endpoint::IncomingSessionFuture;
use wtransport::endpoint::endpoint_side::Client;
use wtransport::error::{ConnectingError, ConnectionClose, ConnectionError, SendDatagramError};
use wtransport::quinn::crypto::rustls::QuicServerConfig;
use wtransport::quinn::{self, Incoming};
use wtransport::tls::{Sha256Digest, WEBTRANSPORT_ALPN};
use wtransport::{Connection, Endpoint, RecvStream, SendStream, VarInt};

use crate::channel::{self, Datagrams, Delivery, Kind};
use crate::endpoints::CertificatePin;
use crate::failure::Failure;
use crate::frame::{self, Decoder};
use crate::pump::{Abandon, Admission, Cancel, Inbox, Limits, Received};
#[cfg(feature = "webrtc")]
use crate::webrtc::Port;

const READ_CHUNK: usize = 16 * 1024;

fn runtime() -> Result<Arc<Runtime>, Failure> {
    Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("coqui-web-webtransport")
        .enable_all()
        .build()
        .map(Arc::new)
        .map_err(|_| Failure::Unsupported)
}

/// A tokio timeout has to be created inside its runtime, so this future builds it when polled.
async fn bounded<F: Future>(
    limit: Duration,
    future: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    within(limit, future).await
}

fn connecting_failure(error: &ConnectingError) -> Failure {
    match error {
        ConnectingError::DnsLookup(_) | ConnectingError::DnsNotFound => Failure::PathLost,
        // HTTP/3 with no WebTransport at this URL looks the same as a refusal, and a real refusal is refused again on the
        // other transport, which must prove the same peer anyway.
        ConnectingError::SessionRejected => Failure::Unsupported,
        ConnectingError::ConnectionError(error) => connection_failure(error),
        ConnectingError::InvalidUrl(_) | ConnectingError::InvalidServerName(_) => Failure::Protocol,
        _ => Failure::Unsupported,
    }
}

/// What a QUIC close says, from the code `QuicProtoError` shows only in its text. A TLS alert is 0x100 plus its number (RFC 9001
/// section 4.8): one about a certificate must never read as anything else, and another means this peer does not offer this
/// transport, such as a QUIC server with no HTTP/3.
fn quic_failure(code: Option<u64>) -> Failure {
    match code {
        // bad_certificate to certificate_unknown, unknown_ca, access_denied, certificate_required.
        Some(0x12a..=0x12e | 0x130 | 0x131 | 0x174) => Failure::Certificate,
        Some(0x100..=0x1ff) => Failure::Unsupported,
        _ => Failure::Protocol,
    }
}

fn quic_code(text: &str) -> Option<u64> {
    let (_, code) = text.rsplit_once("(code: ")?;
    let code = code.strip_suffix(')')?;
    match code.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => code.parse().ok(),
    }
}

/// A server refusing a connection before its handshake, as a listener's admission does, closes it with QUIC's CONNECTION_REFUSED
/// and no reason, which shows only in the close's text. That close travels in an Initial packet, whose keys anyone who saw the
/// client's first packet can derive (RFC 9001 section 5.2), so it proves no more than a TCP reset does.
fn refused(close: &ConnectionClose) -> bool {
    close.to_string() == wtransport::quinn::TransportErrorCode::CONNECTION_REFUSED.to_string()
}

/// What a peer's close says when it carries a TLS alert, as a server refusing a client's certificate sends one. quinn shows the code
/// only in the close's text, so each crypto code's own rendering is matched. A close in an Initial packet is forgeable, and the
/// failure it can be made to read as never permits a fallback.
fn closed_failure(close: &ConnectionClose) -> Failure {
    let text = close.to_string();
    let alert = (0..=u8::MAX).find(|alert| {
        let code = wtransport::quinn::TransportErrorCode::crypto(*alert).to_string();
        text.strip_prefix(code.as_str())
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(": "))
    });
    match alert {
        Some(alert) => quic_failure(Some(0x100 + u64::from(alert))),
        None => Failure::PathLost,
    }
}

fn connection_failure(error: &ConnectionError) -> Failure {
    match error {
        ConnectionError::ConnectionClosed(close) if refused(close) => Failure::Permission,
        ConnectionError::ConnectionClosed(close) => closed_failure(close),
        ConnectionError::TimedOut => Failure::Timeout,
        ConnectionError::QuicProto(proto) => quic_failure(quic_code(&proto.to_string())),
        ConnectionError::LocallyClosed => Failure::Cancelled,
        _ => Failure::PathLost,
    }
}

/// A WebTransport channel over one bidirectional stream.
pub struct Channel {
    inbox: Inbox,
    connection: Arc<Connection>,
    send: Mutex<Option<SendStream>>,
    reader: AbortHandle,
    handle: Handle,
    // The largest message read; the reader applies it.
    max_message: Arc<AtomicUsize>,
    max_send: AtomicUsize,
    send_limit: Duration,
    pending_datagrams: usize,
    datagrams: OnceLock<QuicDatagrams>,
    peer_certificates: Option<Vec<Vec<u8>>>,
    // Keeps the driver's runtime alive as long as a channel needs it.
    _runtime: Arc<Runtime>,
    // Its packets go through this port's relay, so it must outlive the listener if the channel does.
    #[cfg(feature = "webrtc")]
    port: Option<Port>,
}

impl fmt::Debug for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Channel")
            .field("remote", &self.remote())
            .field("max_message", &self.max_message.load(Ordering::SeqCst))
            .field("max_send", &self.max_send.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Channel {
    /// Where the peer is. Through a port, the connection itself only knows the relay.
    fn remote(&self) -> SocketAddr {
        let seen = self.connection.remote_address();
        #[cfg(feature = "webrtc")]
        if let Some(source) = self.port.as_ref().and_then(|port| port.source_of(seen)) {
            return source;
        }
        seen
    }

    fn start(
        connection: Connection,
        send: SendStream,
        recv: RecvStream,
        limits: Limits,
        runtime: Arc<Runtime>,
        #[cfg(feature = "webrtc")] port: Option<Port>,
    ) -> Self {
        let (to_reader, inbox) = mpsc::sync_channel::<Received>(limits.pending.max(1));
        let handle = runtime.handle().clone();
        let max_message = Arc::new(AtomicUsize::new(limits.max_message));
        let reader = handle
            .spawn(read_loop(recv, Arc::clone(&max_message), to_reader))
            .abort_handle();
        let peer_certificates = connection
            .peer_identity()
            .filter(|chain| !chain.as_slice().is_empty())
            .map(|chain| {
                chain
                    .as_slice()
                    .iter()
                    .map(|certificate| certificate.der().to_vec())
                    .collect()
            });
        let connection = Arc::new(connection);
        // Through a port, a finished handshake is what keeps a relay from being replaced, and the connection's end is what ends it.
        #[cfg(feature = "webrtc")]
        if let Some(port) = &port {
            port.prove(connection.remote_address());
            let (port, watched) = (port.clone(), Arc::clone(&connection));
            handle.spawn(async move {
                watched.closed().await;
                port.release(watched.remote_address());
            });
        }
        Self {
            inbox: Inbox::new(inbox),
            connection,
            send: Mutex::new(Some(send)),
            reader,
            handle,
            max_message,
            max_send: AtomicUsize::new(limits.max_message),
            send_limit: limits.send,
            pending_datagrams: limits.pending_datagrams,
            datagrams: OnceLock::new(),
            peer_certificates,
            _runtime: runtime,
            #[cfg(feature = "webrtc")]
            port,
        }
    }
}

/// One channel's datagrams. Read only once someone asks for them: until then the transport's own bounded buffer holds them.
struct QuicDatagrams {
    connection: Arc<Connection>,
    inbox: Inbox,
    dropped: Arc<AtomicU64>,
    reader: AbortHandle,
}

impl QuicDatagrams {
    fn start(connection: &Arc<Connection>, pending: usize, handle: &Handle) -> Self {
        let (to_reader, inbox) = mpsc::sync_channel::<Received>(pending.max(1));
        let dropped = Arc::new(AtomicU64::new(0));
        let reader = handle
            .spawn(read_datagrams(
                Arc::clone(connection),
                to_reader,
                Arc::clone(&dropped),
            ))
            .abort_handle();
        Self {
            connection: Arc::clone(connection),
            inbox: Inbox::new(inbox),
            dropped,
            reader,
        }
    }
}

/// Never waits on the reader: a datagram that finds no room is gone, which is what a datagram may be, and is counted.
async fn read_datagrams(
    connection: Arc<Connection>,
    inbox: SyncSender<Received>,
    dropped: Arc<AtomicU64>,
) {
    while let Ok(datagram) = connection.receive_datagram().await {
        match inbox.try_send(Ok(datagram.payload().to_vec())) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::TrySendError::Disconnected(_)) => return,
        }
    }
}

impl Datagrams for QuicDatagrams {
    fn max_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }

    fn send(&self, payload: &[u8]) -> Result<(), Failure> {
        self.connection
            .send_datagram(payload)
            .map_err(|error| match error {
                SendDatagramError::TooLarge => Failure::Protocol,
                SendDatagramError::UnsupportedByPeer => Failure::Unsupported,
                SendDatagramError::NotConnected => Failure::PathLost,
            })
    }

    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
        self.inbox.receive(timeout)
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn delivery(&self) -> Delivery {
        Delivery::Unreliable
    }
}

/// Decodes the stream into messages. A full queue parks this task, so QUIC flow control tells the
/// peer to slow down rather than memory growing.
async fn read_loop(mut recv: RecvStream, maximum: Arc<AtomicUsize>, inbox: SyncSender<Received>) {
    let mut decoder = Decoder::new(maximum.load(Ordering::SeqCst));
    let mut chunk = vec![0_u8; READ_CHUNK];
    loop {
        let count = match recv.read(&mut chunk).await {
            Ok(Some(count)) => count,
            Ok(None) => return,
            Err(_) => {
                let _ = deliver(&inbox, Err(Failure::PathLost)).await;
                return;
            }
        };
        decoder.set_maximum(maximum.load(Ordering::SeqCst));
        decoder.push(&chunk[..count]);
        loop {
            match decoder.next_frame() {
                Ok(Some(message)) => {
                    if !deliver(&inbox, Ok(message)).await {
                        return;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    let _ = deliver(&inbox, Err(Failure::Protocol)).await;
                    return;
                }
            }
        }
    }
}

async fn deliver(inbox: &SyncSender<Received>, mut item: Received) -> bool {
    loop {
        match inbox.try_send(item) {
            Ok(()) => return true,
            Err(mpsc::TrySendError::Disconnected(_)) => return false,
            Err(mpsc::TrySendError::Full(back)) => {
                item = back;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
}

impl Channel {
    /// Writes one frame, waiting at most `limit` for the peer's flow control. Past it, a caller's own wait whose frame had not
    /// started leaves the stream as it was; otherwise part of a frame may have gone, so nothing more can follow it.
    fn write(&self, message: &[u8], limit: Duration, callers_wait: bool) -> Result<(), Failure> {
        let framed = frame::encode(message, self.max_send.load(Ordering::SeqCst))
            .map_err(|_| Failure::Protocol)?;
        let mut guard = self.send.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(stream) = guard.as_mut() else {
            return Err(Failure::Cancelled);
        };
        let mut written = 0;
        let writing = async {
            while written < framed.len() {
                written += stream
                    .write(&framed[written..])
                    .await
                    .map_err(|_| Failure::PathLost)?;
            }
            Ok(())
        };
        match self.handle.block_on(bounded(limit, writing)) {
            Ok(result) => result,
            Err(_) if callers_wait && written == 0 => Err(Failure::Timeout),
            // A peer's flow control can hold a send for ever: past the limit it has stopped reading.
            Err(_) => {
                *guard = None;
                Err(Failure::NoProgress)
            }
        }
    }
}

impl channel::Channel for Channel {
    fn send(&self, message: &[u8]) -> Result<(), Failure> {
        self.write(message, self.send_limit, false)
    }

    /// Waits up to `timeout` instead of `Limits::send`. Past it, [`Failure::Timeout`] if nothing of the message went, and the
    /// channel goes on; [`Failure::NoProgress`] if part of it went, and the channel's stream ends. `None` is [`send`](crate::Channel::send).
    fn send_timeout(&self, message: &[u8], timeout: Option<Duration>) -> Result<(), Failure> {
        match timeout {
            Some(limit) => self.write(message, limit, true),
            None => self.send(message),
        }
    }

    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
        self.inbox.receive(timeout)
    }

    fn set_max_message(&self, bytes: usize) {
        self.set_max_receive(bytes);
        self.set_max_send(bytes);
    }

    fn set_max_receive(&self, bytes: usize) {
        self.max_message.store(bytes, Ordering::SeqCst);
    }

    fn set_max_send(&self, bytes: usize) {
        self.max_send.store(bytes, Ordering::SeqCst);
    }

    fn datagrams(&self) -> Option<&dyn Datagrams> {
        Some(self.datagrams.get_or_init(|| {
            QuicDatagrams::start(&self.connection, self.pending_datagrams, &self.handle)
        }))
    }

    fn peer_certificates(&self) -> Option<&[Vec<u8>]> {
        self.peer_certificates.as_deref()
    }

    fn close(&self) {
        let stream = self
            .send
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(mut stream) = stream {
            let _ = self
                .handle
                .block_on(async { within(Duration::from_secs(2), stream.finish()).await });
        }
        self.reader.abort();
        if let Some(datagrams) = self.datagrams.get() {
            datagrams.reader.abort();
        }
        self.connection.close(VarInt::from_u32(0), b"");
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        channel::Channel::close(self);
    }
}

/// Dials WebTransport endpoints.
pub struct Dialer {
    tls: Tls,
    limits: Limits,
    runtime: Arc<Runtime>,
}

enum Tls {
    Pinned(Vec<Sha256Digest>),
    Custom(Arc<ClientConfig>),
}

impl fmt::Debug for Dialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dialer")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Dialer {
    /// A dialer accepting exactly the certificates with these hashes, as a browser's
    /// `serverCertificateHashes` does.
    ///
    /// # Errors
    ///
    /// [`Failure::Unsupported`] when its runtime could not start.
    pub fn pinned(pins: &[CertificatePin]) -> Result<Self, Failure> {
        Ok(Self {
            tls: Tls::Pinned(
                pins.iter()
                    .map(|pin| Sha256Digest::new(*pin.as_bytes()))
                    .collect(),
            ),
            limits: Limits::default(),
            runtime: runtime()?,
        })
    }

    /// A dialer trusting what this TLS configuration trusts. Its ALPN is set to WebTransport's.
    ///
    /// # Errors
    ///
    /// [`Failure::Unsupported`] when its runtime could not start.
    pub fn with_tls(tls: Arc<ClientConfig>) -> Result<Self, Failure> {
        Ok(Self {
            tls: Tls::Custom(tls),
            limits: Limits::default(),
            runtime: runtime()?,
        })
    }

    /// The bounds of channels this dialer opens.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// A client endpoint, which sends a name's session to `address` when given one.
    fn endpoint(&self, address: Option<SocketAddr>) -> Result<Endpoint<Client>, Failure> {
        let builder = wtransport::ClientConfig::builder().with_bind_default();
        let mut config = match &self.tls {
            Tls::Pinned(pins) => builder.with_server_certificate_hashes(pins.clone()).build(),
            Tls::Custom(tls) => {
                let mut tls = ClientConfig::clone(tls);
                tls.alpn_protocols = alloc::vec![WEBTRANSPORT_ALPN.to_vec()];
                builder.with_custom_tls(tls).build()
            }
        };
        if let Some(address) = address {
            config.set_dns_resolver(Resolved(address));
        }
        let _inside = self.runtime.enter();
        Endpoint::client(config).map_err(|_| Failure::Unsupported)
    }
}

/// How long one address has before the next is tried beside it: RFC 8305's connection attempt delay.
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// Resolves any name to one address, so an attempt goes where it was sent while TLS still checks the name.
#[derive(Debug)]
struct Resolved(SocketAddr);

impl DnsResolver for Resolved {
    fn resolve(&self, _: &str) -> core::pin::Pin<Box<dyn DnsLookupFuture>> {
        let address = self.0;
        Box::pin(async move { Ok(Some(address)) })
    }
}

/// Every address a host name gives, the families taking turns from the resolver's first (RFC 8305 section 4). Empty for an
/// address literal, which needs no choosing.
fn addresses(endpoint: &Url) -> Result<Vec<SocketAddr>, Failure> {
    let Some(url::Host::Domain(name)) = endpoint.host() else {
        return Ok(Vec::new());
    };
    let port = endpoint.port().unwrap_or(443);
    let resolved: Vec<SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(&(name, port))
        .map_err(|_| Failure::PathLost)?
        .collect();
    if resolved.is_empty() {
        return Err(Failure::PathLost);
    }
    Ok(alternate(resolved))
}

/// The families taking turns, each in the resolver's order, starting with the family of its first.
fn alternate(resolved: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let first = resolved.first().is_some_and(SocketAddr::is_ipv6);
    let (preferred, other): (Vec<_>, Vec<_>) = resolved
        .into_iter()
        .partition(|address| address.is_ipv6() == first);
    let mut other = other.into_iter();
    let mut ordered = Vec::with_capacity(preferred.len() + other.len());
    for address in preferred {
        ordered.push(address);
        ordered.extend(other.next());
    }
    ordered.extend(other);
    ordered
}

/// One session and its stream, from `client` to `url`, after waiting `delay`.
async fn attempt(
    client: Endpoint<Client>,
    url: alloc::string::String,
    delay: Duration,
) -> Result<(Connection, SendStream, RecvStream), Failure> {
    tokio::time::sleep(delay).await;
    let connection = client
        .connect(url)
        .await
        .map_err(|e| connecting_failure(&e))?;
    let opening = connection
        .open_bi()
        .await
        .map_err(|e| connection_failure(&e))?;
    let (send, recv) = opening.await.map_err(|_| Failure::PathLost)?;
    Ok((connection, send, recv))
}

impl channel::Dialer for Dialer {
    type Connection = Channel;

    /// A host name that resolves to several addresses is tried at each in turn, a new one every 250 ms beside those still
    /// opening, and the first to open wins. A failure that is not about the path ends the dial at once, whichever address gave it.
    fn dial(&mut self, kind: Kind, endpoint: &Url, timeout: Duration) -> Result<Channel, Failure> {
        if kind != Kind::WebTransport {
            return Err(Failure::Unsupported);
        }
        let url = endpoint.to_string();
        let addresses = addresses(endpoint)?;
        let mut attempts = tokio::task::JoinSet::new();
        if addresses.is_empty() {
            attempts.spawn_on(
                attempt(self.endpoint(None)?, url.clone(), Duration::ZERO),
                self.runtime.handle(),
            );
        }
        let mut delay = Duration::ZERO;
        for address in addresses {
            let client = self.endpoint(Some(address))?;
            attempts.spawn_on(attempt(client, url.clone(), delay), self.runtime.handle());
            delay += ATTEMPT_DELAY;
        }
        let opened = self
            .runtime
            .block_on(bounded(timeout.min(self.limits.handshake), async {
                let mut lost = None;
                while let Some(finished) = attempts.join_next().await {
                    match finished.map_err(|_| Failure::Unsupported)? {
                        Ok(opened) => return Ok(opened),
                        Err(failure) if failure.is_path() => {
                            lost.get_or_insert(failure);
                        }
                        Err(failure) => return Err(failure),
                    }
                }
                Err(lost.unwrap_or(Failure::PathLost))
            }));
        // Those still opening are dropped with the set, which closes them.
        drop(attempts);
        let (connection, send, recv) = opened.map_err(|_| Failure::Timeout)??;
        Ok(Channel::start(
            connection,
            send,
            recv,
            self.limits,
            Arc::clone(&self.runtime),
            #[cfg(feature = "webrtc")]
            None,
        ))
    }
}

/// Builds one connection's TLS configuration from its source and the local address it reached.
type TlsFor = Arc<dyn Fn(SocketAddr, SocketAddr) -> Arc<ServerConfig> + Send + Sync>;

/// The QUIC endpoint behind a listener, on quinn itself so each connection can have a TLS configuration of its own, and the
/// configuration a connection otherwise gets.
fn server_endpoint(
    runtime: &Runtime,
    socket: std::net::UdpSocket,
    config: &wtransport::ServerConfig,
) -> io::Result<(quinn::Endpoint, Arc<quinn::ServerConfig>)> {
    let quic = Arc::new(config.quic_config().clone());
    let _inside = runtime.enter();
    let endpoint = quinn::Endpoint::new(
        config.quic_endpoint_config().clone(),
        Some(quinn::ServerConfig::clone(&quic)),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    Ok((endpoint, quic))
}

/// Accepts WebTransport sessions, each carrying one channel on the first stream a client opens.
pub struct Listener {
    endpoint: quinn::Endpoint,
    quic: Arc<quinn::ServerConfig>,
    tls_for: Option<TlsFor>,
    address: SocketAddr,
    limits: Limits,
    origins: Vec<alloc::string::String>,
    admission: Option<Admission>,
    runtime: Arc<Runtime>,
    #[cfg(feature = "webrtc")]
    port: Option<Port>,
}

impl fmt::Debug for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Listener")
            .field("address", &self.address)
            .field("limits", &self.limits)
            .field("origins", &self.origins)
            .finish_non_exhaustive()
    }
}

impl Listener {
    /// Binds a UDP `address`. TLS is required: WebTransport has no plain form. Its ALPN is set to
    /// WebTransport's. A browser pinning this server by hash needs a certificate valid for at most
    /// 14 days, signed with ECDSA P-256.
    ///
    /// # Errors
    ///
    /// Why it could not bind.
    pub fn bind(address: SocketAddr, tls: Arc<ServerConfig>) -> Result<Self, Failure> {
        let runtime = runtime()?;
        let mut tls = ServerConfig::clone(&tls);
        tls.alpn_protocols = alloc::vec![WEBTRANSPORT_ALPN.to_vec()];
        let config = wtransport::ServerConfig::builder()
            .with_bind_address(address)
            .with_custom_tls(tls)
            .build();
        let (endpoint, quic) = std::net::UdpSocket::bind(address)
            .and_then(|socket| server_endpoint(&runtime, socket, &config))
            .map_err(|error| match error.kind() {
                io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied => Failure::Permission,
                _ => Failure::Unsupported,
            })?;
        let address = endpoint.local_addr().map_err(|_| Failure::Unsupported)?;
        Ok(Self {
            endpoint,
            quic,
            tls_for: None,
            address,
            limits: Limits::default(),
            origins: Vec::new(),
            admission: None,
            runtime,
            #[cfg(feature = "webrtc")]
            port: None,
        })
    }

    /// Listens on a [`Port`], which takes one such listener in its life, so data channels can share the number. `wtransport` runs on a loopback
    /// socket behind the port's relay, unmodified but for not offering to grease QUIC's fixed bit: RFC 9443 forbids that on a shared
    /// port, since a greased packet can read as DTLS. Admission still judges the real source.
    ///
    /// # Errors
    ///
    /// [`Failure::Permission`] when the port already has its listener; otherwise why it could not start.
    #[cfg(feature = "webrtc")]
    pub fn on_port(port: &Port, tls: Arc<ServerConfig>) -> Result<Self, Failure> {
        if !port.take_quic() {
            return Err(Failure::Permission);
        }
        let runtime = runtime()?;
        let mut tls = ServerConfig::clone(&tls);
        tls.alpn_protocols = alloc::vec![WEBTRANSPORT_ALPN.to_vec()];
        let mut config = wtransport::ServerConfig::builder()
            .with_bind_address(SocketAddr::from((core::net::Ipv4Addr::LOCALHOST, 0)))
            .with_custom_tls(tls)
            .build();
        config.quic_endpoint_config_mut().grease_quic_bit(false);
        // An address token is bound to an IP address, and every source here has 127.0.0.1: one would let anyone skip validation.
        let mut tokens = wtransport::quinn::ValidationTokenConfig::default();
        tokens
            .sent(0)
            .log(Arc::new(wtransport::quinn::NoneTokenLog));
        config.quic_config_mut().validation_token_config(tokens);
        let (endpoint, quic) = std::net::UdpSocket::bind((core::net::Ipv4Addr::LOCALHOST, 0))
            .and_then(|socket| server_endpoint(&runtime, socket, &config))
            .map_err(|_| Failure::Unsupported)?;
        port.relay_to(endpoint.local_addr().map_err(|_| Failure::Unsupported)?);
        Ok(Self {
            endpoint,
            quic,
            tls_for: None,
            address: port.local_addr(),
            limits: Limits::default(),
            origins: Vec::new(),
            admission: None,
            runtime,
            port: Some(port.clone()),
        })
    }

    /// Where a handshake comes from. On a port the source is the one its relay stands for, and an address no relay holds reached
    /// the loopback socket some other way, so nothing can be said for it.
    fn source(&self, seen: SocketAddr) -> Option<SocketAddr> {
        #[cfg(feature = "webrtc")]
        if let Some(port) = &self.port {
            return port.source_of(seen);
        }
        Some(seen)
    }

    /// The address a connection reached: on a wildcard bind, the one the client sent to, as the system reports it. On a port it is
    /// the port's own.
    fn local_of(&self, incoming: &Incoming) -> SocketAddr {
        #[cfg(feature = "webrtc")]
        if self.port.is_some() {
            return self.address;
        }
        incoming
            .local_ip()
            .map_or(self.address, |ip| SocketAddr::new(ip, self.address.port()))
    }

    /// Whether a source may start a handshake.
    fn admits(&self, source: Option<SocketAddr>) -> bool {
        let Some(admit) = &self.admission else {
            return true;
        };
        source.is_some_and(|source| admit(source))
    }

    /// The bounds of channels this listener accepts.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
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

    /// Builds each connection's TLS configuration before its handshake from the client's source and the local address it reached
    /// (on a wildcard bind, the one it sent to), so a client certificate verifier can judge a client by both. The handshake runs on
    /// the driver's own threads, where nothing the caller set up around [`Pending::handshake`] is in scope. Its ALPN is set to
    /// WebTransport's. Without this, every connection gets the configuration the listener was bound with.
    #[must_use]
    pub fn with_tls_per_connection(
        mut self,
        tls: impl Fn(SocketAddr, SocketAddr) -> Arc<ServerConfig> + Send + Sync + 'static,
    ) -> Self {
        self.tls_for = Some(Arc::new(tls));
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
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// Waits for one session and its first stream, within the handshake limit once a session arrives.
    ///
    /// # Errors
    ///
    /// [`Failure::Timeout`] when no session arrived within `timeout` or a handshake took too long;
    /// [`Failure::Permission`] for a refused origin; otherwise why the session failed.
    pub fn accept(&self, timeout: Option<Duration>) -> Result<Channel, Failure> {
        self.next(timeout)?.handshake()
    }

    /// Waits for one session from a validated source and returns it before its handshake, so a server can run handshakes on
    /// threads of its own. UDP sources are forgeable, so a source is sent to retry first, and only then judged by admission.
    ///
    /// # Errors
    ///
    /// [`Failure::Timeout`] when none arrived within `timeout`.
    pub fn next(&self, timeout: Option<Duration>) -> Result<Pending, Failure> {
        let deadline = timeout.map(|limit| std::time::Instant::now() + limit);
        loop {
            let incoming = match deadline {
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(std::time::Instant::now());
                    self.runtime
                        .block_on(bounded(left, self.endpoint.accept()))
                        .map_err(|_| Failure::Timeout)?
                }
                None => self.runtime.block_on(self.endpoint.accept()),
            }
            // The listener holds its endpoint open, so it ends only with the runtime.
            .ok_or(Failure::PathLost)?;
            if !incoming.remote_address_validated() {
                // Only a source already validated cannot be sent to retry, and this one was not.
                let _ = incoming.retry();
                continue;
            }
            let seen = incoming.remote_address();
            let source = self.source(seen);
            if !self.admits(source) {
                incoming.refuse();
                continue;
            }
            let local = self.local_of(&incoming);
            return Ok(Pending {
                incoming,
                peer: source.unwrap_or(seen),
                local,
                tls: self
                    .tls_for
                    .as_ref()
                    .map(|tls_for| (Arc::clone(tls_for), Arc::clone(&self.quic))),
                cancel: Arc::default(),
                stop: Arc::default(),
                limits: self.limits,
                origins: self.origins.clone(),
                runtime: Arc::clone(&self.runtime),
                #[cfg(feature = "webrtc")]
                port: self.port.clone(),
            });
        }
    }
}

/// A session that has not done its handshake.
pub struct Pending {
    incoming: Incoming,
    peer: SocketAddr,
    local: SocketAddr,
    tls: Option<(TlsFor, Arc<quinn::ServerConfig>)>,
    cancel: Arc<Abandon>,
    stop: Arc<Notify>,
    limits: Limits,
    origins: Vec<alloc::string::String>,
    runtime: Arc<Runtime>,
    #[cfg(feature = "webrtc")]
    port: Option<Port>,
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending")
            .field("peer", &self.peer)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Pending {
    /// The source address [`Listener::next`] admitted: on a port, the client's, not its relay's.
    #[must_use]
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// The local address the client reached: on a wildcard bind, the one it sent to; on a port, the port's own.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// A handle that abandons this handshake from another thread, before or while [`handshake`](Self::handshake) runs: it then
    /// returns [`Failure::Cancelled`] and the session closes.
    #[must_use]
    pub fn canceller(&self) -> Cancel {
        let stop = Arc::clone(&self.stop);
        self.cancel.interrupt_with(|| {
            Some(Box::new(move || {
                // Kept for a wait that has not started yet.
                stop.notify_one();
            }))
        });
        self.cancel.handle()
    }

    /// Completes the session and takes its first stream, within the handshake limit in total.
    ///
    /// # Errors
    ///
    /// [`Failure::Timeout`] past the limit; [`Failure::Permission`] for a refused origin; [`Failure::Cancelled`] once its
    /// [`canceller`](Self::canceller) has stopped it; otherwise why it failed.
    pub fn handshake(self) -> Result<Channel, Failure> {
        let Self {
            incoming,
            peer,
            local,
            tls,
            cancel,
            stop,
            limits,
            origins,
            runtime,
            #[cfg(feature = "webrtc")]
            port,
        } = self;
        if cancel.cancelled() {
            return Err(Failure::Cancelled);
        }
        let _finishing = cancel.finishing();
        let config = match tls {
            Some((tls_for, base)) => {
                let mut tls = ServerConfig::clone(&tls_for(peer, local));
                tls.alpn_protocols = alloc::vec![WEBTRANSPORT_ALPN.to_vec()];
                let mut config = quinn::ServerConfig::clone(&base);
                config.crypto =
                    Arc::new(QuicServerConfig::try_from(tls).map_err(|_| Failure::Unsupported)?);
                Some(Arc::new(config))
            }
            None => None,
        };
        let opened = runtime.block_on(bounded(limits.handshake, async {
            let connecting = match config {
                Some(config) => incoming.accept_with(config),
                None => incoming.accept(),
            }
            .map_err(|e| connection_failure(&e.into()))?;
            let stopped = stop.notified();
            tokio::pin!(stopped);
            let request = tokio::select! {
                request = IncomingSessionFuture::with_quic_connecting(connecting) => {
                    request.map_err(|e| connection_failure(&e))?
                }
                () = &mut stopped => return Err(Failure::Cancelled),
            };
            if let Some(origin) = request.origin()
                && !origins.is_empty()
                && !origins.iter().any(|allowed| allowed == origin)
            {
                request.forbidden().await;
                return Err(Failure::Permission);
            }
            let connection = tokio::select! {
                connection = request.accept() => connection.map_err(|e| connection_failure(&e))?,
                () = &mut stopped => return Err(Failure::Cancelled),
            };
            let streams = tokio::select! {
                streams = connection.accept_bi() => streams,
                () = &mut stopped => {
                    connection.close(VarInt::from_u32(0), b"");
                    return Err(Failure::Cancelled);
                }
            };
            let (send, recv) = streams.map_err(|e| connection_failure(&e))?;
            Ok((connection, send, recv))
        }));
        let opened = opened
            .map_err(|_| Failure::Timeout)
            .and_then(|opened| opened);
        // A cancel that came before the end wins over what the wait made of it.
        if let Err(failure) = cancel.finish() {
            if let Ok((connection, ..)) = &opened {
                connection.close(VarInt::from_u32(0), b"");
            }
            return Err(failure);
        }
        let (connection, send, recv) = opened?;
        Ok(Channel::start(
            connection,
            send,
            recv,
            limits,
            runtime,
            #[cfg(feature = "webrtc")]
            port,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_certificate_alert_reads_as_one_and_no_other_alert_does() {
        for alert in [42_u64, 43, 44, 45, 46, 48, 49, 116] {
            assert_eq!(
                quic_failure(Some(0x100 + alert)),
                Failure::Certificate,
                "{alert}"
            );
        }
        for alert in [40_u64, 70, 80, 120] {
            assert_eq!(
                quic_failure(Some(0x100 + alert)),
                Failure::Unsupported,
                "{alert}"
            );
        }
        assert_eq!(quic_failure(Some(0xa)), Failure::Protocol);
        assert_eq!(quic_failure(None), Failure::Protocol);
    }

    #[test]
    fn the_families_take_turns_from_the_resolvers_first() {
        let [a, b, c, x, y]: [SocketAddr; 5] = [
            "[::1]:1",
            "[::2]:1",
            "[::3]:1",
            "127.0.0.1:1",
            "127.0.0.2:1",
        ]
        .map(|text| text.parse().unwrap());
        assert_eq!(alternate(alloc::vec![a, b, c, x, y]), [a, x, b, y, c]);
        assert_eq!(alternate(alloc::vec![x, a, b, c, y]), [x, a, y, b, c]);
        assert_eq!(alternate(alloc::vec![x, y]), [x, y]);
        assert!(alternate(Vec::new()).is_empty());
    }

    #[test]
    fn the_code_is_read_from_the_text() {
        assert_eq!(quic_code("no application protocol (code: 376)"), Some(376));
        assert_eq!(quic_code("x (code: 0x178)"), Some(0x178));
        assert_eq!(quic_code("no code here"), None);
    }
}
