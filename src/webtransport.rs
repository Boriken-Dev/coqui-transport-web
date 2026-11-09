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
use std::sync::mpsc::{self, Sender, SyncSender};
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

use coqui_transport::{Capabilities, Carrier, Datagrams, Delivery};

use crate::endpoint::CertificatePin;
use crate::fallback::Kind;
use crate::frame::{self, Decoder};
use crate::pump::{Abandon, Admission, Cancel, Inbox, Limits, Reading, Received, bind_failure};
#[cfg(feature = "webrtc")]
use crate::webrtc::Port;
use coqui_transport::{Failure, NonDefault};

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
    // The largest message read, by position, and how far ahead of the reader; the read loop applies both.
    reading: Arc<Reading>,
    // Wakes a read loop held at its read-ahead: a take, or a raised limit.
    room: Arc<Notify>,
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
            .field("max_message", &self.reading.current())
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
        // Holds no more than the read loop may read ahead, and the failure that ends it.
        let (to_reader, inbox) = mpsc::channel::<Received>();
        let handle = runtime.handle().clone();
        let reading = Arc::new(Reading::new(limits.max_message, limits.pending));
        let room = Arc::new(Notify::new());
        let reader = handle
            .spawn(read_loop(
                recv,
                Arc::clone(&reading),
                Arc::clone(&room),
                to_reader,
            ))
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
            reading,
            room,
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

/// Decodes the stream into messages, each under the bound for its position. Holding as many as the reader allows, it neither decodes
/// nor reads until `room` says the reader took one or the limit rose, so QUIC flow control tells the peer to slow down rather than
/// memory growing.
async fn read_loop(
    mut recv: RecvStream,
    reading: Arc<Reading>,
    room: Arc<Notify>,
    inbox: Sender<Received>,
) {
    let mut read = 0_u64;
    let mut decoder = Decoder::new(reading.at(read));
    let mut chunk = vec![0_u8; READ_CHUNK];
    loop {
        // A notification given before this waits is kept for it, so none is missed.
        while !reading.may_read(read) {
            room.notified().await;
        }
        decoder.set_maximum(reading.at(read));
        match decoder.next_frame() {
            Ok(Some(message)) => {
                read += 1;
                if inbox.send(Ok(message)).is_err() {
                    return;
                }
                continue;
            }
            Ok(None) => {}
            Err(_) => {
                let _ = inbox.send(Err(Failure::Protocol));
                return;
            }
        }
        let count = match recv.read(&mut chunk).await {
            Ok(Some(count)) => count,
            Ok(None) => return,
            Err(_) => {
                let _ = inbox.send(Err(Failure::PathLost));
                return;
            }
        };
        decoder.push(&chunk[..count]);
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

impl coqui_transport::Channel for Channel {
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
        let next = self.inbox.receive(timeout);
        if matches!(next, Ok(Some(_))) {
            self.reading.taken();
            self.room.notify_one();
        }
        next
    }

    fn set_max_message(&self, bytes: usize) {
        self.set_max_receive(bytes);
        self.set_max_send(bytes);
    }

    fn set_max_receive(&self, bytes: usize) {
        self.reading.set(bytes);
    }

    fn set_max_receive_after(&self, messages: usize, bytes: usize) -> Result<(), Failure> {
        self.reading.stage(messages, bytes);
        Ok(())
    }

    fn set_pending(&self, messages: usize) -> Result<(), Failure> {
        self.reading.set_ahead(messages);
        self.room.notify_one();
        Ok(())
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

    /// Datagrams are the connection's own, so they are reported whether or not [`datagrams`](coqui_transport::Channel::datagrams) was called.
    fn capabilities(&self) -> Capabilities {
        Capabilities::new()
            .carrier(Carrier::Stream)
            .limits(self.max_send.load(Ordering::SeqCst), self.reading.current())
            .datagrams(Some((
                Delivery::Unreliable,
                self.connection.max_datagram_size(),
            )))
    }

    fn is_closed(&self) -> bool {
        self.connection.quic_connection().close_reason().is_some()
            || self
                .send
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_none()
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
        coqui_transport::Channel::close(self);
    }
}

/// Dials WebTransport endpoints.
#[derive(Clone)]
pub struct Dialer {
    tls: Tls,
    limits: Limits,
    local: Option<SocketAddr>,
    runtime: Arc<Runtime>,
}

#[derive(Clone)]
enum Tls {
    Pinned(Vec<Sha256Digest>),
    Custom(Arc<ClientConfig>),
}

impl fmt::Debug for Dialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dialer")
            .field("limits", &self.limits)
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

/// Whom a [`DialerBuilder`] trusts.
#[derive(Clone)]
#[non_exhaustive]
pub enum ClientTrust {
    /// Exactly the certificates with these hashes, as a browser's `serverCertificateHashes` does.
    Pinned(Vec<CertificatePin>),
    /// What this TLS configuration trusts. Its ALPN is set to WebTransport's.
    Config(Arc<ClientConfig>),
}

impl fmt::Debug for ClientTrust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pinned(pins) => f.debug_tuple("Pinned").field(&pins.len()).finish(),
            Self::Config(_) => f.write_str("Config(..)"),
        }
    }
}

impl From<Arc<ClientConfig>> for ClientTrust {
    fn from(config: Arc<ClientConfig>) -> Self {
        Self::Config(config)
    }
}

impl From<Vec<CertificatePin>> for ClientTrust {
    fn from(pins: Vec<CertificatePin>) -> Self {
        Self::Pinned(pins)
    }
}

/// What a [`DialerBuilder`] takes whole through `settings`, in the form a file, a form or a peer fills.
///
/// The trust holds certificates and code, so the builder takes it as an argument. Every key is optional (an absent one is its
/// default) and an unknown key is refused. The type is a guatiao value (`from_value`, `to_value`, `schema`), and
/// `guatiao_serde::text` reads and writes its text. It is `#[non_exhaustive]`: start from [`Default`] and assign the fields.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, guatiao::ToValue, guatiao::FromValue, guatiao::Schema,
)]
#[map(deny_unknown_fields)]
#[non_exhaustive]
pub struct DialerSettings {
    /// The bounds of channels this dialer opens.
    #[map(default = DialerSettings::default().limits)]
    pub limits: Limits,
    /// Binds the dialer's UDP socket to this address rather than to what the system picks, so a listener sees the session come
    /// from there. Give port 0 for any free port: each address a host name resolves to is tried from a socket of its own. Only
    /// endpoint addresses of its family are tried; an address this host cannot bind, or an endpoint with none of its family,
    /// fails the dial with [`Failure::Unsupported`], or [`Failure::Permission`] when the address is taken or not allowed.
    pub local_addr: Option<SocketAddr>,
}

/// Builds a [`Dialer`]: [`Dialer::builder`], the settings, then [`build`](Self::build).
#[derive(Clone, Debug)]
#[must_use]
pub struct DialerBuilder {
    trust: ClientTrust,
    settings: DialerSettings,
}

impl DialerBuilder {
    /// The bounds of channels this dialer opens; see [`DialerSettings::limits`].
    pub const fn limits(mut self, limits: Limits) -> Self {
        self.settings.limits = limits;
        self
    }

    /// The local address the UDP socket binds to; see [`DialerSettings::local_addr`].
    pub const fn local_addr(mut self, address: SocketAddr) -> Self {
        self.settings.local_addr = Some(address);
        self
    }

    /// Every setting from `settings`. Replaces what the setters set before, and is replaced by what they set after it. The
    /// trust is an argument, not a setting, and stays.
    pub fn settings(mut self, settings: DialerSettings) -> Self {
        self.settings = settings;
        self
    }

    /// The dialer.
    ///
    /// # Errors
    ///
    /// [`Failure::Unsupported`] when its runtime could not start.
    pub fn build(self) -> Result<Dialer, Failure> {
        let tls = match self.trust {
            ClientTrust::Pinned(pins) => Tls::Pinned(
                pins.iter()
                    .map(|pin| Sha256Digest::new(*pin.as_bytes()))
                    .collect(),
            ),
            ClientTrust::Config(config) => Tls::Custom(config),
        };
        Ok(Dialer {
            tls,
            limits: self.settings.limits,
            local: self.settings.local_addr,
            runtime: runtime()?,
        })
    }
}

impl Dialer {
    /// A builder for a dialer that trusts `trust`, with every setting at its default.
    pub fn builder(trust: impl Into<ClientTrust>) -> DialerBuilder {
        DialerBuilder {
            trust: trust.into(),
            settings: DialerSettings::default(),
        }
    }

    /// The settings this dialer was built with.
    #[must_use]
    pub fn settings(&self) -> DialerSettings {
        DialerSettings {
            limits: self.limits,
            local_addr: self.local,
        }
    }

    /// The settings of this dialer that differ from their default, named by key.
    #[must_use]
    pub fn non_defaults(&self) -> Vec<NonDefault> {
        NonDefault::of_settings(&self.settings())
    }

    /// A client endpoint, which sends a name's session to `address` when given one.
    fn endpoint(&self, address: Option<SocketAddr>) -> Result<Endpoint<Client>, Failure> {
        let builder = match self.local {
            Some(local) => wtransport::ClientConfig::builder()
                .with_bind_socket(std::net::UdpSocket::bind(local).map_err(|e| bind_failure(&e))?),
            None => wtransport::ClientConfig::builder().with_bind_default(),
        };
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

/// A [`Dialer`] and the one endpoint it opens, as a [`coqui_transport::Connector`].
///
/// A channel it returns is open and not yet trusted: prove the peer before delivering anything to the application.
#[derive(Clone, Debug)]
pub struct Connector {
    dialer: Dialer,
    endpoint: Url,
}

impl Connector {
    /// A connector that opens `endpoint` with `dialer`.
    #[must_use]
    pub const fn new(dialer: Dialer, endpoint: Url) -> Self {
        Self { dialer, endpoint }
    }
}

impl coqui_transport::Connector for Connector {
    type Connection = Channel;
    type Error = Failure;

    fn connect(&self, timeout: Duration) -> Result<Channel, Failure> {
        crate::Dialer::dial(
            &mut self.dialer.clone(),
            Kind::WebTransport,
            &self.endpoint,
            timeout,
        )
    }
}

impl crate::Dialer for Dialer {
    type Connection = Channel;

    /// A host name that resolves to several addresses is tried at each in turn, a new one every 250 ms beside those still
    /// opening, and the first to open wins. A failure that is not about the path ends the dial at once, whichever address gave it.
    fn dial(&mut self, kind: Kind, endpoint: &Url, timeout: Duration) -> Result<Channel, Failure> {
        if kind != Kind::WebTransport {
            return Err(Failure::Unsupported);
        }
        let url = endpoint.to_string();
        let mut addresses = addresses(endpoint)?;
        if let Some(local) = self.local {
            // A literal gives no addresses to choose from, so its own family is what must match.
            let reachable = match endpoint.host() {
                Some(url::Host::Ipv4(_)) => local.is_ipv4(),
                Some(url::Host::Ipv6(_)) => local.is_ipv6(),
                _ => {
                    addresses.retain(|address| address.is_ipv4() == local.is_ipv4());
                    !addresses.is_empty()
                }
            };
            if !reachable {
                return Err(Failure::Unsupported);
            }
        }
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

/// Waits without a limit; [`Listener::accept`] takes one. A failed handshake fails that call only: the listener goes on.
impl coqui_transport::Listener for Listener {
    type Connection = Channel;
    type Error = Failure;

    fn accept(&self) -> Result<Channel, Failure> {
        Self::accept(self, None)
    }
}

/// Where a [`ListenerBuilder`] listens.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Binding {
    /// A UDP address of its own. TLS is required: WebTransport has no plain form.
    Address(SocketAddr),
    /// A [`Port`], which takes one such listener in its life, so data channels can share the number. `wtransport` runs on a
    /// loopback socket behind the port's relay, unmodified but for not offering to grease QUIC's fixed bit: RFC 9443 forbids
    /// that on a shared port, since a greased packet can read as DTLS. Admission still judges the real source. Building is
    /// [`Failure::Permission`] when the port already has its listener.
    #[cfg(feature = "webrtc")]
    Port(Port),
}

impl From<SocketAddr> for Binding {
    fn from(address: SocketAddr) -> Self {
        Self::Address(address)
    }
}

#[cfg(feature = "webrtc")]
impl From<Port> for Binding {
    fn from(port: Port) -> Self {
        Self::Port(port)
    }
}

/// What a [`ListenerBuilder`] takes whole through `settings`, in the form a file, a form or a peer fills.
///
/// The binding, the TLS configuration and the admission function hold code, so the builder takes them as arguments. Every key is
/// optional (an absent one is its default) and an unknown key is refused. The type is a guatiao value (`from_value`,
/// `to_value`, `schema`), and `guatiao_serde::text` reads and writes its text. It is `#[non_exhaustive]`: start from
/// [`Default`] and assign the fields.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, guatiao::ToValue, guatiao::FromValue, guatiao::Schema,
)]
#[map(deny_unknown_fields)]
#[non_exhaustive]
pub struct ListenerSettings {
    /// The bounds of channels this listener accepts.
    #[map(default = ListenerSettings::default().limits)]
    pub limits: Limits,
    /// Refuses a browser whose `Origin` is not listed. A request with no `Origin` is not a browser and is unaffected. An empty
    /// list checks nothing; identity still has to be proven afterwards.
    #[map(default = ListenerSettings::default().origins)]
    pub origins: Vec<alloc::string::String>,
}

/// Builds a [`Listener`]: [`Listener::builder`], the settings, then [`build`](Self::build). TLS is required: WebTransport has
/// no plain form. Its ALPN is set to WebTransport's. A browser pinning this server by hash needs a certificate valid for at most
/// 14 days, signed with ECDSA P-256.
#[must_use]
pub struct ListenerBuilder {
    binding: Binding,
    tls: Arc<ServerConfig>,
    settings: ListenerSettings,
    tls_for: Option<TlsFor>,
    admission: Option<Admission>,
}

impl fmt::Debug for ListenerBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerBuilder")
            .field("binding", &self.binding)
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl ListenerBuilder {
    /// The bounds of channels this listener accepts.
    pub const fn limits(mut self, limits: Limits) -> Self {
        self.settings.limits = limits;
        self
    }

    /// Refuses a browser whose `Origin` is not listed; see [`ListenerSettings::origins`]. Replaces the list set before.
    pub fn origins(mut self, origins: impl IntoIterator<Item = alloc::string::String>) -> Self {
        self.settings.origins = origins.into_iter().collect();
        self
    }

    /// Builds each connection's TLS configuration before its handshake from the client's source and the local address it reached
    /// (on a wildcard bind, the one it sent to), so a client certificate verifier can judge a client by both. The handshake runs
    /// on the driver's own threads, where nothing the caller set up around [`Pending::handshake`] is in scope. Its ALPN is set to
    /// WebTransport's. Without this, every connection gets the configuration the listener was built with.
    pub fn tls_per_connection(
        mut self,
        tls: impl Fn(SocketAddr, SocketAddr) -> Arc<ServerConfig> + Send + Sync + 'static,
    ) -> Self {
        self.tls_for = Some(Arc::new(tls));
        self
    }

    /// Refuses a source address before any handshake, so a denied peer costs nothing. Decided on each connection.
    pub fn admission(mut self, admit: impl Fn(SocketAddr) -> bool + Send + Sync + 'static) -> Self {
        self.admission = Some(Arc::new(admit));
        self
    }

    /// Every setting from `settings`. Replaces what the setters set before, and is replaced by what they set after it. The
    /// binding, the TLS configuration and the functions are arguments, not settings, and stay.
    pub fn settings(mut self, settings: ListenerSettings) -> Self {
        self.settings = settings;
        self
    }

    /// Binds the listener.
    ///
    /// # Errors
    ///
    /// Why it could not bind, or start; [`Failure::Permission`] when a [`Binding::Port`] already has its listener.
    pub fn build(self) -> Result<Listener, Failure> {
        let mut listener = match self.binding {
            Binding::Address(address) => Listener::bind(address, self.tls)?,
            #[cfg(feature = "webrtc")]
            Binding::Port(port) => Listener::on_port(&port, self.tls)?,
        };
        listener.limits = self.settings.limits;
        listener.origins = self.settings.origins;
        listener.tls_for = self.tls_for;
        listener.admission = self.admission;
        Ok(listener)
    }
}

impl Listener {
    /// A builder for a listener on `binding` serving `tls`, with every setting at its default.
    pub fn builder(binding: impl Into<Binding>, tls: Arc<ServerConfig>) -> ListenerBuilder {
        ListenerBuilder {
            binding: binding.into(),
            tls,
            settings: ListenerSettings::default(),
            tls_for: None,
            admission: None,
        }
    }

    /// The settings this listener was built with.
    #[must_use]
    pub fn settings(&self) -> ListenerSettings {
        ListenerSettings {
            limits: self.limits,
            origins: self.origins.clone(),
        }
    }

    /// The settings of this listener that differ from their default, named by key.
    #[must_use]
    pub fn non_defaults(&self) -> Vec<NonDefault> {
        NonDefault::of_settings(&self.settings())
    }

    fn bind(address: SocketAddr, tls: Arc<ServerConfig>) -> Result<Self, Failure> {
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

    #[cfg(feature = "webrtc")]
    fn on_port(port: &Port, tls: Arc<ServerConfig>) -> Result<Self, Failure> {
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
