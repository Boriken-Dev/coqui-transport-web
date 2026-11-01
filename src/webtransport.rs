//! A WebTransport dialer and listener: one bidirectional stream, framed by [`frame`].
//!
//! QUIC needs an async runtime, so each dialer and listener runs a small one inside. Nothing async
//! crosses this API and the caller needs no runtime of its own. Its calls block, so a caller already
//! inside an async runtime makes them through that runtime's blocking pool.

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::net::SocketAddr;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::io;
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Mutex, PoisonError};

use rustls::{ClientConfig, ServerConfig};
use tokio::runtime::{Builder, Handle, Runtime};
use tokio::task::AbortHandle;
use tokio::time::timeout as within;
use url::Url;
use wtransport::endpoint::IncomingSession;
use wtransport::endpoint::endpoint_side::{Client, Server};
use wtransport::error::{ConnectingError, ConnectionError};
use wtransport::tls::{Sha256Digest, WEBTRANSPORT_ALPN};
use wtransport::{Connection, Endpoint, RecvStream, SendStream, VarInt};

use crate::channel::{self, Kind};
use crate::endpoints::CertificatePin;
use crate::failure::Failure;
use crate::frame::{self, Decoder};
use crate::pump::{Admission, Inbox, Limits, Received};

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
        ConnectingError::SessionRejected => Failure::Permission,
        ConnectingError::ConnectionError(error) => connection_failure(error),
        ConnectingError::InvalidUrl(_) | ConnectingError::InvalidServerName(_) => Failure::Protocol,
        _ => Failure::Unsupported,
    }
}

fn connection_failure(error: &ConnectionError) -> Failure {
    match error {
        ConnectionError::TimedOut => Failure::Timeout,
        ConnectionError::QuicProto(_) => Failure::Certificate,
        ConnectionError::LocallyClosed => Failure::Cancelled,
        _ => Failure::PathLost,
    }
}

/// A WebTransport channel over one bidirectional stream.
pub struct Channel {
    inbox: Inbox,
    connection: Connection,
    send: Mutex<Option<SendStream>>,
    reader: AbortHandle,
    handle: Handle,
    max_message: Arc<AtomicUsize>,
    send_limit: Duration,
    // Keeps the driver's runtime alive as long as a channel needs it.
    _runtime: Arc<Runtime>,
}

impl fmt::Debug for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Channel")
            .field("remote", &self.connection.remote_address())
            .field("max_message", &self.max_message.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Channel {
    fn start(
        connection: Connection,
        send: SendStream,
        recv: RecvStream,
        limits: Limits,
        runtime: Arc<Runtime>,
    ) -> Self {
        let (to_reader, inbox) = mpsc::sync_channel::<Received>(limits.pending.max(1));
        let handle = runtime.handle().clone();
        let max_message = Arc::new(AtomicUsize::new(limits.max_message));
        let reader = handle
            .spawn(read_loop(recv, Arc::clone(&max_message), to_reader))
            .abort_handle();
        Self {
            inbox: Inbox::new(inbox),
            connection,
            send: Mutex::new(Some(send)),
            reader,
            handle,
            max_message,
            send_limit: limits.send,
            _runtime: runtime,
        }
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

impl channel::Channel for Channel {
    fn send(&self, message: &[u8]) -> Result<(), Failure> {
        let framed = frame::encode(message, self.max_message.load(Ordering::SeqCst))
            .map_err(|_| Failure::Protocol)?;
        let mut guard = self.send.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(stream) = guard.as_mut() else {
            return Err(Failure::Cancelled);
        };
        match self
            .handle
            .block_on(bounded(self.send_limit, stream.write_all(&framed)))
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(Failure::PathLost),
            // A peer's flow control can hold a send for ever: past the limit it has stopped reading. Part of a frame may
            // have gone, so nothing more can follow it on this stream.
            Err(_) => {
                *guard = None;
                Err(Failure::NoProgress)
            }
        }
    }

    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
        self.inbox.receive(timeout)
    }

    fn set_max_message(&self, bytes: usize) {
        self.max_message.store(bytes, Ordering::SeqCst);
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

    fn endpoint(&self) -> Result<Endpoint<Client>, Failure> {
        let builder = wtransport::ClientConfig::builder().with_bind_default();
        let config = match &self.tls {
            Tls::Pinned(pins) => builder.with_server_certificate_hashes(pins.clone()).build(),
            Tls::Custom(tls) => {
                let mut tls = ClientConfig::clone(tls);
                tls.alpn_protocols = alloc::vec![WEBTRANSPORT_ALPN.to_vec()];
                builder.with_custom_tls(tls).build()
            }
        };
        let _inside = self.runtime.enter();
        Endpoint::client(config).map_err(|_| Failure::Unsupported)
    }
}

impl channel::Dialer for Dialer {
    type Connection = Channel;

    fn dial(&mut self, kind: Kind, endpoint: &Url, timeout: Duration) -> Result<Channel, Failure> {
        if kind != Kind::WebTransport {
            return Err(Failure::Unsupported);
        }
        let client = self.endpoint()?;
        let url = endpoint.to_string();
        let opened = self
            .runtime
            .block_on(bounded(timeout.min(self.limits.handshake), async {
                let connection = client
                    .connect(url)
                    .await
                    .map_err(|e| connecting_failure(&e))?;
                let opening = connection
                    .open_bi()
                    .await
                    .map_err(|e| connection_failure(&e))?;
                let (send, recv) = opening.await.map_err(|_| Failure::PathLost)?;
                Ok::<_, Failure>((connection, send, recv))
            }));
        let (connection, send, recv) = opened.map_err(|_| Failure::Timeout)??;
        Ok(Channel::start(
            connection,
            send,
            recv,
            self.limits,
            Arc::clone(&self.runtime),
        ))
    }
}

/// Accepts WebTransport sessions, each carrying one channel on the first stream a client opens.
pub struct Listener {
    endpoint: Endpoint<Server>,
    address: SocketAddr,
    limits: Limits,
    origins: Vec<alloc::string::String>,
    admission: Option<Admission>,
    runtime: Arc<Runtime>,
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
        let endpoint = {
            let _inside = runtime.enter();
            Endpoint::server(config).map_err(|error: io::Error| match error.kind() {
                io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied => Failure::Permission,
                _ => Failure::Unsupported,
            })?
        };
        let address = endpoint.local_addr().map_err(|_| Failure::Unsupported)?;
        Ok(Self {
            endpoint,
            address,
            limits: Limits::default(),
            origins: Vec::new(),
            admission: None,
            runtime,
        })
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
            let incoming: IncomingSession = match deadline {
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(std::time::Instant::now());
                    self.runtime
                        .block_on(bounded(left, self.endpoint.accept()))
                        .map_err(|_| Failure::Timeout)?
                }
                None => self.runtime.block_on(self.endpoint.accept()),
            };
            if !incoming.remote_address_validated() {
                incoming.retry();
                continue;
            }
            if self
                .admission
                .as_ref()
                .is_some_and(|admit| !admit(incoming.remote_address()))
            {
                incoming.refuse();
                continue;
            }
            return Ok(Pending {
                incoming,
                limits: self.limits,
                origins: self.origins.clone(),
                runtime: Arc::clone(&self.runtime),
            });
        }
    }
}

/// A session that has not done its handshake.
pub struct Pending {
    incoming: IncomingSession,
    limits: Limits,
    origins: Vec<alloc::string::String>,
    runtime: Arc<Runtime>,
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Pending {
    /// Completes the session and takes its first stream, within the handshake limit in total.
    ///
    /// # Errors
    ///
    /// [`Failure::Timeout`] past the limit; [`Failure::Permission`] for a refused origin; otherwise why it failed.
    pub fn handshake(self) -> Result<Channel, Failure> {
        let Self {
            incoming,
            limits,
            origins,
            runtime,
        } = self;
        let opened = runtime.block_on(bounded(limits.handshake, async {
            let request = incoming.await.map_err(|e| connection_failure(&e))?;
            if let Some(origin) = request.origin()
                && !origins.is_empty()
                && !origins.iter().any(|allowed| allowed == origin)
            {
                request.forbidden().await;
                return Err(Failure::Permission);
            }
            let connection = request.accept().await.map_err(|e| connection_failure(&e))?;
            let (send, recv) = connection
                .accept_bi()
                .await
                .map_err(|e| connection_failure(&e))?;
            Ok((connection, send, recv))
        }));
        let (connection, send, recv) = opened.map_err(|_| Failure::Timeout)??;
        Ok(Channel::start(connection, send, recv, limits, runtime))
    }
}
