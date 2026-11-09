//! What a channel and a pending handshake tell about the peer, over real sockets on loopback. Each binds port 0.
#![cfg(all(feature = "websocket", feature = "webtransport"))]
#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use coqui_transport_web::{
    CertificatePin, Channel, Dialer, Failure, Kind, websocket, webtransport,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use url::Url;

const WAIT: Duration = Duration::from_secs(10);

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

struct Identity {
    certificate: CertificateDer<'static>,
    key: Vec<u8>,
}

impl Identity {
    fn new() -> Self {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        static MADE: AtomicUsize = AtomicUsize::new(0);
        let names = vec!["localhost".to_owned(), "127.0.0.1".to_owned()];
        let mut params = rcgen::CertificateParams::new(names).unwrap();
        // A subject of its own, so one identity's certificate never names another as its issuer.
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            format!("peer {}", MADE.fetch_add(1, Ordering::Relaxed)),
        );
        // What pinning by hash requires: at most 14 days.
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
        params.not_after = params.not_before + time::Duration::days(10);
        let certificate = params.self_signed(&key).unwrap();
        Self {
            certificate: certificate.der().clone(),
            key: key.serialize_der(),
        }
    }

    fn der(&self) -> Vec<Vec<u8>> {
        vec![self.certificate.to_vec()]
    }

    fn pin(&self) -> CertificatePin {
        let certificate =
            wtransport::tls::Certificate::from_der(self.certificate.to_vec()).unwrap();
        CertificatePin::from_bytes(*certificate.hash().as_ref())
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// What a server asks of a client.
#[derive(Clone, Copy, Debug)]
enum Ask {
    Nothing,
    Optional,
    Required,
}

fn server_tls(server: &Identity, client: &Identity, ask: Ask) -> Arc<rustls::ServerConfig> {
    let builder = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(client.certificate.clone()).unwrap();
    let verifier =
        rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider());
    let builder = match ask {
        Ask::Nothing => builder.with_no_client_auth(),
        Ask::Optional => {
            builder.with_client_cert_verifier(verifier.allow_unauthenticated().build().unwrap())
        }
        Ask::Required => builder.with_client_cert_verifier(verifier.build().unwrap()),
    };
    Arc::new(
        builder
            .with_single_cert(
                vec![server.certificate.clone()],
                PrivatePkcs8KeyDer::from(server.key.clone()).into(),
            )
            .unwrap(),
    )
}

fn client_tls(server: &Identity, client: Option<&Identity>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(server.certificate.clone()).unwrap();
    let builder = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    Arc::new(match client {
        None => builder.with_no_client_auth(),
        Some(client) => builder
            .with_client_auth_cert(
                vec![client.certificate.clone()],
                PrivatePkcs8KeyDer::from(client.key.clone()).into(),
            )
            .unwrap(),
    })
}

type Seen = Option<Vec<Vec<u8>>>;

fn seen(channel: &impl Channel) -> Seen {
    channel.peer_certificates().map(<[Vec<u8>]>::to_vec)
}

/// What the client and the server of one WebSocket saw of each other's certificates.
fn over_websocket(
    server: Option<Arc<rustls::ServerConfig>>,
    dialer: websocket::Dialer,
) -> (Seen, Seen) {
    let scheme = if server.is_some() { "wss" } else { "ws" };
    let listener = websocket::Listener::builder(
        loopback(),
        server.map_or(websocket::ServerTls::Plain, websocket::ServerTls::Config),
    )
    .build()
    .unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = thread::spawn(move || seen(&listener.accept(Some(WAIT)).unwrap()));
    let url = Url::parse(&format!("{scheme}://127.0.0.1:{port}/")).unwrap();
    let client = { dialer }.dial(Kind::WebSocket, &url, WAIT).unwrap();
    (seen(&client), accepted.join().unwrap())
}

/// What the client and the server of one WebTransport session saw of each other's certificates.
fn over_webtransport(
    server: Arc<rustls::ServerConfig>,
    mut dialer: webtransport::Dialer,
) -> (Seen, Seen) {
    let listener = webtransport::Listener::builder(loopback(), server)
        .build()
        .unwrap();
    let port = listener.local_addr().port();
    let accepted = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        (seen(&channel), channel)
    });
    let url = Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap();
    let client = dialer.dial(Kind::WebTransport, &url, WAIT).unwrap();
    // A server has no stream to accept until the client's carries something.
    client.send(b"open").unwrap();
    let (server_saw, _channel) = accepted.join().unwrap();
    (seen(&client), server_saw)
}

#[test]
fn each_end_of_a_tls_websocket_has_the_chain_the_other_presented() {
    let (server, client) = (Identity::new(), Identity::new());
    for (ask, presents, server_sees) in [
        (Ask::Nothing, true, None),
        (Ask::Optional, false, None),
        (Ask::Optional, true, Some(client.der())),
        (Ask::Required, true, Some(client.der())),
    ] {
        let dialer = websocket::Dialer::builder()
            .tls(client_tls(&server, presents.then_some(&client)))
            .build();
        let seen = over_websocket(Some(server_tls(&server, &client, ask)), dialer);
        assert_eq!(
            seen,
            (Some(server.der()), server_sees),
            "{ask:?} {presents}"
        );
    }
}

#[test]
fn a_plain_websocket_has_no_certificates() {
    assert_eq!(
        over_websocket(None, websocket::Dialer::builder().build()),
        (None, None)
    );
}

#[test]
fn each_end_of_a_webtransport_session_has_the_chain_the_other_presented() {
    let (server, client) = (Identity::new(), Identity::new());
    for (ask, presents, server_sees) in [
        (Ask::Nothing, true, None),
        (Ask::Optional, false, None),
        (Ask::Optional, true, Some(client.der())),
        (Ask::Required, true, Some(client.der())),
    ] {
        let dialer = webtransport::Dialer::builder(webtransport::ClientTrust::Config(client_tls(
            &server,
            presents.then_some(&client),
        )))
        .build()
        .unwrap();
        let seen = over_webtransport(server_tls(&server, &client, ask), dialer);
        assert_eq!(
            seen,
            (Some(server.der()), server_sees),
            "{ask:?} {presents}"
        );
    }
    // A pinned dialer has the chain its pin matched.
    let pinned =
        webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::from([server.pin()])))
            .build()
            .unwrap();
    let seen = over_webtransport(server_tls(&server, &client, Ask::Nothing), pinned);
    assert_eq!(seen, (Some(server.der()), None));
}

#[test]
fn a_boxed_channel_passes_its_certificates_on() {
    let (server, client) = (Identity::new(), Identity::new());
    let listener = websocket::Listener::builder(
        loopback(),
        websocket::ServerTls::Config(server_tls(&server, &client, Ask::Nothing)),
    )
    .build()
    .unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = thread::spawn(move || listener.accept(Some(WAIT)).map(|_| ()));
    let url = Url::parse(&format!("wss://127.0.0.1:{port}/")).unwrap();
    let boxed: Box<dyn Channel> = Box::new(
        websocket::Dialer::builder()
            .tls(client_tls(&server, None))
            .build()
            .dial(Kind::WebSocket, &url, WAIT)
            .unwrap(),
    );
    assert_eq!(seen(&boxed), Some(server.der()));
    accepted.join().unwrap().unwrap();
}

/// An admission that lets everyone in and remembers who it was asked about.
fn noting() -> (
    Arc<Mutex<Vec<SocketAddr>>>,
    impl Fn(SocketAddr) -> bool + Send + Sync + 'static,
) {
    let noted = Arc::new(Mutex::new(Vec::new()));
    let noting = Arc::clone(&noted);
    (noted, move |source| {
        noting.lock().unwrap().push(source);
        true
    })
}

#[test]
fn a_pending_websocket_names_the_source_it_admitted() {
    let (noted, admit) = noting();
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .admission(admit)
        .build()
        .unwrap();
    let tcp = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let pending = listener.next(Some(WAIT)).unwrap();
    assert_eq!(pending.peer_addr(), tcp.local_addr().unwrap());
    assert_eq!(*noted.lock().unwrap(), [pending.peer_addr()]);
}

#[test]
fn a_pending_webtransport_session_names_the_source_it_admitted() {
    let id = Identity::new();
    let (noted, admit) = noting();
    let listener = webtransport::Listener::builder(loopback(), server_tls(&id, &id, Ask::Nothing))
        .admission(admit)
        .build()
        .unwrap();
    let url = Url::parse(&format!(
        "https://127.0.0.1:{}/",
        listener.local_addr().port()
    ))
    .unwrap();
    let client = thread::spawn(move || {
        let _ =
            webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::from([id.pin()])))
                .build()
                .unwrap()
                .dial(Kind::WebTransport, &url, Duration::from_secs(3));
    });
    let pending = listener.next(Some(WAIT)).unwrap();
    assert_eq!(*noted.lock().unwrap(), [pending.peer_addr()]);
    assert!(pending.peer_addr().ip().is_loopback());
    assert_ne!(pending.peer_addr(), listener.local_addr());
    drop(pending);
    client.join().unwrap();
}

/// A loopback address other than the listener's, as a client resuming from a second source would have.
fn second_loopback() -> SocketAddr {
    "127.0.0.2:0".parse().unwrap()
}

/// An address on no host (RFC 5737), which no socket here can be bound to.
fn not_here() -> SocketAddr {
    "192.0.2.1:0".parse().unwrap()
}

#[test]
fn a_websocket_dialer_bound_to_a_local_address_is_admitted_from_it() {
    let (noted, admit) = noting();
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .admission(admit)
        .build()
        .unwrap();
    let url = Url::parse(&format!("ws://{}/", listener.local_addr().unwrap())).unwrap();
    let client = thread::spawn(move || {
        let near = websocket::Dialer::builder()
            .local_addr(second_loopback())
            .build()
            .dial(Kind::WebSocket, &url, WAIT)
            .unwrap();
        near.send(b"open").unwrap();
        near
    });
    let pending = listener.next(Some(WAIT)).unwrap();
    assert_eq!(pending.peer_addr().ip(), second_loopback().ip());
    assert_eq!(*noted.lock().unwrap(), [pending.peer_addr()]);
    let far = pending.handshake().unwrap();
    assert_eq!(far.receive(Some(WAIT)), Ok(Some(b"open".to_vec())));
    drop(client.join().unwrap());
}

#[test]
fn a_webtransport_dialer_bound_to_a_local_address_is_admitted_from_it() {
    let id = Identity::new();
    let (noted, admit) = noting();
    let listener = webtransport::Listener::builder(loopback(), server_tls(&id, &id, Ask::Nothing))
        .admission(admit)
        .build()
        .unwrap();
    let url = Url::parse(&format!(
        "https://127.0.0.1:{}/",
        listener.local_addr().port()
    ))
    .unwrap();
    let client = thread::spawn(move || {
        let near =
            webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::from([id.pin()])))
                .local_addr(second_loopback())
                .build()
                .unwrap()
                .dial(Kind::WebTransport, &url, WAIT)
                .unwrap();
        near.send(b"open").unwrap();
        near
    });
    let pending = listener.next(Some(WAIT)).unwrap();
    assert_eq!(pending.peer_addr().ip(), second_loopback().ip());
    assert_eq!(*noted.lock().unwrap(), [pending.peer_addr()]);
    let far = pending.handshake().unwrap();
    assert_eq!(far.receive(Some(WAIT)), Ok(Some(b"open".to_vec())));
    drop(client.join().unwrap());
}

/// A local address this host does not have, or of the other family from the endpoint, fails the dial before anything is sent.
#[test]
fn a_dialer_whose_local_address_cannot_reach_the_endpoint_says_so() {
    let id = Identity::new();
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .build()
        .unwrap();
    let url = Url::parse(&format!("ws://{}/", listener.local_addr().unwrap())).unwrap();
    for local in [not_here(), "[::1]:0".parse().unwrap()] {
        let dialed = websocket::Dialer::builder().local_addr(local).build().dial(
            Kind::WebSocket,
            &url,
            WAIT,
        );
        assert_eq!(dialed.err(), Some(Failure::Unsupported), "{local}");
    }
    assert_eq!(
        listener.next(Some(Duration::from_millis(200))).err(),
        Some(Failure::Timeout)
    );
    let quic = webtransport::Listener::builder(loopback(), server_tls(&id, &id, Ask::Nothing))
        .build()
        .unwrap();
    let url = Url::parse(&format!("https://127.0.0.1:{}/", quic.local_addr().port())).unwrap();
    for local in [not_here(), "[::1]:0".parse().unwrap()] {
        let dialed =
            webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::from([id.pin()])))
                .local_addr(local)
                .build()
                .unwrap()
                .dial(Kind::WebTransport, &url, Duration::from_secs(3));
        assert_eq!(dialed.err(), Some(Failure::Unsupported), "{local}");
    }
}

#[cfg(feature = "webrtc")]
#[test]
fn a_pending_session_on_a_port_names_the_client_and_not_its_relay() {
    use coqui_transport_web::webrtc::{Port, Settings};
    let id = Identity::new();
    let (noted, admit) = noting();
    let port = Port::bind(loopback(), Settings::default()).unwrap();
    let listener =
        webtransport::Listener::builder(port.clone(), server_tls(&id, &id, Ask::Nothing))
            .admission(admit)
            .build()
            .unwrap();
    let url = Url::parse(&format!("https://127.0.0.1:{}/", port.local_addr().port())).unwrap();
    let client = thread::spawn(move || {
        let _ =
            webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::from([id.pin()])))
                .build()
                .unwrap()
                .dial(Kind::WebTransport, &url, Duration::from_secs(3));
    });
    let pending = listener.next(Some(WAIT)).unwrap();
    assert_eq!(*noted.lock().unwrap(), [pending.peer_addr()]);
    drop(pending);
    client.join().unwrap();
}

/// A server refusing the client's certificate, or the lack of one, fails the dial as a certificate refusal, by the alerts a TLS
/// WebSocket reads as one.
#[test]
fn a_webtransport_client_refused_by_certificate_is_told_so() {
    let (server, trusted, stranger) = (Identity::new(), Identity::new(), Identity::new());
    for presented in [Some(&stranger), None] {
        let listener = webtransport::Listener::builder(
            loopback(),
            server_tls(&server, &trusted, Ask::Required),
        )
        .build()
        .unwrap();
        let url = Url::parse(&format!(
            "https://127.0.0.1:{}/",
            listener.local_addr().port()
        ))
        .unwrap();
        let accepting = thread::spawn(move || listener.accept(Some(WAIT)).err());
        let dialed = webtransport::Dialer::builder(webtransport::ClientTrust::Config(client_tls(
            &server, presented,
        )))
        .build()
        .unwrap()
        .dial(Kind::WebTransport, &url, WAIT);
        assert_eq!(
            dialed.err(),
            Some(Failure::Certificate),
            "presented: {}",
            presented.is_some()
        );
        assert!(accepting.join().unwrap().is_some());
    }
}

/// Nothing listening at the address is still a path failure, which permits a fallback, and never a certificate refusal. Which
/// one depends on whether the system reports the unreachable port or the handshake runs out of time.
#[test]
fn a_webtransport_dial_nothing_answers_is_a_path_failure() {
    let server = Identity::new();
    let port = std::net::UdpSocket::bind(loopback())
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let url = Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap();
    let dialed =
        webtransport::Dialer::builder(webtransport::ClientTrust::Config(client_tls(&server, None)))
            .build()
            .unwrap()
            .dial(Kind::WebTransport, &url, Duration::from_secs(2));
    let failure = dialed.err();
    assert!(failure.is_some_and(Failure::is_path), "{failure:?}");
}

/// Each connection's source and the local address it reached, as a listener's TLS hook was given them.
type Addressed = Arc<Mutex<Vec<(SocketAddr, SocketAddr)>>>;

/// A listener on `address` that notes what its TLS hook is given and answers with `server`'s configuration.
fn noting_tls(address: SocketAddr, server: &Identity) -> (webtransport::Listener, Addressed) {
    let tls = server_tls(server, server, Ask::Nothing);
    let noted = Addressed::default();
    let noting = Arc::clone(&noted);
    let listener = webtransport::Listener::builder(
        address,
        webtransport::ServerTls::per_connection(move |source, local| {
            noting.lock().unwrap().push((source, local));
            Arc::clone(&tls)
        }),
    )
    .build()
    .unwrap();
    (listener, noted)
}

#[test]
fn a_wildcard_webtransport_listener_builds_tls_from_the_source_and_the_address_reached() {
    let server = Identity::new();
    let (listener, noted) = noting_tls("0.0.0.0:0".parse().unwrap(), &server);
    let port = listener.local_addr().port();
    let accepted = thread::spawn(move || {
        let pending = listener.next(Some(WAIT)).unwrap();
        let addresses = (pending.peer_addr(), pending.local_addr());
        (addresses, pending.handshake().unwrap())
    });
    let url = Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap();
    let client =
        webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::from([server.pin()])))
            .build()
            .unwrap()
            .dial(Kind::WebTransport, &url, WAIT)
            .unwrap();
    client.send(b"open").unwrap();
    let ((source, local), _channel) = accepted.join().unwrap();
    assert_eq!(local, SocketAddr::from(([127, 0, 0, 1], port)));
    assert!(
        source.ip().is_loopback() && source.port() != port,
        "{source}"
    );
    assert_eq!(*noted.lock().unwrap(), [(source, local)]);
}

/// Opens a session to `port` on 127.0.0.1 from a socket bound to `from`, and sends one message on its stream.
fn session_from(from: [u8; 4], port: u16, server: &Identity) {
    let hash = wtransport::tls::Certificate::from_der(server.certificate.to_vec())
        .unwrap()
        .hash();
    let config = wtransport::ClientConfig::builder()
        .with_bind_address(SocketAddr::from((from, 0)))
        .with_server_certificate_hashes([hash])
        .build();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let client = wtransport::Endpoint::client(config).unwrap();
        let session = client
            .connect(format!("https://127.0.0.1:{port}/"))
            .await
            .unwrap();
        let (mut send, _recv) = session.open_bi().await.unwrap().await.unwrap();
        send.write_all(&coqui_transport_web::frame::encode(b"open", 1024).unwrap())
            .await
            .unwrap();
        // Held open until the server has the session.
        tokio::time::sleep(Duration::from_millis(500)).await;
    });
}

#[test]
fn webtransport_clients_from_different_sources_reach_tls_apart() {
    let server = Identity::new();
    let (listener, noted) = noting_tls(loopback(), &server);
    let port = listener.local_addr().port();
    let accepting = thread::spawn(move || {
        (0..2)
            .map(|_| listener.accept(Some(WAIT)).unwrap())
            .collect::<Vec<_>>()
    });
    for from in [[127, 0, 0, 1], [127, 0, 0, 2]] {
        session_from(from, port, &server);
    }
    let _channels = accepting.join().unwrap();
    let mut sources: Vec<_> = noted
        .lock()
        .unwrap()
        .iter()
        .map(|(source, _)| source.ip())
        .collect();
    sources.sort();
    assert_eq!(
        sources,
        [[127, 0, 0, 1], [127, 0, 0, 2]].map(std::net::IpAddr::from)
    );
}
