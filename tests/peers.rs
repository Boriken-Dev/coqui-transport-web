//! What a channel and a pending handshake tell about the peer, over real sockets on loopback. Each binds port 0.
#![cfg(all(feature = "websocket", feature = "webtransport"))]
#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use coqui_web::{CertificatePin, Channel, Dialer, Failure, Kind, websocket, webtransport};
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
    let listener = websocket::Listener::bind(loopback(), server).unwrap();
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
    let listener = webtransport::Listener::bind(loopback(), server).unwrap();
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
        let dialer =
            websocket::Dialer::new().with_tls(client_tls(&server, presents.then_some(&client)));
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
    assert_eq!(over_websocket(None, websocket::Dialer::new()), (None, None));
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
        let dialer =
            webtransport::Dialer::with_tls(client_tls(&server, presents.then_some(&client)))
                .unwrap();
        let seen = over_webtransport(server_tls(&server, &client, ask), dialer);
        assert_eq!(
            seen,
            (Some(server.der()), server_sees),
            "{ask:?} {presents}"
        );
    }
    // A pinned dialer has the chain its pin matched.
    let pinned = webtransport::Dialer::pinned(&[server.pin()]).unwrap();
    let seen = over_webtransport(server_tls(&server, &client, Ask::Nothing), pinned);
    assert_eq!(seen, (Some(server.der()), None));
}

#[test]
fn a_boxed_channel_passes_its_certificates_on() {
    let (server, client) = (Identity::new(), Identity::new());
    let listener =
        websocket::Listener::bind(loopback(), Some(server_tls(&server, &client, Ask::Nothing)))
            .unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = thread::spawn(move || listener.accept(Some(WAIT)).map(|_| ()));
    let url = Url::parse(&format!("wss://127.0.0.1:{port}/")).unwrap();
    let boxed: Box<dyn Channel> = Box::new(
        websocket::Dialer::new()
            .with_tls(client_tls(&server, None))
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
    let listener = websocket::Listener::bind(loopback(), None)
        .unwrap()
        .with_admission(admit);
    let tcp = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let pending = listener.next(Some(WAIT)).unwrap();
    assert_eq!(pending.peer_addr(), tcp.local_addr().unwrap());
    assert_eq!(*noted.lock().unwrap(), [pending.peer_addr()]);
}

#[test]
fn a_pending_webtransport_session_names_the_source_it_admitted() {
    let id = Identity::new();
    let (noted, admit) = noting();
    let listener = webtransport::Listener::bind(loopback(), server_tls(&id, &id, Ask::Nothing))
        .unwrap()
        .with_admission(admit);
    let url = Url::parse(&format!(
        "https://127.0.0.1:{}/",
        listener.local_addr().port()
    ))
    .unwrap();
    let client = thread::spawn(move || {
        let _ = webtransport::Dialer::pinned(&[id.pin()]).unwrap().dial(
            Kind::WebTransport,
            &url,
            Duration::from_secs(3),
        );
    });
    let pending = listener.next(Some(WAIT)).unwrap();
    assert_eq!(*noted.lock().unwrap(), [pending.peer_addr()]);
    assert!(pending.peer_addr().ip().is_loopback());
    assert_ne!(pending.peer_addr(), listener.local_addr());
    drop(pending);
    client.join().unwrap();
}

#[cfg(feature = "webrtc")]
#[test]
fn a_pending_session_on_a_port_names_the_client_and_not_its_relay() {
    use coqui_web::webrtc::{Port, Settings};
    let id = Identity::new();
    let (noted, admit) = noting();
    let port = Port::bind(loopback(), Settings::default()).unwrap();
    let listener = webtransport::Listener::on_port(&port, server_tls(&id, &id, Ask::Nothing))
        .unwrap()
        .with_admission(admit);
    let url = Url::parse(&format!("https://127.0.0.1:{}/", port.local_addr().port())).unwrap();
    let client = thread::spawn(move || {
        let _ = webtransport::Dialer::pinned(&[id.pin()]).unwrap().dial(
            Kind::WebTransport,
            &url,
            Duration::from_secs(3),
        );
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
        let listener =
            webtransport::Listener::bind(loopback(), server_tls(&server, &trusted, Ask::Required))
                .unwrap();
        let url = Url::parse(&format!(
            "https://127.0.0.1:{}/",
            listener.local_addr().port()
        ))
        .unwrap();
        let accepting = thread::spawn(move || listener.accept(Some(WAIT)).err());
        let dialed = webtransport::Dialer::with_tls(client_tls(&server, presented))
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
    let dialed = webtransport::Dialer::with_tls(client_tls(&server, None))
        .unwrap()
        .dial(Kind::WebTransport, &url, Duration::from_secs(2));
    let failure = dialed.err();
    assert!(failure.is_some_and(Failure::is_path), "{failure:?}");
}
