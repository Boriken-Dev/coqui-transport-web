//! What a channel and a pending handshake tell about the peer, over real sockets on loopback. Each binds port 0.
#![cfg(all(feature = "websocket", feature = "webtransport"))]
#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use coqui_web::{CertificatePin, Channel, Dialer, Kind, websocket, webtransport};
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
        let names = vec!["localhost".to_owned(), "127.0.0.1".to_owned()];
        let mut params = rcgen::CertificateParams::new(names).unwrap();
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

