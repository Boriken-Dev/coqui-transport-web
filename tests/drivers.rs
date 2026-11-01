//! The drivers against each other, over real sockets on loopback. Each binds port 0.
#![cfg(all(feature = "websocket", feature = "webtransport"))]
#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use coqui_web::websocket::{self, Frames};
use coqui_web::{
    CertificatePin, Channel, Dialer, Endpoints, Failure, Kind, Limits, NoPreflight, webtransport,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use url::Url;

const LOOPBACK: &str = "127.0.0.1:0";
const WAIT: Duration = Duration::from_secs(10);

fn loopback() -> SocketAddr {
    LOOPBACK.parse().unwrap()
}

struct Identity {
    certificate: CertificateDer<'static>,
    key: Vec<u8>,
}

fn identity() -> Identity {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    // What pinning by hash requires, in browsers and in wtransport alike: at most 14 days.
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    params.not_after = params.not_before + time::Duration::days(10);
    let certificate = params.self_signed(&key).unwrap();
    Identity {
        certificate: certificate.der().clone(),
        key: key.serialize_der(),
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn server_tls(identity: &Identity) -> Arc<rustls::ServerConfig> {
    Arc::new(
        rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.certificate.clone()],
                PrivatePkcs8KeyDer::from(identity.key.clone()).into(),
            )
            .unwrap(),
    )
}

fn client_tls(identity: &Identity) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(identity.certificate.clone()).unwrap();
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn pin(identity: &Identity) -> CertificatePin {
    use wtransport::tls::Certificate;
    let certificate = Certificate::from_der(identity.certificate.to_vec()).unwrap();
    CertificatePin::from_bytes(*certificate.hash().as_ref())
}

fn echo_once<C: Channel>(server: &C) {
    let message = server.receive(Some(WAIT)).unwrap().unwrap();
    server.send(&message).unwrap();
}

fn round_trip<C: Channel>(client: &C) {
    client.send(b"{\"jsonrpc\":\"2.0\",\"id\":1}").unwrap();
    assert_eq!(
        client.receive(Some(WAIT)).unwrap().unwrap(),
        b"{\"jsonrpc\":\"2.0\",\"id\":1}"
    );
    client.send("café".as_bytes()).unwrap();
    assert_eq!(
        client.receive(Some(WAIT)).unwrap().unwrap(),
        "café".as_bytes()
    );
}

fn plain_ws_url(address: SocketAddr) -> Url {
    Url::parse(&format!("ws://{address}/channel")).unwrap()
}

#[test]
fn plain_websocket_carries_ordered_messages_on_loopback() {
    let listener = websocket::Listener::bind(loopback(), None).unwrap();
    let url = plain_ws_url(listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        echo_once(&channel);
        echo_once(&channel);
        // The peer's orderly close is the end of the stream, not a failure.
        assert_eq!(channel.receive(Some(WAIT)).unwrap(), None);
    });
    let client = websocket::Dialer::new()
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    round_trip(&client);
    client.close();
    server.join().unwrap();
}

#[test]
fn a_plain_websocket_listener_beyond_loopback_is_refused() {
    let address: SocketAddr = "0.0.0.0:0".parse().unwrap();
    assert_eq!(
        websocket::Listener::bind(address, None).unwrap_err(),
        Failure::Permission
    );
}

#[test]
fn wss_verifies_the_certificate_and_a_stranger_is_rejected() {
    let trusted = identity();
    let listener = websocket::Listener::bind(loopback(), Some(server_tls(&trusted))).unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = Url::parse(&format!("wss://localhost:{port}/channel")).unwrap();
    let server = thread::spawn(move || {
        // The stranger's attempt fails its handshake, then the trusted client connects.
        let first = listener.accept(Some(WAIT));
        let channel = match first {
            Ok(channel) => channel,
            Err(_) => listener.accept(Some(WAIT)).unwrap(),
        };
        echo_once(&channel);
        echo_once(&channel);
    });
    let stranger = identity();
    let refused = websocket::Dialer::new()
        .with_tls(client_tls(&stranger))
        .dial(Kind::WebSocket, &url, WAIT);
    assert_eq!(refused.unwrap_err(), Failure::Certificate);
    let client = websocket::Dialer::new()
        .with_tls(client_tls(&trusted))
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    round_trip(&client);
    server.join().unwrap();
}

#[test]
fn wss_with_no_tls_configuration_fails_closed() {
    let url = Url::parse("wss://localhost:1/").unwrap();
    let refused = websocket::Dialer::new().dial(Kind::WebSocket, &url, Duration::from_secs(2));
    assert!(refused.is_err());
}

#[test]
fn a_websocket_message_over_the_limit_ends_the_channel_as_a_protocol_failure() {
    let limits = Limits::default().with_max_message(16);
    let listener = websocket::Listener::bind(loopback(), None)
        .unwrap()
        .with_limits(limits);
    let url = plain_ws_url(listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        channel.receive(Some(WAIT))
    });
    let client = websocket::Dialer::new()
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    client.send(&[b'x'; 64]).unwrap();
    assert_eq!(server.join().unwrap(), Err(Failure::Protocol));
}

#[test]
fn a_binary_websocket_message_is_refused_on_a_text_channel() {
    let listener = websocket::Listener::bind(loopback(), None).unwrap();
    let url = plain_ws_url(listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        channel.receive(Some(WAIT))
    });
    let client = websocket::Dialer::new()
        .with_frames(Frames::Binary)
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    client.send(&[0xff, 0x00]).unwrap();
    assert_eq!(server.join().unwrap(), Err(Failure::Protocol));
}

#[test]
fn invalid_text_is_refused_before_it_reaches_the_wire() {
    let listener = websocket::Listener::bind(loopback(), None).unwrap();
    let url = plain_ws_url(listener.local_addr().unwrap());
    let server = thread::spawn(move || listener.accept(Some(WAIT)).map(|_| ()));
    let client = websocket::Dialer::new()
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    assert_eq!(client.send(&[0xff]), Err(Failure::Protocol));
    assert_eq!(client.send(b""), Err(Failure::Protocol));
    server.join().unwrap().unwrap();
}

#[test]
fn a_listed_origin_is_required_when_origins_are_set() {
    use tungstenite::client::IntoClientRequest;
    let listener = websocket::Listener::bind(loopback(), None)
        .unwrap()
        .with_origins(["https://allowed.example".to_owned()]);
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let refused = listener.accept(Some(WAIT)).map(|_| ());
        let allowed = listener.accept(Some(WAIT)).map(|_| ());
        (refused, allowed)
    });
    let dial = |origin: &str| {
        let tcp = std::net::TcpStream::connect(address).unwrap();
        let mut request = format!("ws://{address}/").into_client_request().unwrap();
        request
            .headers_mut()
            .insert("origin", origin.parse().unwrap());
        tungstenite::client::client(request, tcp)
            .map(|_| ())
            .is_ok()
    };
    assert!(!dial("https://evil.example"));
    assert!(dial("https://allowed.example"));
    let (refused, allowed) = server.join().unwrap();
    assert!(refused.is_err());
    allowed.unwrap();
}

#[test]
fn a_denied_source_never_starts_a_handshake() {
    let listener = websocket::Listener::bind(loopback(), None)
        .unwrap()
        .with_admission(|_| false);
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        listener
            .accept(Some(Duration::from_millis(600)))
            .map(|_| ())
    });
    let url = plain_ws_url(address);
    let refused = websocket::Dialer::new().dial(Kind::WebSocket, &url, Duration::from_millis(500));
    assert!(refused.is_err());
    assert_eq!(server.join().unwrap(), Err(Failure::Timeout));
}

#[test]
fn a_dialer_header_and_the_path_reach_the_server_and_a_value_never_prints() {
    use tungstenite::handshake::server::{ErrorResponse, Request, Response};
    let raw = std::net::TcpListener::bind(loopback()).unwrap();
    let port = raw.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (tcp, _) = raw.accept().unwrap();
        let mut seen = None;
        let check = |request: &Request, response: Response| -> Result<Response, ErrorResponse> {
            seen = Some((
                request.uri().path().to_owned(),
                request
                    .headers()
                    .get("authorization")
                    .map(|value| value.to_str().unwrap().to_owned()),
            ));
            Ok(response)
        };
        let socket = tungstenite::accept_hdr(tcp, check).unwrap();
        drop(socket);
        seen.unwrap()
    });
    let url = Url::parse(&format!("ws://127.0.0.1:{port}/v1/assistant/agent-link")).unwrap();
    let mut dialer = websocket::Dialer::new().with_header("authorization", "Bearer secret-token");
    assert!(!format!("{dialer:?}").contains("secret-token"));
    let _channel = dialer.dial(Kind::WebSocket, &url, WAIT).unwrap();
    let (path, header) = server.join().unwrap();
    assert_eq!(path, "/v1/assistant/agent-link");
    assert_eq!(header.as_deref(), Some("Bearer secret-token"));
}

#[test]
fn a_receive_timeout_leaves_the_channel_usable() {
    let listener = websocket::Listener::bind(loopback(), None).unwrap();
    let url = plain_ws_url(listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        assert_eq!(
            channel.receive(Some(Duration::from_millis(30))),
            Err(Failure::Timeout)
        );
        echo_once(&channel);
    });
    let client = websocket::Dialer::new()
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    thread::sleep(Duration::from_millis(60));
    client.send(b"later").unwrap();
    assert_eq!(client.receive(Some(WAIT)).unwrap().unwrap(), b"later");
    server.join().unwrap();
}

#[test]
fn a_slow_reader_does_not_lose_messages_past_the_pending_bound() {
    let limits = Limits::default().with_pending(2);
    let listener = websocket::Listener::bind(loopback(), None)
        .unwrap()
        .with_limits(limits);
    let url = plain_ws_url(listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        thread::sleep(Duration::from_millis(200));
        (0..50)
            .map(|_| channel.receive(Some(WAIT)).unwrap().unwrap())
            .collect::<Vec<_>>()
    });
    let client = websocket::Dialer::new()
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    let sent: Vec<Vec<u8>> = (0..50).map(|n| format!("{n}").into_bytes()).collect();
    for message in &sent {
        client.send(message).unwrap();
    }
    assert_eq!(server.join().unwrap(), sent);
}

#[test]
fn webtransport_carries_ordered_messages_with_a_pinned_certificate() {
    let id = identity();
    let listener = webtransport::Listener::bind(loopback(), server_tls(&id)).unwrap();
    let port = listener.local_addr().port();
    let url = Url::parse(&format!("https://127.0.0.1:{port}/channel")).unwrap();
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        echo_once(&channel);
        echo_once(&channel);
        channel
    });
    let client = webtransport::Dialer::pinned(&[pin(&id)])
        .unwrap()
        .dial(Kind::WebTransport, &url, WAIT)
        .unwrap();
    round_trip(&client);
    client.close();
    drop(server.join().unwrap());
}

#[test]
fn webtransport_refuses_a_certificate_with_another_hash() {
    let id = identity();
    let listener = webtransport::Listener::bind(loopback(), server_tls(&id)).unwrap();
    let port = listener.local_addr().port();
    let url = Url::parse(&format!("https://127.0.0.1:{port}/channel")).unwrap();
    let _server = thread::spawn(move || {
        let _ = listener.accept(Some(Duration::from_secs(5)));
    });
    let wrong = CertificatePin::from_bytes([0x11; 32]);
    let refused = webtransport::Dialer::pinned(&[wrong]).unwrap().dial(
        Kind::WebTransport,
        &url,
        Duration::from_secs(5),
    );
    assert_eq!(refused.unwrap_err(), Failure::Certificate);
}

#[test]
fn webtransport_message_over_the_limit_ends_the_channel_as_a_protocol_failure() {
    let id = identity();
    let limits = Limits::default().with_max_message(8);
    let listener = webtransport::Listener::bind(loopback(), server_tls(&id))
        .unwrap()
        .with_limits(limits);
    let port = listener.local_addr().port();
    let url = Url::parse(&format!("https://127.0.0.1:{port}/channel")).unwrap();
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        channel.receive(Some(WAIT))
    });
    let client = webtransport::Dialer::pinned(&[pin(&id)])
        .unwrap()
        .dial(Kind::WebTransport, &url, WAIT)
        .unwrap();
    client.send(&[b'x'; 64]).unwrap();
    assert_eq!(server.join().unwrap(), Err(Failure::Protocol));
}

/// Dials whichever driver the kind names, so the real `connect` runs across both.
struct Both {
    websocket: websocket::Dialer,
    webtransport: webtransport::Dialer,
}

impl Dialer for Both {
    type Connection = Box<dyn Channel>;

    fn dial(
        &mut self,
        kind: Kind,
        endpoint: &Url,
        timeout: Duration,
    ) -> Result<Self::Connection, Failure> {
        match kind {
            Kind::WebSocket => Ok(Box::new(self.websocket.dial(kind, endpoint, timeout)?)),
            _ => Ok(Box::new(self.webtransport.dial(kind, endpoint, timeout)?)),
        }
    }
}

#[test]
fn a_blocked_webtransport_path_falls_back_to_websocket() {
    let listener = websocket::Listener::bind(loopback(), None).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        echo_once(&channel);
        echo_once(&channel);
    });
    // Nothing answers on this UDP port, which is what a path that blocks QUIC looks like.
    let silent = std::net::UdpSocket::bind(loopback()).unwrap();
    let port = silent.local_addr().unwrap().port();
    let endpoints = Endpoints::builder()
        .webtransport(format!("https://127.0.0.1:{port}/channel"))
        .websocket(format!("ws://127.0.0.1:{}/channel", address.port()))
        .allow_plain_loopback(true)
        .build()
        .unwrap();
    let mut dialer = Both {
        websocket: websocket::Dialer::new(),
        webtransport: webtransport::Dialer::with_tls(client_tls(&identity())).unwrap(),
    };
    let started = Instant::now();
    let link = coqui_web::connect(
        &endpoints,
        &mut dialer,
        &mut NoPreflight,
        Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(link.kind(), Kind::WebSocket);
    assert!(
        started.elapsed() >= Duration::from_secs(1),
        "it waited for the QUIC deadline"
    );
    round_trip(link.channel());
    server.join().unwrap();
}
