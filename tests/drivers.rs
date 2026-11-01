//! The drivers against each other, over real sockets on loopback. Each binds port 0.
#![cfg(all(feature = "websocket", feature = "webtransport"))]
#![allow(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::result_large_err
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use coqui_web::websocket::{self, Frames};
use coqui_web::{
    CertificatePin, Channel, Dialer, Endpoints, Failure, Kind, Limits, NoPreflight, Phase,
    Recovery, webtransport,
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
fn close_delivers_what_was_queued_before_it_returns() {
    let listener = websocket::Listener::bind(loopback(), None).unwrap();
    let url = plain_ws_url(listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        let mut got = Vec::new();
        while let Ok(Some(message)) = channel.receive(Some(WAIT)) {
            got.push(message);
        }
        got
    });
    let client = websocket::Dialer::new()
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    let sent: Vec<Vec<u8>> = (0..20).map(|n| format!("{n}").into_bytes()).collect();
    for message in &sent {
        client.send(message).unwrap();
    }
    client.close();
    assert_eq!(server.join().unwrap(), sent);
}

#[test]
fn plain_websocket_from_a_dialer_is_refused_beyond_loopback() {
    let url = Url::parse("ws://192.0.2.1:9/").unwrap();
    let refused = websocket::Dialer::new().dial(Kind::WebSocket, &url, Duration::from_millis(200));
    assert!(refused.is_err());
    // A listener answering on another address of this machine is still not loopback by name.
    let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let local = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    if local.connect("192.0.2.1:9").is_ok()
        && let Ok(address) = local.local_addr()
        && !address.ip().is_loopback()
        && !address.ip().is_unspecified()
    {
        let url = Url::parse(&format!("ws://{}:{port}/", address.ip())).unwrap();
        let refused = websocket::Dialer::new().dial(Kind::WebSocket, &url, Duration::from_secs(2));
        assert_eq!(refused.unwrap_err(), Failure::Permission);
    }
}

#[test]
fn a_peer_dribbling_its_handshake_gets_no_longer_than_the_total_limit_and_holds_up_nobody() {
    use std::io::Write;
    let limits = Limits::default().with_handshake(Duration::from_millis(600));
    let listener = websocket::Listener::bind(loopback(), None)
        .unwrap()
        .with_limits(limits);
    let address = listener.local_addr().unwrap();
    let mut slow = std::net::TcpStream::connect(address).unwrap();
    let dribbling = thread::spawn(move || {
        for _ in 0..40 {
            if slow.write_all(b"G").is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
    let pending = listener.next(Some(WAIT)).unwrap();
    let started = Instant::now();
    assert!(pending.handshake().is_err());
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    dribbling.join().unwrap();
}

#[test]
fn a_peer_that_goes_silent_is_noticed_and_a_live_one_is_not() {
    let idle = Duration::from_millis(200);
    let limits = Limits::default().with_idle(idle);
    // Two live drivers answer each other's pings, so silence between messages ends nothing.
    let listener = websocket::Listener::bind(loopback(), None)
        .unwrap()
        .with_limits(limits);
    let url = plain_ws_url(listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        echo_once(&channel);
        channel
    });
    let client = websocket::Dialer::new()
        .with_limits(limits)
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    thread::sleep(idle * 4);
    client.send(b"still here").unwrap();
    assert_eq!(client.receive(Some(WAIT)).unwrap().unwrap(), b"still here");
    let held = server.join().unwrap();

    // A socket that opened and then says nothing, and answers no ping, is gone.
    let raw = std::net::TcpListener::bind(loopback()).unwrap();
    let url = plain_ws_url(raw.local_addr().unwrap());
    let silent = thread::spawn(move || {
        let (tcp, _) = raw.accept().unwrap();
        let socket = tungstenite::accept(tcp).unwrap();
        thread::sleep(Duration::from_secs(3));
        drop(socket);
    });
    let client = websocket::Dialer::new()
        .with_limits(limits)
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    assert_eq!(client.receive(Some(WAIT)), Err(Failure::NoProgress));
    silent.join().unwrap();
    drop(held);
}

#[test]
fn a_peer_that_stops_reading_ends_the_channel_with_no_progress() {
    let limits = Limits::default()
        .with_send(Duration::from_millis(300))
        .with_max_message(1024 * 1024);
    let listener = websocket::Listener::bind(loopback(), None)
        .unwrap()
        .with_limits(limits);
    let url = plain_ws_url(listener.local_addr().unwrap());
    let raw = thread::spawn(move || {
        let tcp = std::net::TcpStream::connect(url.socket_addrs(|| None).unwrap()[0]).unwrap();
        let (socket, _) = tungstenite::client(url.as_str(), tcp).unwrap();
        thread::sleep(Duration::from_secs(8));
        drop(socket);
    });
    let channel = listener.accept(Some(WAIT)).unwrap();
    let big = vec![b'x'; 1024 * 1024];
    let started = Instant::now();
    let ended = loop {
        assert!(started.elapsed() < Duration::from_secs(7), "it kept going");
        match channel.send(&big) {
            Ok(()) => {}
            Err(Failure::NoProgress) => thread::sleep(Duration::from_millis(50)),
            // The worker has gone; why is in the inbox.
            Err(_) => break channel.receive(Some(WAIT)),
        }
        match channel.receive(Some(Duration::from_millis(1))) {
            Err(Failure::Timeout) => {}
            other => break other,
        }
    };
    assert_eq!(ended, Err(Failure::NoProgress));
    raw.join().unwrap();
}

#[test]
fn a_raised_limit_takes_effect_both_ways_and_a_lowered_one_refuses() {
    let limits = Limits::default().with_max_message(16);
    let listener = websocket::Listener::bind(loopback(), None)
        .unwrap()
        .with_limits(limits);
    let url = plain_ws_url(listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        assert_eq!(channel.send(&[b'x'; 32]), Err(Failure::Protocol));
        channel.set_max_message(64);
        channel.send(b"raised").unwrap();
        let got = channel.receive(Some(WAIT)).unwrap().unwrap();
        assert_eq!(got.len(), 32);
        channel.set_max_message(16);
        channel.send(b"lowered").unwrap();
        channel.receive(Some(WAIT))
    });
    let client = websocket::Dialer::new()
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    assert_eq!(client.receive(Some(WAIT)).unwrap().unwrap(), b"raised");
    client.send(&[b'x'; 32]).unwrap();
    assert_eq!(client.receive(Some(WAIT)).unwrap().unwrap(), b"lowered");
    client.send(&[b'x'; 32]).unwrap();
    assert!(server.join().unwrap().is_err(), "over the lowered limit");
}

#[test]
fn queued_bytes_over_the_budget_are_refused_rather_than_held() {
    let limits = Limits::default().with_queued_bytes(8);
    let listener = websocket::Listener::bind(loopback(), None).unwrap();
    let url = plain_ws_url(listener.local_addr().unwrap());
    let _server = thread::spawn(move || listener.accept(Some(WAIT)).map(|_| ()));
    let client = websocket::Dialer::new()
        .with_limits(limits)
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    assert_eq!(client.send(&[b'x'; 64]), Err(Failure::NoProgress));
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
fn webtransport_and_websocket_serve_one_port_number_on_one_address() {
    let id = identity();
    let tcp = websocket::Listener::bind(loopback(), Some(server_tls(&id))).unwrap();
    let port = tcp.local_addr().unwrap().port();
    let udp = webtransport::Listener::bind(SocketAddr::new(loopback().ip(), port), server_tls(&id))
        .unwrap();
    assert_eq!(udp.local_addr().port(), port);
    let endpoints = Endpoints::builder()
        .address(format!("https://127.0.0.1:{port}/channel"))
        .build()
        .unwrap();
    let serve_tcp = thread::spawn(move || {
        let channel = tcp.accept(Some(WAIT)).unwrap();
        echo_once(&channel);
        echo_once(&channel);
        channel
    });
    let serve_udp = thread::spawn(move || {
        let channel = udp.accept(Some(WAIT)).unwrap();
        echo_once(&channel);
        echo_once(&channel);
        channel
    });
    let quic = webtransport::Dialer::pinned(&[pin(&id)])
        .unwrap()
        .dial(Kind::WebTransport, endpoints.webtransport().unwrap(), WAIT)
        .unwrap();
    round_trip(&quic);
    quic.close();
    // The certificate names `localhost`, which only WebSocket's check looks at.
    let mut named = endpoints.websocket().unwrap().clone();
    named.set_host(Some("localhost")).unwrap();
    let socket = websocket::Dialer::new()
        .with_tls(client_tls(&id))
        .dial(Kind::WebSocket, &named, WAIT)
        .unwrap();
    round_trip(&socket);
    socket.close();
    drop(serve_udp.join().unwrap());
    drop(serve_tcp.join().unwrap());
}

/// A QUIC server that is not what a WebTransport client wants, kept running by the returned runtime.
fn other_quic_server(
    id: &Identity,
    alpn: &[u8],
    answer_not_found: bool,
) -> (tokio::runtime::Runtime, u16) {
    let mut tls = rustls::ServerConfig::clone(&server_tls(id));
    tls.alpn_protocols = vec![alpn.to_vec()];
    let config = wtransport::ServerConfig::builder()
        .with_bind_address(loopback())
        .with_custom_tls(tls)
        .build();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let endpoint = {
        let _inside = runtime.enter();
        wtransport::Endpoint::server(config).unwrap()
    };
    let port = endpoint.local_addr().unwrap().port();
    runtime.spawn(async move {
        loop {
            let incoming = endpoint.accept().await;
            if let Ok(request) = incoming.await
                && answer_not_found
            {
                request.not_found().await;
            }
        }
    });
    (runtime, port)
}

#[test]
fn a_server_that_does_not_offer_webtransport_is_a_reason_to_try_websocket() {
    let id = identity();
    for (alpn, not_found) in [(&b"something-else"[..], false), (&b"h3"[..], true)] {
        let (_running, port) = other_quic_server(&id, alpn, not_found);
        let url = Url::parse(&format!("https://127.0.0.1:{port}/channel")).unwrap();
        let failure = webtransport::Dialer::pinned(&[pin(&id)])
            .unwrap()
            .dial(Kind::WebTransport, &url, WAIT)
            .unwrap_err();
        assert_eq!(
            failure.recovery(Kind::WebTransport, Phase::Opening, true),
            Recovery::VerifyFallback,
            "{alpn:?} gave {failure:?}"
        );
    }
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
