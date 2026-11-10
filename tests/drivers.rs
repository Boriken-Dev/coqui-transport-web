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

use coqui_transport_web::websocket::{self, Frames};
use coqui_transport_web::{
    CertificatePin, Channel, Dialer, Endpoints, Failure, FailureExt, Kind, Limits, NoPreflight,
    Phase, Recovery, webtransport,
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
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .build()
        .unwrap();
    let url = plain_ws_url(listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        echo_once(&channel);
        echo_once(&channel);
        // The peer's orderly close is the end of the stream, not a failure.
        assert_eq!(channel.receive(Some(WAIT)).unwrap(), None);
    });
    let client = websocket::Dialer::builder()
        .build()
        .unwrap()
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
        websocket::Listener::builder(address, websocket::ServerTls::Plain)
            .build()
            .unwrap_err(),
        coqui_builder::builder::BuildError::Failed(Failure::Permission)
    );
}

#[test]
fn wss_verifies_the_certificate_and_a_stranger_is_rejected() {
    let trusted = identity();
    let listener = websocket::Listener::builder(
        loopback(),
        websocket::ServerTls::Config(server_tls(&trusted)),
    )
    .build()
    .unwrap();
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
    let refused = websocket::Dialer::builder()
        .tls(client_tls(&stranger))
        .build()
        .unwrap()
        .dial(Kind::WebSocket, &url, WAIT);
    assert_eq!(refused.unwrap_err(), Failure::Certificate);
    let client = websocket::Dialer::builder()
        .tls(client_tls(&trusted))
        .build()
        .unwrap()
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    round_trip(&client);
    server.join().unwrap();
}

#[test]
fn wss_with_no_tls_configuration_fails_closed() {
    let url = Url::parse("wss://localhost:1/").unwrap();
    let refused = websocket::Dialer::builder().build().unwrap().dial(
        Kind::WebSocket,
        &url,
        Duration::from_secs(2),
    );
    assert!(refused.is_err());
}

#[test]
fn a_websocket_message_over_the_limit_ends_the_channel_as_a_protocol_failure() {
    let limits = {
        let mut value = Limits::default();
        value.max_message = 16;
        value
    };
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .limits(limits)
        .build()
        .unwrap();
    let url = plain_ws_url(listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        channel.receive(Some(WAIT))
    });
    let client = websocket::Dialer::builder()
        .build()
        .unwrap()
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    client.send(&[b'x'; 64]).unwrap();
    assert_eq!(server.join().unwrap(), Err(Failure::Protocol));
}

#[test]
fn a_binary_websocket_message_is_refused_on_a_text_channel() {
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .build()
        .unwrap();
    let url = plain_ws_url(listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        channel.receive(Some(WAIT))
    });
    let client = websocket::Dialer::builder()
        .frames(Frames::Binary)
        .build()
        .unwrap()
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    client.send(&[0xff, 0x00]).unwrap();
    assert_eq!(server.join().unwrap(), Err(Failure::Protocol));
}

#[test]
fn invalid_text_is_refused_before_it_reaches_the_wire() {
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .build()
        .unwrap();
    let url = plain_ws_url(listener.local_addr().unwrap());
    let server = thread::spawn(move || listener.accept(Some(WAIT)).map(|_| ()));
    let client = websocket::Dialer::builder()
        .build()
        .unwrap()
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    assert_eq!(client.send(&[0xff]), Err(Failure::Protocol));
    assert_eq!(client.send(b""), Err(Failure::Protocol));
    server.join().unwrap().unwrap();
}

#[test]
fn a_listed_origin_is_required_when_origins_are_set() {
    use tungstenite::client::IntoClientRequest;
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .origins(["https://allowed.example".to_owned()])
        .build()
        .unwrap();
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
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .admission(|_| false)
        .build()
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        listener
            .accept(Some(Duration::from_millis(600)))
            .map(|_| ())
    });
    let url = plain_ws_url(address);
    let refused = websocket::Dialer::builder().build().unwrap().dial(
        Kind::WebSocket,
        &url,
        Duration::from_millis(500),
    );
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
    let mut dialer = websocket::Dialer::builder()
        .headers(vec![(
            "authorization".to_owned(),
            "Bearer secret-token".to_owned(),
        )])
        .build()
        .unwrap();
    assert!(!format!("{dialer:?}").contains("secret-token"));
    let _channel = dialer.dial(Kind::WebSocket, &url, WAIT).unwrap();
    let (path, header) = server.join().unwrap();
    assert_eq!(path, "/v1/assistant/agent-link");
    assert_eq!(header.as_deref(), Some("Bearer secret-token"));
}

#[test]
fn close_delivers_what_was_queued_before_it_returns() {
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .build()
        .unwrap();
    let url = plain_ws_url(listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        let mut got = Vec::new();
        while let Ok(Some(message)) = channel.receive(Some(WAIT)) {
            got.push(message);
        }
        got
    });
    let client = websocket::Dialer::builder()
        .build()
        .unwrap()
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
    let refused = websocket::Dialer::builder().build().unwrap().dial(
        Kind::WebSocket,
        &url,
        Duration::from_millis(200),
    );
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
        let refused = websocket::Dialer::builder().build().unwrap().dial(
            Kind::WebSocket,
            &url,
            Duration::from_secs(2),
        );
        assert_eq!(refused.unwrap_err(), Failure::Permission);
    }
}

/// An address of this machine beyond loopback, if it has one with a route.
fn beyond_loopback() -> Option<std::net::IpAddr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect("192.0.2.1:9").ok()?;
    let address = probe.local_addr().ok()?.ip();
    (!address.is_loopback() && !address.is_unspecified()).then_some(address)
}

#[test]
fn a_plain_websocket_listener_beyond_loopback_is_a_choice_it_reports() {
    let anywhere: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let listener = websocket::Listener::builder(anywhere, websocket::ServerTls::Plain)
        .plain_beyond_loopback(true)
        .build()
        .unwrap();
    assert!(listener.plain_beyond_loopback());
    assert!(format!("{listener:?}").contains("plain_beyond_loopback: true"));
    for local in [
        websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
            .plain_beyond_loopback(true)
            .build()
            .unwrap(),
        websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
            .build()
            .unwrap(),
        websocket::Listener::builder(
            anywhere,
            websocket::ServerTls::Config(server_tls(&identity())),
        )
        .build()
        .unwrap(),
    ] {
        assert!(!local.plain_beyond_loopback(), "{local:?}");
    }
}

#[test]
fn a_dialer_opens_plain_websocket_beyond_loopback_only_when_told_to() {
    let refused = websocket::Dialer::builder().build().unwrap().dial(
        Kind::WebSocket,
        &Url::parse("ws://192.0.2.1:9/").unwrap(),
        Duration::from_secs(5),
    );
    assert_eq!(refused.unwrap_err(), Failure::Permission);
    assert!(
        !websocket::Dialer::builder()
            .build()
            .unwrap()
            .plain_beyond_loopback()
    );
    let Some(address) = beyond_loopback() else {
        eprintln!("no address beyond loopback with a route: the dial itself is not tried");
        return;
    };
    let listener =
        websocket::Listener::builder(SocketAddr::new(address, 0), websocket::ServerTls::Plain)
            .plain_beyond_loopback(true)
            .build()
            .unwrap();
    let url = plain_ws_url(listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        echo_once(&channel);
        echo_once(&channel);
    });
    let refused = websocket::Dialer::builder()
        .build()
        .unwrap()
        .dial(Kind::WebSocket, &url, WAIT);
    assert_eq!(refused.unwrap_err(), Failure::Permission);
    let mut dialer = websocket::Dialer::builder()
        .plain_beyond_loopback(true)
        .build()
        .unwrap();
    assert!(dialer.plain_beyond_loopback());
    assert!(format!("{dialer:?}").contains("plain_beyond_loopback: true"));
    let client = dialer.dial(Kind::WebSocket, &url, WAIT).unwrap();
    round_trip(&client);
    server.join().unwrap();
}

#[test]
fn a_peer_dribbling_its_handshake_gets_no_longer_than_the_total_limit_and_holds_up_nobody() {
    use std::io::Write;
    let limits = {
        let mut value = Limits::default();
        value.handshake = Duration::from_millis(600);
        value
    };
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .limits(limits)
        .build()
        .unwrap();
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
    let limits = {
        let mut value = Limits::default();
        value.idle = idle;
        value
    };
    // Two live drivers answer each other's pings, so silence between messages ends nothing.
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .limits(limits)
        .build()
        .unwrap();
    let url = plain_ws_url(listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        echo_once(&channel);
        channel
    });
    let client = websocket::Dialer::builder()
        .limits(limits)
        .build()
        .unwrap()
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
    let client = websocket::Dialer::builder()
        .limits(limits)
        .build()
        .unwrap()
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    assert_eq!(client.receive(Some(WAIT)), Err(Failure::NoProgress));
    silent.join().unwrap();
    drop(held);
}

#[test]
fn a_peer_that_stops_reading_ends_the_channel_with_no_progress() {
    let limits = {
        let mut value = Limits::default();
        value.send = Duration::from_millis(300);
        value.max_message = 1024 * 1024;
        value
    };
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .limits(limits)
        .build()
        .unwrap();
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
    let limits = {
        let mut value = Limits::default();
        value.max_message = 16;
        value
    };
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .limits(limits)
        .build()
        .unwrap();
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
    let client = websocket::Dialer::builder()
        .build()
        .unwrap()
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
    let limits = {
        let mut value = Limits::default();
        value.queued_bytes = 8;
        value
    };
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .build()
        .unwrap();
    let url = plain_ws_url(listener.local_addr().unwrap());
    let _server = thread::spawn(move || listener.accept(Some(WAIT)).map(|_| ()));
    let client = websocket::Dialer::builder()
        .limits(limits)
        .build()
        .unwrap()
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    assert_eq!(client.send(&[b'x'; 64]), Err(Failure::NoProgress));
}

#[test]
fn a_receive_timeout_leaves_the_channel_usable() {
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .build()
        .unwrap();
    let url = plain_ws_url(listener.local_addr().unwrap());
    // The client sends only once the timeout has happened, whatever the machine's speed.
    let (timed_out, wait_for_it) = std::sync::mpsc::channel();
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        assert_eq!(
            channel.receive(Some(Duration::from_millis(30))),
            Err(Failure::Timeout)
        );
        timed_out.send(()).unwrap();
        echo_once(&channel);
    });
    let client = websocket::Dialer::builder()
        .build()
        .unwrap()
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    wait_for_it.recv_timeout(WAIT).unwrap();
    client.send(b"later").unwrap();
    assert_eq!(client.receive(Some(WAIT)).unwrap().unwrap(), b"later");
    server.join().unwrap();
}

#[test]
fn a_slow_reader_does_not_lose_messages_past_the_pending_bound() {
    let limits = {
        let mut value = Limits::default();
        value.pending = 2;
        value
    };
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .limits(limits)
        .build()
        .unwrap();
    let url = plain_ws_url(listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        thread::sleep(Duration::from_millis(200));
        (0..50)
            .map(|_| channel.receive(Some(WAIT)).unwrap().unwrap())
            .collect::<Vec<_>>()
    });
    let client = websocket::Dialer::builder()
        .build()
        .unwrap()
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
    let listener = webtransport::Listener::builder(loopback(), server_tls(&id))
        .build()
        .unwrap();
    let port = listener.local_addr().port();
    let url = Url::parse(&format!("https://127.0.0.1:{port}/channel")).unwrap();
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        echo_once(&channel);
        echo_once(&channel);
        channel
    });
    let client =
        webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::from([pin(&id)])))
            .build()
            .unwrap()
            .dial(Kind::WebTransport, &url, WAIT)
            .unwrap();
    round_trip(&client);
    client.close();
    drop(server.join().unwrap());
}

/// A connected WebTransport pair with `limits` on the listening side.
fn webtransport_pair(
    limits: coqui_transport_web::Limits,
) -> (webtransport::Channel, webtransport::Channel) {
    let id = identity();
    let listener = webtransport::Listener::builder(loopback(), server_tls(&id))
        .limits(limits)
        .build()
        .unwrap();
    let port = listener.local_addr().port();
    let accepted = thread::spawn(move || listener.accept(Some(WAIT)).unwrap());
    let client =
        webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::from([pin(&id)])))
            .build()
            .unwrap()
            .dial(
                Kind::WebTransport,
                &Url::parse(&format!("https://127.0.0.1:{port}/channel")).unwrap(),
                WAIT,
            )
            .unwrap();
    // A client has nothing to accept until its stream carries something.
    client.send(b"open").unwrap();
    let server = accepted.join().unwrap();
    assert_eq!(server.receive(Some(WAIT)).unwrap().unwrap(), b"open");
    (client, server)
}

#[test]
fn webtransport_datagrams_go_both_ways_beside_the_messages() {
    let (client, server) = webtransport_pair(coqui_transport_web::Limits::default());
    let (near, far) = (client.datagrams().unwrap(), server.datagrams().unwrap());
    assert!(near.max_size().unwrap() > 1000, "{:?}", near.max_size());
    assert_eq!(near.delivery(), coqui_transport_web::Delivery::Unreliable);
    // Sent until one arrives: losing one is what they may do, even here.
    let until = std::time::Instant::now() + WAIT;
    let arrived = loop {
        near.send(b"\xff\x00raw").unwrap();
        match far.receive(Some(Duration::from_millis(100))) {
            Ok(Some(datagram)) => break datagram,
            Err(Failure::Timeout) => assert!(std::time::Instant::now() < until, "none arrived"),
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(arrived, b"\xff\x00raw");
    far.send(b"back").unwrap();
    assert_eq!(near.receive(Some(WAIT)).unwrap().unwrap(), b"back");
    client.send(b"a message").unwrap();
    assert_eq!(server.receive(Some(WAIT)).unwrap().unwrap(), b"a message");
}

#[test]
fn a_datagram_too_large_is_refused_and_the_channel_goes_on() {
    let (client, server) = webtransport_pair(coqui_transport_web::Limits::default());
    let datagrams = client.datagrams().unwrap();
    let largest = datagrams.max_size().unwrap();
    assert_eq!(
        datagrams.send(&vec![1; largest + 1]),
        Err(Failure::Protocol)
    );
    datagrams.send(&vec![1; largest]).unwrap();
    client.send(b"still here").unwrap();
    assert_eq!(server.receive(Some(WAIT)).unwrap().unwrap(), b"still here");
}

#[test]
fn a_reader_behind_loses_datagrams_and_can_see_how_many() {
    let (client, server) = webtransport_pair({
        let mut value = coqui_transport_web::Limits::default();
        value.pending_datagrams = 2;
        value
    });
    let (near, far) = (client.datagrams().unwrap(), server.datagrams().unwrap());
    let until = std::time::Instant::now() + WAIT;
    while far.dropped() == 0 {
        assert!(std::time::Instant::now() < until, "nothing was discarded");
        for _ in 0..16 {
            let _ = near.send(b"more than it holds");
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        far.receive(Some(WAIT)).unwrap().unwrap(),
        b"more than it holds"
    );
    // The stream never slowed for that.
    client.send(b"message").unwrap();
    assert_eq!(server.receive(Some(WAIT)).unwrap().unwrap(), b"message");
}

#[test]
fn datagrams_end_with_the_channel() {
    let (client, server) = webtransport_pair(coqui_transport_web::Limits::default());
    let far = server.datagrams().unwrap();
    client.close();
    let until = std::time::Instant::now() + WAIT;
    loop {
        match far.receive(Some(Duration::from_millis(100))) {
            Ok(None) => break,
            Err(Failure::Timeout) => assert!(std::time::Instant::now() < until, "it went on"),
            other => panic!("{other:?}"),
        }
    }
    let near = client.datagrams().unwrap();
    assert_eq!(near.send(b"late"), Err(Failure::PathLost));
}

/// A connected WebSocket pair, with each end's dialer as `dialer` makes it.
fn websocket_pair(
    limits: coqui_transport_web::Limits,
    frames: Frames,
    dialer: impl FnOnce(websocket::DialerBuilder) -> websocket::DialerBuilder,
) -> (websocket::Channel, websocket::Channel) {
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .limits(limits)
        .frames(frames)
        .build()
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = thread::spawn(move || listener.accept(Some(WAIT)).unwrap());
    let client = dialer(websocket::Dialer::builder().limits(limits).frames(frames))
        .build()
        .unwrap()
        .dial(
            Kind::WebSocket,
            &Url::parse(&format!("ws://127.0.0.1:{port}/")).unwrap(),
            WAIT,
        )
        .unwrap();
    (client, accepted.join().unwrap())
}

#[test]
fn a_websocket_has_no_datagrams_unless_asked_and_its_wire_is_unchanged() {
    let (client, server) = websocket_pair(
        coqui_transport_web::Limits::default(),
        Frames::Binary,
        |dialer| dialer,
    );
    assert!(client.datagrams().is_none());
    assert!(server.datagrams().is_none());
    let boxed: Box<dyn Channel> = Box::new(client);
    assert!(boxed.datagrams().is_none());

    // A peer that knows nothing of tags sees a body as it was, and is seen as it was.
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .frames(Frames::Binary)
        .build()
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = thread::spawn(move || listener.accept(Some(WAIT)).unwrap());
    let (mut raw, _) = tungstenite::connect(format!("ws://127.0.0.1:{port}/")).unwrap();
    let server = accepted.join().unwrap();
    server.send(&[0, 1, 2]).unwrap();
    assert_eq!(raw.read().unwrap().into_data().as_ref(), [0, 1, 2]);
    raw.send(tungstenite::Message::binary(vec![1, 2, 3]))
        .unwrap();
    assert_eq!(server.receive(Some(WAIT)).unwrap().unwrap(), [1, 2, 3]);
}

#[test]
fn websocket_datagrams_go_both_ways_beside_the_messages_in_either_frame_kind() {
    for frames in [Frames::Binary, Frames::Text] {
        let (client, server) =
            websocket_pair(coqui_transport_web::Limits::default(), frames, |builder| {
                builder.datagrams(true)
            });
        let (near, far) = (client.datagrams().unwrap(), server.datagrams().unwrap());
        assert_eq!(near.delivery(), coqui_transport_web::Delivery::OverStream);
        assert_eq!(near.max_size(), Some(64 * 1024));
        client.send(b"a message").unwrap();
        near.send(b"\xff\x00raw").unwrap();
        near.send(b"").unwrap();
        assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), b"\xff\x00raw");
        assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), b"");
        assert_eq!(server.receive(Some(WAIT)).unwrap().unwrap(), b"a message");
        far.send(b"back").unwrap();
        server.send(b"a reply").unwrap();
        assert_eq!(near.receive(Some(WAIT)).unwrap().unwrap(), b"back");
        assert_eq!(client.receive(Some(WAIT)).unwrap().unwrap(), b"a reply");
    }
}

#[test]
fn a_websocket_message_at_its_limit_still_fits_with_the_tag() {
    let limits = {
        let mut value = coqui_transport_web::Limits::default();
        value.max_message = 5;
        value
    };
    let (client, server) =
        websocket_pair(limits, Frames::Binary, |builder| builder.datagrams(true));
    client.send(b"12345").unwrap();
    assert_eq!(server.receive(Some(WAIT)).unwrap().unwrap(), b"12345");
    assert_eq!(client.send(b"123456"), Err(Failure::Protocol));
}

#[test]
fn a_websocket_datagram_size_is_a_setting_with_no_floor_and_it_binds_both_ways() {
    let limits = {
        let mut value = coqui_transport_web::Limits::default();
        value.websocket_datagram = 4;
        value
    };
    let (client, server) =
        websocket_pair(limits, Frames::Binary, |builder| builder.datagrams(true));
    let (near, far) = (client.datagrams().unwrap(), server.datagrams().unwrap());
    assert_eq!(near.max_size(), Some(4));
    assert_eq!(near.send(b"12345"), Err(Failure::Protocol));
    client.send(b"still here").unwrap();
    assert_eq!(server.receive(Some(WAIT)).unwrap().unwrap(), b"still here");

    // A peer whose own setting is larger: the extra is discarded and counted, and nothing else is harmed.
    let wide = coqui_transport_web::Limits::default();
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .limits(limits)
        .frames(Frames::Binary)
        .build()
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = thread::spawn(move || listener.accept(Some(WAIT)).unwrap());
    let wider = websocket::Dialer::builder()
        .limits(wide)
        .frames(Frames::Binary)
        .datagrams(true)
        .build()
        .unwrap()
        .dial(
            Kind::WebSocket,
            &Url::parse(&format!("ws://127.0.0.1:{port}/")).unwrap(),
            WAIT,
        )
        .unwrap();
    let narrow = accepted.join().unwrap();
    let there = narrow.datagrams().unwrap();
    wider.datagrams().unwrap().send(b"far too long").unwrap();
    wider.datagrams().unwrap().send(b"fits").unwrap();
    assert_eq!(there.receive(Some(WAIT)).unwrap().unwrap(), b"fits");
    assert_eq!(there.dropped(), 1);
    assert_eq!(far.dropped(), 0);

    let none = {
        let mut value = coqui_transport_web::Limits::default();
        value.websocket_datagram = 0;
        value
    };
    let (client, _server) = websocket_pair(none, Frames::Binary, |builder| builder.datagrams(true));
    let datagrams = client.datagrams().unwrap();
    assert_eq!(datagrams.send(b"x"), Err(Failure::Protocol));
    datagrams.send(b"").unwrap();
}

#[test]
fn websocket_datagrams_nobody_asked_for_are_not_held() {
    let (client, server) = websocket_pair(
        {
            let mut value = coqui_transport_web::Limits::default();
            value.pending_datagrams = 1;
            value
        },
        Frames::Binary,
        |builder| builder.datagrams(true),
    );
    let near = client.datagrams().unwrap();
    near.send(b"one").unwrap();
    client.send(b"then this").unwrap();
    assert_eq!(server.receive(Some(WAIT)).unwrap().unwrap(), b"then this");
    let far = server.datagrams().unwrap();
    assert_eq!(far.dropped(), 1, "it came before anyone asked");
    assert!(matches!(
        far.receive(Some(Duration::from_millis(50))),
        Err(Failure::Timeout)
    ));
    // Asked for, a reader behind loses the ones past its queue, and messages are not held up by it.
    near.send(b"kept").unwrap();
    client.send(b"sync").unwrap();
    assert_eq!(server.receive(Some(WAIT)).unwrap().unwrap(), b"sync");
    near.send(b"past the queue").unwrap();
    client.send(b"sync").unwrap();
    assert_eq!(server.receive(Some(WAIT)).unwrap().unwrap(), b"sync");
    assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), b"kept");
    assert_eq!(far.dropped(), 2);
}

#[test]
fn a_datagram_from_a_peer_cannot_arrive_as_a_message_or_break_the_channel() {
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .frames(Frames::Binary)
        .build()
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = thread::spawn(move || listener.accept(Some(WAIT)).unwrap());
    let mut request = tungstenite::client::IntoClientRequest::into_client_request(format!(
        "ws://127.0.0.1:{port}/"
    ))
    .unwrap();
    request.headers_mut().insert(
        "sec-websocket-protocol",
        tungstenite::http::HeaderValue::from_static(
            coqui_transport_web::frame::WS_DATAGRAMS_PROTOCOL,
        ),
    );
    let (mut raw, _) = tungstenite::connect(request).unwrap();
    let server = accepted.join().unwrap();
    let far = server.datagrams().unwrap();
    raw.send(tungstenite::Message::binary(vec![1, 9])).unwrap();
    raw.send(tungstenite::Message::binary(vec![0, 7])).unwrap();
    assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), [9]);
    assert_eq!(server.receive(Some(WAIT)).unwrap().unwrap(), [7]);
    // A tag this does not know ends it, rather than being guessed at.
    raw.send(tungstenite::Message::binary(vec![2, 9])).unwrap();
    assert_eq!(server.receive(Some(WAIT)), Err(Failure::Protocol));
}

#[test]
fn a_server_that_does_not_agree_is_a_failure_a_caller_can_read() {
    // A WebSocket server that knows nothing of this, as anyone else's would be.
    let server = std::net::TcpListener::bind(loopback()).unwrap();
    let port = server.local_addr().unwrap().port();
    thread::spawn(move || {
        let (stream, _) = server.accept().unwrap();
        let _ = tungstenite::accept(stream);
    });
    let refused = websocket::Dialer::builder()
        .datagrams(true)
        .build()
        .unwrap()
        .dial(
            Kind::WebSocket,
            &Url::parse(&format!("ws://127.0.0.1:{port}/")).unwrap(),
            WAIT,
        );
    assert_eq!(refused.err(), Some(Failure::Unsupported));
}

#[test]
fn websocket_datagrams_end_with_the_channel() {
    let (client, server) = websocket_pair(
        coqui_transport_web::Limits::default(),
        Frames::Binary,
        |builder| builder.datagrams(true),
    );
    let far = server.datagrams().unwrap();
    client.close();
    assert_eq!(far.receive(Some(WAIT)), Ok(None));
    server.close();
    assert_eq!(far.send(b"late"), Err(Failure::PathLost));
}

#[test]
fn webtransport_and_websocket_serve_one_port_number_on_one_address() {
    let id = identity();
    let tcp =
        websocket::Listener::builder(loopback(), websocket::ServerTls::Config(server_tls(&id)))
            .build()
            .unwrap();
    let port = tcp.local_addr().unwrap().port();
    let udp =
        webtransport::Listener::builder(SocketAddr::new(loopback().ip(), port), server_tls(&id))
            .build()
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
    let quic =
        webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::from([pin(&id)])))
            .build()
            .unwrap()
            .dial(Kind::WebTransport, endpoints.webtransport().unwrap(), WAIT)
            .unwrap();
    round_trip(&quic);
    quic.close();
    // The certificate names `localhost`, which only WebSocket's check looks at.
    let mut named = endpoints.websocket().unwrap().clone();
    named.set_host(Some("localhost")).unwrap();
    let socket = websocket::Dialer::builder()
        .tls(client_tls(&id))
        .build()
        .unwrap()
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
        let failure =
            webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::from([pin(&id)])))
                .build()
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
    let listener = webtransport::Listener::builder(loopback(), server_tls(&id))
        .build()
        .unwrap();
    let port = listener.local_addr().port();
    let url = Url::parse(&format!("https://127.0.0.1:{port}/channel")).unwrap();
    let _server = thread::spawn(move || {
        let _ = listener.accept(Some(Duration::from_secs(5)));
    });
    let wrong = CertificatePin::from_bytes([0x11; 32]);
    let refused =
        webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::from([wrong])))
            .build()
            .unwrap()
            .dial(Kind::WebTransport, &url, Duration::from_secs(5));
    assert_eq!(refused.unwrap_err(), Failure::Certificate);
}

#[test]
fn a_source_webtransport_admission_refuses_is_told_so_and_does_not_fall_back() {
    let id = identity();
    let listener = webtransport::Listener::builder(loopback(), server_tls(&id))
        .admission(|_| false)
        .build()
        .unwrap();
    let port = listener.local_addr().port();
    let serving = thread::spawn(move || listener.next(Some(Duration::from_secs(3))).map(|_| ()));
    let url = Url::parse(&format!("https://127.0.0.1:{port}/channel")).unwrap();
    let started = Instant::now();
    let refused =
        webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::from([pin(&id)])))
            .build()
            .unwrap()
            .dial(Kind::WebTransport, &url, WAIT)
            .unwrap_err();
    assert_eq!(refused, Failure::Permission);
    assert!(started.elapsed() < Duration::from_secs(3), "it was told");
    assert_eq!(
        refused.recovery(Kind::WebTransport, Phase::Opening, true),
        Recovery::Deny
    );
    assert_eq!(serving.join().unwrap(), Err(Failure::Timeout));
}

#[test]
fn webtransport_message_over_the_limit_ends_the_channel_as_a_protocol_failure() {
    let id = identity();
    let limits = {
        let mut value = Limits::default();
        value.max_message = 8;
        value
    };
    let listener = webtransport::Listener::builder(loopback(), server_tls(&id))
        .limits(limits)
        .build()
        .unwrap();
    let port = listener.local_addr().port();
    let url = Url::parse(&format!("https://127.0.0.1:{port}/channel")).unwrap();
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        channel.receive(Some(WAIT))
    });
    let client =
        webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::from([pin(&id)])))
            .build()
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
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .build()
        .unwrap();
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
        websocket: websocket::Dialer::builder().build().unwrap(),
        webtransport: webtransport::Dialer::builder(webtransport::ClientTrust::Config(client_tls(
            &identity(),
        )))
        .build()
        .unwrap(),
    };
    let started = Instant::now();
    let link = coqui_transport_web::connect(
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

#[test]
fn a_webtransport_name_resolving_to_both_families_reaches_a_listener_on_either() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
    let resolved: Vec<SocketAddr> = ("localhost", 1).to_socket_addrs().unwrap().collect();
    // The listener takes the family the resolver does not put first.
    let other = if resolved[0].is_ipv6() {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    };
    if !resolved.iter().any(|address| address.ip() == other) {
        eprintln!("localhost names one family here: {resolved:?}");
        return;
    }
    let id = identity();
    let listener = webtransport::Listener::builder(SocketAddr::new(other, 0), server_tls(&id))
        .build()
        .unwrap();
    let port = listener.local_addr().port();
    let server = thread::spawn(move || {
        let channel = listener.accept(Some(WAIT)).unwrap();
        echo_once(&channel);
        echo_once(&channel);
        channel
    });
    let url = Url::parse(&format!("https://localhost:{port}/channel")).unwrap();
    let started = Instant::now();
    let client =
        webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::from([pin(&id)])))
            .build()
            .unwrap()
            .dial(Kind::WebTransport, &url, WAIT)
            .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    round_trip(&client);
    drop(server.join().unwrap());
}

/// A handshake limit no test waits out.
fn patient() -> Limits {
    {
        let mut value = Limits::default();
        value.handshake = Duration::from_secs(30);
        value
    }
}

/// Whether a socket's peer has closed it: an end, or a reset, and not a read still waiting.
fn ended(socket: &std::net::TcpStream) -> bool {
    use std::io::Read;
    socket.set_read_timeout(Some(WAIT)).unwrap();
    match (&*socket).read(&mut [0; 1]) {
        Ok(read) => read == 0,
        Err(error) => !matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
    }
}

#[test]
fn a_websocket_handshake_can_be_abandoned_from_another_thread() {
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .limits(patient())
        .build()
        .unwrap();
    let address = listener.local_addr().unwrap();
    // A peer that connects and says nothing.
    let silent = std::net::TcpStream::connect(address).unwrap();
    let pending = listener.next(Some(WAIT)).unwrap();
    let cancel = pending.canceller();
    let started = Instant::now();
    let handshaking = thread::spawn(move || pending.handshake().map(|_| ()));
    thread::sleep(Duration::from_millis(200));
    assert!(cancel.cancel());
    assert_eq!(handshaking.join().unwrap(), Err(Failure::Cancelled));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(!cancel.cancel());
    assert!(ended(&silent));
    // Cancelled before it starts.
    let _quiet = std::net::TcpStream::connect(address).unwrap();
    let pending = listener.next(Some(WAIT)).unwrap();
    assert!(pending.canceller().cancel());
    assert_eq!(pending.handshake().map(|_| ()), Err(Failure::Cancelled));
    // Once it finished, a cancel changes nothing.
    let url = plain_ws_url(address);
    let client = thread::spawn(move || {
        websocket::Dialer::builder()
            .build()
            .unwrap()
            .dial(Kind::WebSocket, &url, WAIT)
    });
    let pending = listener.next(Some(WAIT)).unwrap();
    let cancel = pending.canceller();
    let channel = pending.handshake().unwrap();
    assert!(!cancel.cancel());
    client.join().unwrap().unwrap().send(b"still").unwrap();
    assert_eq!(channel.receive(Some(WAIT)).unwrap().unwrap(), b"still");
}

#[test]
fn a_webtransport_handshake_can_be_abandoned_from_another_thread() {
    let id = identity();
    let listener = webtransport::Listener::builder(loopback(), server_tls(&id))
        .limits(patient())
        .build()
        .unwrap();
    let url = Url::parse(&format!(
        "https://127.0.0.1:{}/channel",
        listener.local_addr().port()
    ))
    .unwrap();
    let dial = |url: Url, pin: CertificatePin| {
        thread::spawn(move || {
            webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::from([pin])))
                .build()
                .unwrap()
                .dial(Kind::WebTransport, &url, WAIT)
        })
    };
    // A client that opens a session and no stream, which the handshake waits for.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let config = wtransport::ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(*pin(&id).as_bytes())])
        .build();
    let endpoint = {
        let _inside = runtime.enter();
        wtransport::Endpoint::client(config).unwrap()
    };
    let session = url.to_string();
    let silent = runtime.spawn(async move {
        let connection = endpoint.connect(session).await.unwrap();
        tokio::time::timeout(WAIT, connection.closed()).await
    });
    let pending = listener.next(Some(WAIT)).unwrap();
    let cancel = pending.canceller();
    let started = Instant::now();
    let handshaking = thread::spawn(move || pending.handshake().map(|_| ()));
    thread::sleep(Duration::from_millis(500));
    assert!(cancel.cancel());
    assert_eq!(handshaking.join().unwrap(), Err(Failure::Cancelled));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(!cancel.cancel());
    assert!(
        runtime.block_on(silent).unwrap().is_ok(),
        "the client's session went on"
    );
    // Cancelled before it starts: the session is refused.
    let client = dial(url.clone(), pin(&id));
    let pending = listener.next(Some(WAIT)).unwrap();
    assert!(pending.canceller().cancel());
    assert_eq!(pending.handshake().map(|_| ()), Err(Failure::Cancelled));
    assert_eq!(client.join().unwrap().unwrap_err(), Failure::Permission);
    // Once it finished, a cancel changes nothing.
    let client = dial(url, pin(&id));
    let pending = listener.next(Some(WAIT)).unwrap();
    let cancel = pending.canceller();
    let channel = pending.handshake().unwrap();
    assert!(!cancel.cancel());
    client.join().unwrap().unwrap().send(b"still").unwrap();
    assert_eq!(channel.receive(Some(WAIT)).unwrap().unwrap(), b"still");
}
