//! The channels as `coqui-transport` sees them: capabilities, the end of a channel, connectors and listeners, and the
//! settings a dialer or listener reports.
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

use coqui_transport::{Capabilities, Carrier, Channel, Connector as _, Delivery, Failure};
use coqui_transport_web::websocket::{self, Frames};
use coqui_transport_web::{CertificatePin, Dialer as _, Kind, NonDefault, webtransport};
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

fn identity() -> Identity {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    params.not_after = params.not_before + time::Duration::days(10);
    let certificate = params.self_signed(&key).unwrap();
    Identity {
        certificate: certificate.der().clone(),
        key: key.serialize_der(),
    }
}

fn server_tls(identity: &Identity) -> Arc<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
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

fn pin(identity: &Identity) -> CertificatePin {
    use wtransport::tls::Certificate;
    let certificate = Certificate::from_der(identity.certificate.to_vec()).unwrap();
    CertificatePin::from_bytes(*certificate.hash().as_ref())
}

fn websocket_pair(
    dialer: websocket::DialerBuilder,
    frames: Frames,
) -> (websocket::Channel, websocket::Channel) {
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .frames(frames)
        .build()
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = thread::spawn(move || listener.accept(Some(WAIT)).unwrap());
    let client = dialer
        .frames(frames)
        .build()
        .dial(
            Kind::WebSocket,
            &Url::parse(&format!("ws://127.0.0.1:{port}/")).unwrap(),
            WAIT,
        )
        .unwrap();
    (client, accepted.join().unwrap())
}

fn webtransport_pair() -> (webtransport::Channel, webtransport::Channel) {
    let id = identity();
    let listener = webtransport::Listener::builder(loopback(), server_tls(&id))
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

fn eventually(what: &str, mut holds: impl FnMut() -> bool) {
    let until = Instant::now() + WAIT;
    while !holds() {
        assert!(Instant::now() < until, "{what}");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_websocket_reports_its_messages_its_limits_and_no_datagrams_nobody_agreed_to() {
    let (client, _server) = websocket_pair(websocket::Dialer::builder(), Frames::Binary);
    let reported = client.capabilities();
    assert_eq!(reported.carrier, Carrier::Messages);
    assert_eq!(reported.datagrams, None);
    assert_eq!(reported.max_datagram, None);
    client.set_max_send(77);
    client.set_max_receive(88);
    let reported = client.capabilities();
    assert_eq!(reported.max_send, Some(77));
    assert_eq!(reported.max_receive, Some(88));
    client.set_max_message(99);
    let reported = client.capabilities();
    assert_eq!(
        (reported.max_send, reported.max_receive),
        (Some(99), Some(99))
    );
}

#[test]
fn a_websocket_with_agreed_datagrams_reports_them_as_over_the_stream() {
    let (client, _server) =
        websocket_pair(websocket::Dialer::builder().datagrams(true), Frames::Binary);
    let reported = client.capabilities();
    assert_eq!(reported.datagrams, Some(Delivery::OverStream));
    assert!(reported.max_datagram.is_some_and(|size| size > 0));
}

#[test]
fn asking_a_websocket_what_it_can_do_does_not_start_holding_datagrams() {
    let (client, server) =
        websocket_pair(websocket::Dialer::builder().datagrams(true), Frames::Binary);
    for _ in 0..3 {
        client.datagrams().unwrap().send(b"nobody asked").unwrap();
    }
    // The server asks only what it can do: that must not be a reason to keep what arrives.
    let _ = server.capabilities();
    thread::sleep(Duration::from_millis(300));
    let datagrams = server.datagrams().unwrap();
    assert_eq!(
        datagrams.receive(Some(Duration::from_millis(200))),
        Err(Failure::Timeout)
    );
    assert!(datagrams.dropped() >= 3, "{}", datagrams.dropped());
}

#[test]
fn a_webtransport_channel_reports_a_stream_and_native_datagrams_before_any_were_asked_for() {
    let (client, _server) = webtransport_pair();
    let reported = client.capabilities();
    assert_eq!(reported.carrier, Carrier::Stream);
    assert_eq!(reported.datagrams, Some(Delivery::Unreliable));
    assert!(reported.max_datagram.is_some_and(|size| size > 1000));
    client.set_max_message(1234);
    let reported = client.capabilities();
    assert_eq!(
        (reported.max_send, reported.max_receive),
        (Some(1234), Some(1234))
    );
    assert_ne!(reported, Capabilities::new());
}

#[test]
fn a_websocket_knows_it_is_closed_here_and_when_the_peer_closed() {
    let (client, server) = websocket_pair(websocket::Dialer::builder(), Frames::Binary);
    assert!(!client.is_closed() && !server.is_closed());
    client.close();
    assert!(client.is_closed());
    eventually("the peer's close was not noticed", || server.is_closed());
}

#[test]
fn a_webtransport_channel_knows_it_is_closed_here_and_when_the_peer_closed() {
    let (client, server) = webtransport_pair();
    assert!(!client.is_closed() && !server.is_closed());
    client.close();
    assert!(client.is_closed());
    eventually("the peer's close was not noticed", || server.is_closed());
}

#[test]
fn a_websocket_connector_and_listener_are_the_traits_of_coqui_transport() {
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .frames(Frames::Binary)
        .build()
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = thread::spawn(move || coqui_transport::Listener::accept(&listener).unwrap());
    let connector = websocket::Connector::new(
        websocket::Dialer::builder().frames(Frames::Binary).build(),
        Url::parse(&format!("ws://127.0.0.1:{port}/")).unwrap(),
    );
    let client = connector.connect(WAIT).unwrap();
    let server = accepted.join().unwrap();
    client.send(b"through the traits").unwrap();
    assert_eq!(
        server.receive(Some(WAIT)).unwrap().unwrap(),
        b"through the traits"
    );
}

#[test]
fn a_webtransport_connector_and_listener_are_the_traits_of_coqui_transport() {
    let id = identity();
    let listener = webtransport::Listener::builder(loopback(), server_tls(&id))
        .build()
        .unwrap();
    let port = listener.local_addr().port();
    let accepted = thread::spawn(move || coqui_transport::Listener::accept(&listener).unwrap());
    let connector = webtransport::Connector::new(
        webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::from([pin(&id)])))
            .build()
            .unwrap(),
        Url::parse(&format!("https://127.0.0.1:{port}/channel")).unwrap(),
    );
    let client = connector.connect(WAIT).unwrap();
    client.send(b"through the traits").unwrap();
    let server = accepted.join().unwrap();
    assert_eq!(
        server.receive(Some(WAIT)).unwrap().unwrap(),
        b"through the traits"
    );
}

#[test]
fn a_connector_to_a_closed_port_fails() {
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .build()
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let connector = websocket::Connector::new(
        websocket::Dialer::builder().build(),
        Url::parse(&format!("ws://127.0.0.1:{port}/")).unwrap(),
    );
    assert!(connector.connect(Duration::from_secs(2)).is_err());
}

#[test]
fn a_dialer_and_a_listener_report_each_setting_that_differs_from_the_default() {
    assert_eq!(websocket::Dialer::builder().build().non_defaults(), []);
    assert_eq!(
        websocket::Dialer::builder()
            .plain_beyond_loopback(true)
            .build()
            .non_defaults(),
        [NonDefault::new("plain_beyond_loopback", "true", "false")]
    );
    let on_loopback = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .build()
        .unwrap();
    assert_eq!(on_loopback.non_defaults(), []);
    let wide =
        websocket::Listener::builder("0.0.0.0:0".parse().unwrap(), websocket::ServerTls::Plain)
            .plain_beyond_loopback(true)
            .build()
            .unwrap();
    let reported = wide.non_defaults();
    assert_eq!(reported.len(), 1);
    assert_eq!(reported[0].setting, "plain_beyond_loopback");
    assert_eq!(reported[0].default, "false");
    assert_eq!(reported[0].value, "true");
}
