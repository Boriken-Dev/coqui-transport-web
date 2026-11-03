//! How much a channel sends, and when, over real sockets on loopback. Each binds port 0.
#![cfg(all(feature = "websocket", feature = "webtransport"))]
#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use coqui_web::{CertificatePin, Channel, Dialer, Failure, Kind, Limits, websocket, webtransport};
use rustls::pki_types::PrivatePkcs8KeyDer;
use url::Url;

const WAIT: Duration = Duration::from_secs(10);

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// A server configuration and the pin of its certificate.
fn server_tls() -> (Arc<rustls::ServerConfig>, CertificatePin) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    // What pinning by hash requires: at most 14 days.
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    params.not_after = params.not_before + time::Duration::days(10);
    let certificate = params.self_signed(&key).unwrap();
    let pin = wtransport::tls::Certificate::from_der(certificate.der().to_vec()).unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.der().clone()],
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    (
        Arc::new(tls),
        CertificatePin::from_bytes(*pin.hash().as_ref()),
    )
}

/// A connected WebSocket pair, client first, with `client` and `server` limits.
fn websocket_pair(client: Limits, server: Limits) -> (websocket::Channel, websocket::Channel) {
    let listener = websocket::Listener::bind(loopback(), None)
        .unwrap()
        .with_limits(server)
        .with_frames(websocket::Frames::Binary);
    let url = Url::parse(&format!("ws://{}/", listener.local_addr().unwrap())).unwrap();
    let accepted = thread::spawn(move || listener.accept(Some(WAIT)).unwrap());
    let near = websocket::Dialer::new()
        .with_limits(client)
        .with_frames(websocket::Frames::Binary)
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    (near, accepted.join().unwrap())
}

/// A connected WebTransport pair, client first, with `client` and `server` limits.
fn webtransport_pair(
    client: Limits,
    server: Limits,
) -> (webtransport::Channel, webtransport::Channel) {
    let (tls, pin) = server_tls();
    let listener = webtransport::Listener::bind(loopback(), tls)
        .unwrap()
        .with_limits(server);
    let url = Url::parse(&format!(
        "https://127.0.0.1:{}/",
        listener.local_addr().port()
    ))
    .unwrap();
    let accepted = thread::spawn(move || listener.accept(Some(WAIT)).unwrap());
    let near = webtransport::Dialer::pinned(&[pin])
        .unwrap()
        .with_limits(client)
        .dial(Kind::WebTransport, &url, WAIT)
        .unwrap();
    // A server has no stream to accept until the client's carries something.
    near.send(b"open").unwrap();
    let far = accepted.join().unwrap();
    assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), b"open");
    (near, far)
}

fn length(channel: &impl Channel) -> Result<usize, Failure> {
    Ok(channel.receive(Some(WAIT))?.unwrap().len())
}

/// A server reading under a small bound still answers up to the client's, and a send bound leaves reading alone.
fn bounds_go_each_way(client: &impl Channel, server: &impl Channel) {
    server.set_max_receive(64);
    client.send(&[b'q'; 32]).unwrap();
    assert_eq!(length(server), Ok(32));
    server.send(&[b'a'; 1000]).unwrap();
    assert_eq!(length(client), Ok(1000));
    server.set_max_send(16);
    assert_eq!(server.send(&[b'a'; 17]), Err(Failure::Protocol));
    server.send(&[b'a'; 16]).unwrap();
    assert_eq!(length(client), Ok(16));
    client.send(&[b'q'; 64]).unwrap();
    assert_eq!(length(server), Ok(64));
    client.send(&[b'q'; 65]).unwrap();
    assert_eq!(length(server), Err(Failure::Protocol));
}

#[test]
fn a_websocket_bounds_what_it_reads_and_what_it_sends_apart() {
    let (client, server) = websocket_pair(Limits::default(), Limits::default());
    bounds_go_each_way(&client, &server);
}

#[test]
fn a_webtransport_channel_bounds_what_it_reads_and_what_it_sends_apart() {
    let (client, server) = webtransport_pair(Limits::default(), Limits::default());
    bounds_go_each_way(&client, &server);
}

#[test]
fn a_boxed_channel_passes_both_bounds_on() {
    let (client, server) = websocket_pair(Limits::default(), Limits::default());
    let server: Box<dyn Channel> = Box::new(server);
    bounds_go_each_way(&client, &server);
}
