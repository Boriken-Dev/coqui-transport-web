//! How much a channel sends, and when, over real sockets on loopback. Each binds port 0.
#![cfg(all(feature = "websocket", feature = "webtransport"))]
#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]

use std::net::SocketAddr;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

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

/// Sends until the queue stays full, which it does once the peer's reader takes nothing and both sockets have filled.
fn fill(channel: &impl Channel, message: &[u8]) -> usize {
    let until = Instant::now() + WAIT;
    let (mut sent, mut refused) = (0, 0);
    loop {
        assert!(Instant::now() < until, "the queue never filled");
        match channel.send(message) {
            Ok(()) => (sent, refused) = (sent + 1, 0),
            Err(Failure::NoProgress) if refused == 2 => return sent,
            Err(Failure::NoProgress) => {
                refused += 1;
                thread::sleep(Duration::from_millis(200));
            }
            other => panic!("{other:?}"),
        }
    }
}

/// A sender behind a reader that takes one message at most, and the 64 KiB message it sends.
fn behind_a_stalled_reader(client: Limits) -> (websocket::Channel, websocket::Channel, Vec<u8>) {
    let client = client.with_queued_bytes(256 * 1024);
    let (near, far) = websocket_pair(client, Limits::default().with_pending(1));
    (near, far, vec![7; 64 * 1024])
}

#[test]
fn a_websocket_send_waits_for_room_as_long_as_its_caller_says() {
    let (client, server, message) = behind_a_stalled_reader(Limits::default());
    let sent = fill(&client, &message);
    let started = Instant::now();
    assert_eq!(
        client.send_timeout(&message, Some(Duration::from_millis(300))),
        Err(Failure::Timeout)
    );
    assert!(started.elapsed() >= Duration::from_millis(300));
    // Once the reader takes again, a waiting send goes, and nothing before it was lost.
    let reader = thread::spawn(move || {
        let mut taken = 0;
        while let Some(message) = server.receive(Some(WAIT)).unwrap() {
            assert_eq!(message.len(), 64 * 1024);
            taken += 1;
        }
        taken
    });
    client.send_timeout(&message, Some(WAIT)).unwrap();
    client.close();
    assert_eq!(reader.join().unwrap(), sent + 1);
}

#[test]
fn a_websocket_send_waiting_for_room_ends_with_the_channel() {
    // Ended by its own send limit, and by a close.
    for (closing, ended) in [(false, Failure::PathLost), (true, Failure::Cancelled)] {
        let (client, _server, message) =
            behind_a_stalled_reader(Limits::default().with_send(Duration::from_secs(1)));
        fill(&client, &message);
        let client = Arc::new(client);
        let (done, outcome) = mpsc::channel();
        let waiting = Arc::clone(&client);
        thread::spawn(move || done.send(waiting.send_timeout(&message, None)));
        if closing {
            thread::sleep(Duration::from_millis(300));
            client.close();
        }
        let outcome = outcome
            .recv_timeout(WAIT)
            .expect("the sender was left waiting");
        assert_eq!(outcome, Err(ended), "closing: {closing}");
    }
}

#[test]
fn a_webtransport_send_waits_as_long_as_its_caller_says() {
    let (client, _server) = webtransport_pair(
        Limits::default().with_send(Duration::from_secs(5)),
        Limits::default().with_pending(1),
    );
    let message = vec![7; 256 * 1024];
    let until = Instant::now() + WAIT;
    let (outcome, waited) = loop {
        let started = Instant::now();
        match client.send_timeout(&message, Some(Duration::from_millis(300))) {
            Ok(()) => assert!(Instant::now() < until, "flow control never held a send"),
            other => break (other, started.elapsed()),
        }
    };
    assert!(
        matches!(outcome, Err(Failure::Timeout | Failure::NoProgress)),
        "{outcome:?}"
    );
    assert!(waited < Duration::from_secs(2), "{waited:?}");
}
