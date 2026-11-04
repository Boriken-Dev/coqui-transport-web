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

/// The bound a server reads a hello under, while the peer still owes a proof.
const SMALL: usize = 64 * 1024;
/// The bound for everything after the proof.
const FULL: usize = 1 << 20;

/// A server reads a hello under the small bound, stages the full bound to start after one more message, and replies. The client then
/// sends `first` and, when given, `second` at once, and the server's reader waits so its driver can read both ahead of it.
fn after_a_staged_bound(
    client: &impl Channel,
    server: &impl Channel,
    first: &[u8],
    second: Option<&[u8]>,
) -> Vec<Result<usize, Failure>> {
    server.set_max_receive(SMALL);
    client.send(b"hello").unwrap();
    assert_eq!(server.receive(Some(WAIT)), Ok(Some(b"hello".to_vec())));
    server.set_max_receive_after(1, FULL).unwrap();
    server.send(b"reply").unwrap();
    assert_eq!(client.receive(Some(WAIT)), Ok(Some(b"reply".to_vec())));
    client.send(first).unwrap();
    if let Some(second) = second {
        client.send(second).unwrap();
    }
    thread::sleep(Duration::from_millis(100));
    let mut read = vec![length(server)];
    if second.is_some() && read[0].is_ok() {
        read.push(length(server));
    }
    read
}

/// The large message comes right behind the small one, and the driver reads it before the reader has taken the small one: it is
/// still judged by its own position, under the full bound.
fn a_large_message_right_after_the_small_one_is_taken(
    client: &impl Channel,
    server: &impl Channel,
) {
    let large = vec![7; FULL];
    assert_eq!(
        after_a_staged_bound(client, server, &[1; 32], Some(&large)),
        [Ok(32), Ok(FULL)]
    );
}

/// The large message comes in place of the small one, so it is judged under the small bound.
fn a_large_message_in_place_of_the_small_one_is_refused(
    client: &impl Channel,
    server: &impl Channel,
) {
    let large = vec![7; FULL];
    assert_eq!(
        after_a_staged_bound(client, server, &large, None),
        [Err(Failure::Protocol)]
    );
}

#[test]
fn a_websocket_takes_a_large_message_right_after_the_small_one_under_a_staged_bound() {
    let (client, server) = websocket_pair(Limits::default(), Limits::default());
    a_large_message_right_after_the_small_one_is_taken(&client, &server);
}

#[test]
fn a_webtransport_channel_takes_a_large_message_right_after_the_small_one_under_a_staged_bound() {
    let (client, server) = webtransport_pair(Limits::default(), Limits::default());
    a_large_message_right_after_the_small_one_is_taken(&client, &server);
}

#[test]
fn a_websocket_refuses_a_large_message_in_place_of_the_small_one_under_a_staged_bound() {
    let (client, server) = websocket_pair(Limits::default(), Limits::default());
    a_large_message_in_place_of_the_small_one_is_refused(&client, &server);
    // Refused as any message over its bound is: a close with 1009, which the sender reads as refused rather than lost.
    assert_eq!(client.receive(Some(WAIT)), Err(Failure::Protocol));
}

#[test]
fn a_webtransport_channel_refuses_a_large_message_in_place_of_the_small_one_under_a_staged_bound() {
    let (client, server) = webtransport_pair(Limits::default(), Limits::default());
    a_large_message_in_place_of_the_small_one_is_refused(&client, &server);
}

#[test]
fn a_boxed_channel_stages_a_bound_through_its_driver() {
    let (client, server) = websocket_pair(Limits::default(), Limits::default());
    let server: Box<dyn Channel> = Box::new(server);
    a_large_message_right_after_the_small_one_is_taken(&client, &server);
    let (client, server) = webtransport_pair(Limits::default(), Limits::default());
    let server: Box<dyn Channel> = Box::new(server);
    a_large_message_in_place_of_the_small_one_is_refused(&client, &server);
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

/// A server that read a small hello, then raises its bound, takes one 1 MiB message and stops reading: the client's sends
/// fill every buffer between them and then wait, and neither end sees the other as gone.
#[test]
fn a_websocket_reader_that_stops_holds_its_sender_back() {
    let (client, server) = websocket_pair(Limits::default(), Limits::default());
    server.set_max_receive(1024);
    client.send(b"hello").unwrap();
    assert_eq!(server.receive(Some(WAIT)).unwrap().unwrap(), b"hello");
    // Raised before the client sends: a bound reaches only what is read after it.
    server.set_max_receive(64 << 20);
    client.set_max_send(64 << 20);
    let message = vec![3; 1 << 20];
    client
        .send_timeout(&message, Some(Duration::from_millis(700)))
        .unwrap();
    let (opened, taken) = mpsc::channel();
    let (done, finished) = mpsc::channel::<()>();
    let holding = thread::spawn(move || {
        let first = server.receive(Some(WAIT));
        opened.send(()).unwrap();
        // Reads no more until the sender has given up.
        let _ = finished.recv();
        let rest = server.receive(Some(Duration::ZERO));
        (first, rest)
    });
    taken.recv_timeout(Duration::from_secs(60)).unwrap();
    let started = Instant::now();
    let mut ended = None;
    for _ in 0..1000 {
        if let Err(failure) = client.send_timeout(&message, Some(Duration::from_millis(700))) {
            ended = Some(failure);
            break;
        }
    }
    assert_eq!(ended, Some(Failure::Timeout));
    assert!(started.elapsed() < Duration::from_secs(60));
    done.send(()).unwrap();
    let (first, rest) = holding.join().unwrap();
    assert_eq!(first.map(|m| m.map(|m| m.len())), Ok(Some(1 << 20)));
    // What waits for the reader is the next message, not an end.
    assert_eq!(rest.map(|m| m.map(|m| m.len())), Ok(Some(1 << 20)));
}

/// A reader that stops for longer than twice the idle limit leaves both ends open: the end not reading still pings, and its
/// own silence counts for nothing while it cannot listen.
#[test]
fn a_websocket_reader_stalled_past_the_idle_limit_is_not_taken_for_gone() {
    let idle = Duration::from_millis(200);
    let (client, server) = websocket_pair(
        Limits::default().with_idle(idle),
        Limits::default().with_idle(idle).with_pending(1),
    );
    for n in 0..4 {
        client.send(&[n; 16]).unwrap();
    }
    thread::sleep(idle * 6);
    for n in 0..4 {
        assert_eq!(server.receive(Some(WAIT)), Ok(Some(vec![n; 16])));
    }
    client.send(b"after").unwrap();
    assert_eq!(server.receive(Some(WAIT)), Ok(Some(b"after".to_vec())));
    server.send(b"back").unwrap();
    assert_eq!(client.receive(Some(WAIT)), Ok(Some(b"back".to_vec())));
}

/// A message over the bound its reader set ends the channel at both ends as refused, while the sender still has more on
/// the way: neither end reads the other as gone.
#[test]
fn a_websocket_message_over_the_readers_bound_is_refused_at_both_ends() {
    let (client, server) = websocket_pair(Limits::default(), Limits::default());
    server.set_max_receive(1024);
    client.send(b"hello").unwrap();
    assert_eq!(server.receive(Some(WAIT)).unwrap().unwrap(), b"hello");
    let message = vec![3; 1 << 20];
    let until = Instant::now() + WAIT;
    let refused = loop {
        assert!(Instant::now() < until, "the client was never refused");
        if let Err(failure) = client.send_timeout(&message, Some(Duration::from_millis(700))) {
            break failure;
        }
    };
    assert_eq!(refused, Failure::Protocol);
    assert_eq!(server.receive(Some(WAIT)), Err(Failure::Protocol));
    assert_eq!(client.receive(Some(WAIT)), Err(Failure::Protocol));
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
