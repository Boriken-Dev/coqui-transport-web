//! A send observed to completion, a channel ended without draining, and a handshake bounded by a caller's deadline, over real
//! sockets on loopback. Each binds port 0.
#![cfg(feature = "websocket")]
#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]

use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use coqui_transport_web::websocket::{self, Frames};
use coqui_transport_web::{Channel, Dialer, Failure, Kind, Limits};
use url::Url;

const WAIT: Duration = Duration::from_secs(30);
/// More than a loopback connection's two socket buffers hold, so a peer that stops reading holds it back.
const BIG: usize = 64 * 1024 * 1024;

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// A connected pair, client first. The server reads one message ahead at most, so once it holds one it stops reading.
fn pair() -> (websocket::Channel, websocket::Channel) {
    let mut limits = Limits::default();
    limits.max_message = 2 * BIG;
    limits.queued_bytes = 2 * BIG;
    let mut server = limits;
    server.pending = 1;
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .limits(server)
        .frames(Frames::Binary)
        .build()
        .unwrap();
    let url = Url::parse(&format!("ws://{}/", listener.local_addr().unwrap())).unwrap();
    let accepted = thread::spawn(move || listener.accept(Some(WAIT)).unwrap());
    let near = websocket::Dialer::builder()
        .limits(limits)
        .frames(Frames::Binary)
        .build()
        .unwrap()
        .dial(Kind::WebSocket, &url, WAIT)
        .unwrap();
    (near, accepted.join().unwrap())
}

/// Sends `first`, which the server then holds, so that it reads nothing more until it is taken.
fn stall(near: &websocket::Channel, far: &websocket::Channel) {
    near.send(b"first").unwrap();
    // The server has the first message in hand once it is ready to give it, and reads no further.
    thread::sleep(Duration::from_millis(300));
    assert!(!far.is_closed());
}

#[test]
fn a_send_is_completed_when_the_socket_has_taken_it_whole() {
    let (near, far) = pair();
    stall(&near, &far);
    let started = Instant::now();
    let big = vec![7_u8; BIG];
    // Queued at once, as `send` would; not taken by the socket while the peer reads nothing.
    assert_eq!(
        near.send_completed_until(&big, started + Duration::from_millis(400)),
        Err(Failure::Timeout)
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    // The message stayed queued, and goes once the peer reads.
    assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), b"first");
    assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap().len(), BIG);
    near.send_completed_until(b"small", Instant::now() + WAIT)
        .unwrap();
    assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), b"small");
}

#[test]
fn a_completed_send_returns_without_waiting_for_the_peer_to_read() {
    let (near, far) = pair();
    let started = Instant::now();
    near.send_completed_until(b"hello", started + WAIT).unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), b"hello");
}

#[test]
fn abort_without_drain_ends_a_channel_whose_peer_takes_nothing() {
    let (near, far) = pair();
    stall(&near, &far);
    near.send(&vec![1_u8; BIG]).unwrap();
    let near = Arc::new(near);
    let waiting = {
        let near = Arc::clone(&near);
        thread::spawn(move || near.send_completed_until(b"behind", Instant::now() + WAIT))
    };
    thread::sleep(Duration::from_millis(300));
    let started = Instant::now();
    near.abort_without_drain();
    // `close` would send the whole message first, for as long as `Limits::send` allows a peer that reads nothing.
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(near.is_closed());
    assert_eq!(waiting.join().unwrap(), Err(Failure::Cancelled));
    assert!(near.send(b"after").is_err());
    // The peer sees the connection end, and never the message that was cut off.
    assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), b"first");
    let after = far.receive(Some(WAIT));
    assert!(
        matches!(after, Ok(None) | Err(_)),
        "a cut-off message arrived"
    );
    // Ending it again does nothing.
    near.abort_without_drain();
    near.close();
}

#[test]
fn a_handshake_ends_at_the_callers_deadline_when_that_is_before_the_limit() {
    let listener = websocket::Listener::builder(loopback(), websocket::ServerTls::Plain)
        .build()
        .unwrap();
    let address = listener.local_addr().unwrap();
    // Connects and says nothing, so the handshake has nothing to read.
    let silent = TcpStream::connect(address).unwrap();
    let pending = listener.next(Some(WAIT)).unwrap();
    let started = Instant::now();
    let outcome = pending.handshake_until(started + Duration::from_millis(300));
    // The default handshake limit is ten seconds.
    assert_eq!(outcome.err(), Some(Failure::Timeout));
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(silent);
}
