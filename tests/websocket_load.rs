//! A WebSocket channel under sustained traffic and against peers that fall behind, over real sockets on loopback.
//!
//! A read timeout expiring just as data arrives fails the read on Windows, with OS error 997, about once in three thousand
//! messages at this rate. So these keep many channels busy for long enough that a driver waiting that way would meet it.
#![cfg(feature = "websocket")]
#![allow(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::result_large_err
)]

use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use coqui_web_channel::websocket::{self, Frames};
use coqui_web_channel::{Channel, Dialer, Failure, Kind, Limits};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use url::Url;

const WAIT: Duration = Duration::from_secs(30);

struct Tls {
    server: Arc<rustls::ServerConfig>,
    client: Arc<rustls::ClientConfig>,
}

fn tls() -> Tls {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
    let certificate = params.self_signed(&key).unwrap();
    let der: CertificateDer<'static> = certificate.der().clone();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![der.clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Tls {
        server: Arc::new(server),
        client: Arc::new(client),
    }
}

/// How the two ends of the pairs a test asks for are set up.
#[derive(Clone, Copy)]
struct Setup {
    secure: bool,
    datagrams: bool,
    near: Limits,
    far: Limits,
}

impl Setup {
    fn new(secure: bool) -> Self {
        Self {
            secure,
            datagrams: false,
            near: Limits::default(),
            far: Limits::default(),
        }
    }

    /// `count` connected pairs, a dialled end and an accepted end.
    fn pairs(self, count: usize) -> Vec<(websocket::Channel, websocket::Channel)> {
        let keys = tls();
        let listener = websocket::Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            self.secure.then(|| Arc::clone(&keys.server)),
        )
        .unwrap()
        .with_limits(self.far)
        .with_frames(Frames::Binary);
        let port = listener.local_addr().unwrap().port();
        // By address: a name can try an address nothing listens on first, which takes seconds a connection on Windows.
        let scheme = if self.secure { "wss" } else { "ws" };
        let url = Url::parse(&format!("{scheme}://127.0.0.1:{port}/")).unwrap();
        let accepting = thread::spawn(move || {
            (0..count)
                .map(|_| listener.accept(Some(WAIT)).unwrap())
                .collect::<Vec<_>>()
        });
        let mut dialer = websocket::Dialer::new()
            .with_limits(self.near)
            .with_frames(Frames::Binary)
            .with_tls(keys.client);
        if self.datagrams {
            dialer = dialer.with_datagrams();
        }
        let near: Vec<_> = (0..count)
            .map(|_| dialer.dial(Kind::WebSocket, &url, WAIT).unwrap())
            .collect();
        near.into_iter().zip(accepting.join().unwrap()).collect()
    }

    fn pair(self) -> (websocket::Channel, websocket::Channel) {
        self.pairs(1).pop().unwrap()
    }
}

/// One busy test at a time: each end of a channel takes up to three file handles, and a process's limit on them can be low.
static BUSY: Mutex<()> = Mutex::new(());

/// 48 channels, 50 echoes a second on each, for `busy`: every echo comes back, in order, once.
fn every_echo_comes_back(secure: bool, busy: Duration) {
    let _alone = BUSY.lock().unwrap_or_else(PoisonError::into_inner);
    let mut running = Vec::new();
    for (client, server) in Setup::new(secure).pairs(48) {
        running.push(thread::spawn(move || {
            let mut expected = 0u64;
            while let Some(message) = server.receive(Some(WAIT)).unwrap() {
                expected += 1;
                assert_eq!(message[..8], expected.to_le_bytes(), "out of order");
                server.send(&message).unwrap();
            }
            expected
        }));
        running.push(thread::spawn(move || {
            let period = Duration::from_millis(20);
            let started = Instant::now();
            let mut sent = 0u64;
            let mut body = [0u8; 64];
            while started.elapsed() < busy {
                sent += 1;
                body[..8].copy_from_slice(&sent.to_le_bytes());
                let at = Instant::now();
                client.send(&body).unwrap();
                let echo = client.receive(Some(WAIT));
                assert_eq!(echo, Ok(Some(body.to_vec())), "echo {sent}");
                thread::sleep(period.saturating_sub(at.elapsed()));
            }
            client.close();
            // Nothing arrives beyond what was sent: the far end's count is compared with this one.
            sent
        }));
    }
    let counts: Vec<u64> = running.into_iter().map(|t| t.join().unwrap()).collect();
    for pair in counts.chunks(2) {
        assert_eq!(
            pair[0], pair[1],
            "the far end saw another number of messages"
        );
    }
}

#[test]
fn many_busy_channels_lose_nothing() {
    every_echo_comes_back(false, Duration::from_secs(10));
}

#[test]
fn many_busy_tls_channels_lose_nothing() {
    every_echo_comes_back(true, Duration::from_secs(10));
}

/// A message that says which it is throughout, at sizes on both sides of what a socket buffer takes at once.
fn numbered(index: usize) -> Vec<u8> {
    let size = [16, 900, 70_000, 1024 * 1024][index % 4];
    let mut body = vec![(index % 251) as u8; size];
    body[..8].copy_from_slice(&(index as u64).to_le_bytes());
    body
}

fn send_retrying(channel: &websocket::Channel, message: &[u8]) {
    loop {
        match channel.send(message) {
            Ok(()) => return,
            // A full queue took nothing, so this is the same message, not another.
            Err(Failure::NoProgress) => thread::sleep(Duration::from_millis(2)),
            Err(failure) => panic!("{failure:?}"),
        }
    }
}

fn large_messages_cross_each_other(secure: bool) {
    const COUNT: usize = 120;
    let (client, server) = Setup::new(secure).pair();
    let (client, server) = (Arc::new(client), Arc::new(server));
    let mut running = Vec::new();
    for (from, to) in [
        (Arc::clone(&client), Arc::clone(&server)),
        (Arc::clone(&server), Arc::clone(&client)),
    ] {
        running.push(thread::spawn(move || {
            for index in 0..COUNT {
                send_retrying(&from, &numbered(index));
            }
        }));
        running.push(thread::spawn(move || {
            // Neither end reads at first, so both sockets fill and each worker has to read and write at once.
            thread::sleep(Duration::from_millis(200));
            for index in 0..COUNT {
                let message = to.receive(Some(WAIT)).unwrap().unwrap();
                assert!(message == numbered(index), "message {index} was not itself");
            }
        }));
    }
    for thread in running {
        thread.join().unwrap();
    }
    client.close();
    assert_eq!(server.receive(Some(WAIT)), Ok(None), "and nothing else");
}

#[test]
fn large_messages_cross_each_other_whole_and_once() {
    large_messages_cross_each_other(false);
}

#[test]
fn large_tls_messages_cross_each_other_whole_and_once() {
    large_messages_cross_each_other(true);
}

/// Sends until the channel says why it ended, and how long after the first send that was.
fn send_until_it_ends(channel: &websocket::Channel) -> (Failure, Duration) {
    let big = vec![b'x'; 1024 * 1024];
    let started = Instant::now();
    let failure = loop {
        assert!(started.elapsed() < WAIT, "it kept going");
        match channel.send(&big) {
            Ok(()) => {}
            Err(Failure::NoProgress) => thread::sleep(Duration::from_millis(20)),
            // The worker has gone; why is in the inbox.
            Err(_) => break channel.receive(Some(WAIT)),
        }
        match channel.receive(Some(Duration::from_millis(1))) {
            Err(Failure::Timeout) => {}
            other => break other,
        }
    };
    (failure.unwrap_err(), started.elapsed())
}

fn a_peer_that_stops_reading_is_noticed_at_the_limit(secure: bool) {
    let limit = Duration::from_secs(1);
    let mut setup = Setup::new(secure);
    setup.near = Limits::default().with_send(limit);
    // Holding one message, this end reads nothing more until someone takes it, and nobody does.
    setup.far = Limits::default().with_pending(1);
    let (near, far) = setup.pair();
    let (failure, took) = send_until_it_ends(&near);
    assert_eq!(failure, Failure::NoProgress);
    assert!(took >= limit, "sooner than the limit: {took:?}");
    assert!(took < limit * 6, "long after the limit: {took:?}");
    drop(far);
}

#[test]
fn a_peer_that_stops_reading_is_noticed_at_the_limit_and_not_before() {
    a_peer_that_stops_reading_is_noticed_at_the_limit(false);
}

#[test]
fn a_tls_peer_that_stops_reading_is_noticed_at_the_limit_and_not_before() {
    a_peer_that_stops_reading_is_noticed_at_the_limit(true);
}

fn a_slow_peer_is_not_cut_off(secure: bool) {
    const COUNT: usize = 32;
    let mut setup = Setup::new(secure);
    // Each read frees room well within this, while sending all of it takes several times as long.
    setup.near = Limits::default().with_send(Duration::from_secs(1));
    setup.far = Limits::default().with_pending(1);
    let (near, far) = setup.pair();
    let reader = thread::spawn(move || {
        for index in 0..COUNT {
            thread::sleep(Duration::from_millis(125));
            let message = far.receive(Some(WAIT)).unwrap().unwrap();
            assert_eq!(message.len(), 1024 * 1024);
            assert_eq!(message[..8], (index as u64).to_le_bytes());
        }
        assert_eq!(far.receive(Some(WAIT)), Ok(None));
    });
    for index in 0..COUNT {
        let mut message = vec![b'x'; 1024 * 1024];
        message[..8].copy_from_slice(&(index as u64).to_le_bytes());
        send_retrying(&near, &message);
    }
    // `close` waits while the peer keeps taking what is left, however long that is altogether.
    near.close();
    reader.join().unwrap();
}

#[test]
fn a_slow_peer_that_keeps_reading_is_not_cut_off_and_close_waits_for_it() {
    a_slow_peer_is_not_cut_off(false);
}

#[test]
fn a_slow_tls_peer_that_keeps_reading_is_not_cut_off_and_close_waits_for_it() {
    a_slow_peer_is_not_cut_off(true);
}

#[test]
fn close_with_a_full_queue_sends_it_all_and_closes() {
    for secure in [false, true] {
        let (near, far) = Setup::new(secure).pair();
        let reader = thread::spawn(move || {
            let mut got = 0u64;
            while let Some(message) = far.receive(Some(WAIT)).unwrap() {
                assert_eq!(message[..8], got.to_le_bytes());
                got += 1;
            }
            got
        });
        let mut sent = 0u64;
        let mut body = [0u8; 32];
        loop {
            body[..8].copy_from_slice(&sent.to_le_bytes());
            match near.send(&body) {
                Ok(()) => sent += 1,
                Err(Failure::NoProgress) => break,
                Err(failure) => panic!("{failure:?}"),
            }
        }
        let started = Instant::now();
        near.close();
        assert!(started.elapsed() < Duration::from_secs(5), "{secure}");
        assert_eq!(reader.join().unwrap(), sent, "{secure}");
    }
}

#[test]
fn close_returns_when_a_failure_has_no_reader_to_go_to() {
    let mut setup = Setup::new(false);
    setup.near = Limits::default()
        .with_send(Duration::from_millis(300))
        .with_pending(1);
    setup.far = Limits::default().with_pending(1);
    let (near, far) = setup.pair();
    // More than this end's inbox holds, and nobody reads it, while it fills a peer that does not read either.
    for _ in 0..3 {
        far.send(b"unread").unwrap();
    }
    let big = vec![b'x'; 1024 * 1024];
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(1) {
        let _ = near.send(&big);
        thread::sleep(Duration::from_millis(10));
    }
    let (closed, returned) = mpsc::channel();
    let closer = thread::spawn(move || {
        near.close();
        closed.send(()).unwrap();
    });
    returned
        .recv_timeout(WAIT)
        .expect("close waited for a reader that will never come");
    closer.join().unwrap();
    drop(far);
}

#[test]
fn datagrams_past_one_turn_all_go_and_stay_in_order_beside_large_messages() {
    let mut setup = Setup::new(true);
    setup.datagrams = true;
    let (near, far) = setup.pair();
    let (outgoing, incoming) = (near.datagrams().unwrap(), far.datagrams().unwrap());
    for burst in 0..4u8 {
        near.send(&numbered(3)).unwrap();
        for index in 0..64u8 {
            outgoing.send(&[burst, index]).unwrap();
        }
        // A burst with nothing after it: nothing but the first send wakes the worker for these.
        for index in 0..64u8 {
            assert_eq!(
                incoming.receive(Some(WAIT)).unwrap().unwrap(),
                [burst, index]
            );
        }
        assert!(far.receive(Some(WAIT)).unwrap().unwrap() == numbered(3));
    }
    assert_eq!(outgoing.dropped() + incoming.dropped(), 0);
}
