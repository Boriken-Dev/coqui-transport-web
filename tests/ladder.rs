//! The port and the ladder over real sockets on loopback: a UDP path that a forwarder in the middle can lose, count or black-hole.
#![allow(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::result_large_err
)]

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use coqui_web_channel::webrtc::{Port, Settings, Signaling};
use coqui_web_channel::websocket::{self, Frames};
use coqui_web_channel::{
    CertificatePin, Channel, Datagrams, Delivery, Dialer, Failure, Kind, webtransport,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use url::Url;

const WAIT: Duration = Duration::from_secs(30);
/// Long enough to see nothing come back from a loopback socket.
const QUIET: Duration = Duration::from_millis(800);

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// A certificate a pinning dialer accepts, and its pin.
fn tls() -> (Arc<rustls::ServerConfig>, CertificatePin) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    params.not_after = params.not_before + time::Duration::days(10);
    let certificate = params.self_signed(&key).unwrap();
    let der: CertificateDer<'static> = certificate.der().clone();
    let hash = wtransport::tls::Certificate::from_der(der.to_vec())
        .unwrap()
        .hash();
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![der],
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    (Arc::new(server), CertificatePin::from_bytes(*hash.as_ref()))
}

/// A UDP forwarder in front of a port, as a path that can lose things. Each client gets a socket of its own on the far side, so the
/// port sees a source this test knows.
struct Forwarder {
    address: SocketAddr,
    /// Where it forwards to, which a test may set once the port is bound.
    target: Arc<Mutex<SocketAddr>>,
    /// Of every this many packets the first is dropped; 0 drops none.
    drop_each: Arc<AtomicUsize>,
    black_hole: Arc<AtomicBool>,
    /// Packets to and from the port, and those at least [`Self::LARGE`] bytes.
    upstream: Arc<AtomicU64>,
    downstream: Arc<AtomicU64>,
    large_upstream: Arc<AtomicU64>,
    large_downstream: Arc<AtomicU64>,
    /// The source the port sees.
    sources: Arc<Mutex<Vec<SocketAddr>>>,
    stop: Arc<AtomicBool>,
}

impl Forwarder {
    const LARGE: usize = 1000;

    fn new(target: SocketAddr) -> Self {
        let near = UdpSocket::bind(loopback()).unwrap();
        near.set_nonblocking(true).unwrap();
        let address = near.local_addr().unwrap();
        let this = Self {
            address,
            target: Arc::new(Mutex::new(target)),
            drop_each: Arc::default(),
            black_hole: Arc::default(),
            upstream: Arc::default(),
            downstream: Arc::default(),
            large_upstream: Arc::default(),
            large_downstream: Arc::default(),
            sources: Arc::default(),
            stop: Arc::default(),
        };
        let drop_each = Arc::clone(&this.drop_each);
        let black_hole = Arc::clone(&this.black_hole);
        let upstream = Arc::clone(&this.upstream);
        let downstream = Arc::clone(&this.downstream);
        let large_upstream = Arc::clone(&this.large_upstream);
        let large_downstream = Arc::clone(&this.large_downstream);
        let sources = Arc::clone(&this.sources);
        let stop = Arc::clone(&this.stop);
        let target = Arc::clone(&this.target);
        thread::spawn(move || {
            let mut far: HashMap<SocketAddr, UdpSocket> = HashMap::new();
            let mut buffer = vec![0_u8; 65536];
            let mut counted = 0_usize;
            let mut dropping = |drop_each: &AtomicUsize| {
                let each = drop_each.load(Ordering::SeqCst);
                counted += 1;
                each > 0 && counted.is_multiple_of(each)
            };
            while !stop.load(Ordering::SeqCst) {
                let mut idle = true;
                while let Ok((count, client)) = near.recv_from(&mut buffer) {
                    idle = false;
                    let socket = far.entry(client).or_insert_with(|| {
                        let socket = UdpSocket::bind(loopback()).unwrap();
                        socket.set_nonblocking(true).unwrap();
                        socket
                            .connect(*target.lock().unwrap_or_else(PoisonError::into_inner))
                            .unwrap();
                        sources
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push(socket.local_addr().unwrap());
                        socket
                    });
                    if black_hole.load(Ordering::SeqCst) || dropping(&drop_each) {
                        continue;
                    }
                    upstream.fetch_add(1, Ordering::SeqCst);
                    if count >= Self::LARGE {
                        large_upstream.fetch_add(1, Ordering::SeqCst);
                    }
                    let _ = socket.send(&buffer[..count]);
                }
                for (client, socket) in &far {
                    while let Ok(count) = socket.recv(&mut buffer) {
                        idle = false;
                        if black_hole.load(Ordering::SeqCst) || dropping(&drop_each) {
                            continue;
                        }
                        downstream.fetch_add(1, Ordering::SeqCst);
                        if count >= Self::LARGE {
                            large_downstream.fetch_add(1, Ordering::SeqCst);
                        }
                        let _ = near.send_to(&buffer[..count], client);
                    }
                }
                if idle {
                    thread::sleep(Duration::from_millis(1));
                }
            }
        });
        this
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// A port and a TCP listener on one number.
fn on_one_number(settings: Settings) -> (Port, websocket::Listener) {
    for _ in 0..64 {
        let port = Port::bind(loopback(), settings).unwrap();
        // Whichever number UDP got may be taken on TCP.
        if TcpListener::bind(port.local_addr()).is_ok()
            && let Ok(listener) = websocket::Listener::bind(port.local_addr(), None)
        {
            let listener = listener.with_frames(Frames::Binary).with_webrtc(&port);
            return (port, listener);
        }
    }
    panic!("no number free on both UDP and TCP");
}

struct Pair {
    near: websocket::Channel,
    far: websocket::Channel,
}

fn dial(listener: &websocket::Listener, settings: Option<Settings>) -> Pair {
    let url = Url::parse(&format!("ws://{}/", listener.local_addr().unwrap())).unwrap();
    thread::scope(|scope| {
        let accepted = scope.spawn(|| listener.accept(Some(WAIT)).unwrap());
        let mut dialer = websocket::Dialer::new().with_frames(Frames::Binary);
        dialer = match settings {
            Some(settings) => dialer.with_webrtc(settings),
            None => dialer.with_datagrams(),
        };
        let near = dialer.dial(Kind::WebSocket, &url, WAIT).unwrap();
        Pair {
            near,
            far: accepted.join().unwrap(),
        }
    })
}

/// Sends until one comes back: the first may go before the far side reads.
fn arrives(from: &dyn Datagrams, to: &dyn Datagrams, payload: &[u8]) {
    let deadline = Instant::now() + WAIT;
    loop {
        from.send(payload).unwrap();
        match to.receive(Some(Duration::from_millis(50))) {
            Ok(Some(got)) if got == payload => {
                while let Ok(Some(_)) = to.receive(Some(Duration::from_millis(20))) {}
                return;
            }
            _ if Instant::now() < deadline => {}
            other => panic!("nothing arrived: {other:?}"),
        }
    }
}

fn await_change(changes: &mpsc::Receiver<Delivery>) -> Delivery {
    changes.recv_timeout(WAIT).expect("the path did not change")
}

#[test]
fn a_channel_climbs_mid_use_with_an_event_and_the_limit_follows_the_path() {
    let (_port, listener) = on_one_number(Settings::default());
    let Pair { near, far } = dial(&listener, Some(Settings::default()));
    let near_datagrams = near.datagrams().unwrap();
    let changes = near_datagrams.path_changes().unwrap();
    let far_datagrams = far.datagrams().unwrap();
    let far_changes = far_datagrams.path_changes().unwrap();

    // Over the WebSocket from the start, whatever the data channel is doing.
    near.send(b"first").unwrap();
    assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), b"first");
    assert_eq!(near_datagrams.max_size(), Some(64 * 1024));

    assert_eq!(await_change(&changes), Delivery::Unreliable);
    assert_eq!(await_change(&far_changes), Delivery::Unreliable);
    assert_eq!(near_datagrams.delivery(), Delivery::Unreliable);
    assert_eq!(far_datagrams.delivery(), Delivery::Unreliable);
    let limit = near_datagrams.max_size().unwrap();
    assert!(limit <= 1232, "{limit} does not fit a minimum path");
    assert_eq!(far_datagrams.max_size(), Some(limit));

    arrives(near_datagrams, far_datagrams, b"out");
    arrives(far_datagrams, near_datagrams, b"back");
    arrives(near_datagrams, far_datagrams, &vec![7; limit]);
    // str0m writes nothing for an empty message, so one is refused rather than vanishing.
    assert_eq!(near_datagrams.send(b""), Err(Failure::Protocol));

    // A send over the limit is refused rather than moved, and the channel goes on.
    assert_eq!(
        near_datagrams.send(&vec![7; limit + 1]),
        Err(Failure::Protocol)
    );
    near.send(b"second").unwrap();
    assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), b"second");
    arrives(near_datagrams, far_datagrams, b"still");
    near.close();
    assert_eq!(far.receive(Some(WAIT)).unwrap(), None);
    far.close();
}

#[test]
fn nothing_happens_until_someone_asks_for_datagrams() {
    let (port, listener) = on_one_number(Settings::default());
    let Pair { near, far } = dial(&listener, Some(Settings::default()));
    let datagrams = near.datagrams().unwrap();
    let changes = datagrams.path_changes().unwrap();
    // The far side has an offer and has not asked: no session, and the near side stays where it is.
    assert_eq!(
        changes.recv_timeout(QUIET),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    assert_eq!(port.data_channels(), 0);
    let _ = far.datagrams().unwrap();
    assert_eq!(await_change(&changes), Delivery::Unreliable);
    assert_eq!(port.data_channels(), 1);
}

#[test]
fn a_blocked_udp_path_costs_only_the_attempt() {
    let hole = UdpSocket::bind(loopback()).unwrap();
    let attempt = Duration::from_millis(1500);
    let (port, listener) = on_one_number(
        Settings::default()
            .with_attempt(attempt)
            .with_public_address(hole.local_addr().unwrap()),
    );
    let Pair { near, far } = dial(&listener, Some(Settings::default().with_attempt(attempt)));
    let near_datagrams = near.datagrams().unwrap();
    let far_datagrams = far.datagrams().unwrap();
    let changes = near_datagrams.path_changes().unwrap();

    // Working the whole time, not just after the attempt ends.
    arrives(near_datagrams, far_datagrams, b"during");
    hole.set_read_timeout(Some(WAIT)).unwrap();
    let mut buffer = [0_u8; 2048];
    hole.recv_from(&mut buffer)
        .expect("the attempt never tried the path");

    assert_eq!(
        changes.recv_timeout(attempt + QUIET),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    assert_eq!(near_datagrams.delivery(), Delivery::OverStream);
    assert_eq!(far_datagrams.delivery(), Delivery::OverStream);
    assert_eq!(port.data_channels(), 0);
    arrives(near_datagrams, far_datagrams, b"after");
    arrives(far_datagrams, near_datagrams, b"back");
    near.send(b"message").unwrap();
    assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), b"message");
}

#[test]
fn turned_off_a_channel_asks_for_plain_datagrams_and_never_signals() {
    let (port, listener) = on_one_number(Settings::default());
    let Pair { near, far } = dial(&listener, Some(Settings::default().with_enabled(false)));
    let near_datagrams = near.datagrams().unwrap();
    let far_datagrams = far.datagrams().unwrap();
    assert!(near_datagrams.path_changes().is_none());
    assert!(far_datagrams.path_changes().is_none());
    arrives(near_datagrams, far_datagrams, b"plain");
    assert_eq!(port.data_channels(), 0);
    assert_eq!(near_datagrams.delivery(), Delivery::OverStream);
}

#[test]
fn a_listener_with_no_port_gives_plain_datagrams_to_a_client_that_would_climb() {
    let listener = websocket::Listener::bind(loopback(), None)
        .unwrap()
        .with_frames(Frames::Binary);
    let Pair { near, far } = dial(&listener, Some(Settings::default()));
    let near_datagrams = near.datagrams().unwrap();
    let far_datagrams = far.datagrams().unwrap();
    assert!(near_datagrams.path_changes().is_none());
    arrives(near_datagrams, far_datagrams, b"plain");
    near.send(b"message").unwrap();
    assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), b"message");
}

#[test]
fn a_listener_with_a_port_gives_a_plain_client_what_it_always_did() {
    let (port, listener) = on_one_number(Settings::default());
    let Pair { near, far } = dial(&listener, None);
    let near_datagrams = near.datagrams().unwrap();
    let far_datagrams = far.datagrams().unwrap();
    assert!(far_datagrams.path_changes().is_none());
    arrives(near_datagrams, far_datagrams, b"plain");
    assert_eq!(port.data_channels(), 0);
}

#[test]
fn a_path_that_dies_goes_back_to_the_websocket_with_an_event_and_no_second_attempt() {
    let forwarder = Forwarder::reserve();
    let (port, listener) = on_forwarded(&forwarder);
    let Pair { near, far } = dial(&listener, Some(Settings::default()));
    let near_datagrams = near.datagrams().unwrap();
    let far_datagrams = far.datagrams().unwrap();
    let changes = near_datagrams.path_changes().unwrap();
    let far_changes = far_datagrams.path_changes().unwrap();
    assert_eq!(await_change(&changes), Delivery::Unreliable);
    assert_eq!(await_change(&far_changes), Delivery::Unreliable);
    arrives(near_datagrams, far_datagrams, b"on the path");

    forwarder.black_hole.store(true, Ordering::SeqCst);
    assert_eq!(await_change(&changes), Delivery::OverStream);
    assert_eq!(near_datagrams.delivery(), Delivery::OverStream);
    assert_eq!(near_datagrams.max_size(), Some(64 * 1024));
    assert_eq!(await_change(&far_changes), Delivery::OverStream);
    arrives(near_datagrams, far_datagrams, b"back on the socket");
    arrives(far_datagrams, near_datagrams, b"and the other way");
    assert_eq!(port.data_channels(), 0);
    assert_eq!(
        changes.recv_timeout(QUIET),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
}

/// A port whose candidate is `forwarder`, on the number it forwards to.
fn on_forwarded(forwarder: &Forwarder) -> (Port, websocket::Listener) {
    let settings = Settings::default().with_public_address(forwarder.address);
    let port = Port::bind(loopback(), settings).unwrap();
    *forwarder
        .target
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = port.local_addr();
    let listener = websocket::Listener::bind(loopback(), None)
        .unwrap()
        .with_frames(Frames::Binary)
        .with_webrtc(&port);
    (port, listener)
}

fn answer_with(signal: &[u8], change: impl Fn(&str) -> String) -> Vec<u8> {
    let mut out = vec![signal[0]];
    out.extend_from_slice(change(core::str::from_utf8(&signal[1..]).unwrap()).as_bytes());
    out
}

/// Carries an offer and its answer the way a caller with a sealed link would, changing the answer on its way.
fn carry(pair: &Pair, change: impl Fn(&str) -> String) {
    let offer = pair.near.next_signal(Some(WAIT)).unwrap().unwrap();
    pair.far.deliver_signal(&offer).unwrap();
    let answer = pair.far.next_signal(Some(WAIT)).unwrap().unwrap();
    pair.near
        .deliver_signal(&answer_with(&answer, change))
        .unwrap();
}

#[test]
fn signals_a_caller_carries_open_it_and_a_changed_fingerprint_never_does() {
    let settings = Settings::default()
        .with_signaling(Signaling::ByCaller)
        .with_attempt(Duration::from_secs(2));
    let (_port, listener) = on_one_number(settings);

    let pair = dial(&listener, Some(settings));
    let near = pair.near.datagrams().unwrap();
    let far = pair.far.datagrams().unwrap();
    let changes = near.path_changes().unwrap();
    carry(&pair, str::to_owned);
    assert_eq!(await_change(&changes), Delivery::Unreliable);
    arrives(near, far, b"bound");

    let tampered = dial(&listener, Some(settings));
    let near = tampered.near.datagrams().unwrap();
    let far = tampered.far.datagrams().unwrap();
    let changes = near.path_changes().unwrap();
    carry(&tampered, |answer| {
        let start = answer.find("a=fingerprint:sha-256 ").unwrap() + 22;
        let flipped = if answer[start..].starts_with('A') {
            "B"
        } else {
            "A"
        };
        format!("{}{flipped}{}", &answer[..start], &answer[start + 1..])
    });
    assert_eq!(
        changes.recv_timeout(Duration::from_secs(4)),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    assert_eq!(near.delivery(), Delivery::OverStream);
    arrives(near, far, b"still over the socket");
}

#[test]
fn a_caller_carrying_signals_ignores_one_arriving_on_the_socket() {
    let attempt = Duration::from_millis(1500);
    let (port, listener) = on_one_number(
        Settings::default()
            .with_signaling(Signaling::ByCaller)
            .with_attempt(attempt),
    );
    let pair = dial(&listener, Some(Settings::default().with_attempt(attempt)));
    let near = pair.near.datagrams().unwrap();
    let far = pair.far.datagrams().unwrap();
    let changes = near.path_changes().unwrap();
    assert_eq!(
        changes.recv_timeout(attempt + QUIET),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    assert_eq!(port.data_channels(), 0);
    assert_eq!(
        pair.far.next_signal(Some(Duration::ZERO)),
        Err(Failure::Timeout)
    );
    arrives(near, far, b"over the socket");
    assert_eq!(pair.near.deliver_signal(b"x"), Err(Failure::Unsupported));
}

#[test]
fn a_candidate_a_peer_names_elsewhere_gets_nothing_from_either_side() {
    let Ok(victim) = UdpSocket::bind("127.0.0.2:0") else {
        return;
    };
    victim.set_read_timeout(Some(QUIET)).unwrap();
    let elsewhere = victim.local_addr().unwrap();
    let line = format!(
        "a=candidate:9 1 udp 2130706431 {} {} typ host\r\n",
        elsewhere.ip(),
        elsewhere.port()
    );
    let settings = Settings::default()
        .with_signaling(Signaling::ByCaller)
        .with_attempt(Duration::from_secs(2));
    let (_port, listener) = on_one_number(settings);
    let mut buffer = [0_u8; 2048];

    // An offer naming someone else: the far side never writes there, and the channel still opens by where it really is.
    let pair = dial(&listener, Some(settings));
    let near = pair.near.datagrams().unwrap();
    let _far = pair.far.datagrams().unwrap();
    let changes = near.path_changes().unwrap();
    let offer = pair.near.next_signal(Some(WAIT)).unwrap().unwrap();
    pair.far
        .deliver_signal(&answer_with(&offer, |sdp| {
            let at = sdp.find("m=application").unwrap();
            let end = at + sdp[at..].find("\r\n").unwrap() + 2;
            format!("{}{line}{}", &sdp[..end], &sdp[end..])
        }))
        .unwrap();
    let answer = pair.far.next_signal(Some(WAIT)).unwrap().unwrap();
    pair.near.deliver_signal(&answer).unwrap();
    assert_eq!(await_change(&changes), Delivery::Unreliable);
    assert!(
        victim.recv_from(&mut buffer).is_err(),
        "an offer's candidate drew a packet"
    );

    // An answer naming someone else: refused, nothing sent there, and the channel stays on the socket.
    let lying = |sdp: &str| {
        let at = sdp.find("a=candidate:").unwrap();
        let end = at + sdp[at..].find("\r\n").unwrap() + 2;
        format!("{}{line}{}", &sdp[..at], &sdp[end..])
    };
    let refused = dial(&listener, Some(settings));
    let near = refused.near.datagrams().unwrap();
    let _far = refused.far.datagrams().unwrap();
    let changes = near.path_changes().unwrap();
    carry(&refused, lying);
    assert!(
        victim.recv_from(&mut buffer).is_err(),
        "an answer's candidate drew a packet"
    );
    assert_eq!(
        changes.recv_timeout(Duration::ZERO),
        Err(mpsc::RecvTimeoutError::Timeout)
    );

    // The same answer allowed: this is what the check above would have seen, had the refusal not been there.
    let allowed = dial(&listener, Some(settings.with_any_candidate()));
    let _near = allowed.near.datagrams().unwrap();
    let _far = allowed.far.datagrams().unwrap();
    carry(&allowed, lying);
    victim.set_read_timeout(Some(WAIT)).unwrap();
    victim
        .recv_from(&mut buffer)
        .expect("the control: an allowed candidate is written to");
}

/// A STUN binding request with this username and an integrity value nobody computed.
fn stun_request(username: &str) -> Vec<u8> {
    let mut attributes = Vec::new();
    attributes.extend_from_slice(&0x0006_u16.to_be_bytes());
    attributes.extend_from_slice(&u16::try_from(username.len()).unwrap().to_be_bytes());
    attributes.extend_from_slice(username.as_bytes());
    while attributes.len() % 4 != 0 {
        attributes.push(0);
    }
    attributes.extend_from_slice(&0x0008_u16.to_be_bytes());
    attributes.extend_from_slice(&20_u16.to_be_bytes());
    attributes.extend_from_slice(&[0xab; 20]);
    let mut packet = vec![0x00, 0x01];
    packet.extend_from_slice(&u16::try_from(attributes.len()).unwrap().to_be_bytes());
    packet.extend_from_slice(&0x2112_a442_u32.to_be_bytes());
    packet.extend_from_slice(&[7; 12]);
    packet.extend_from_slice(&attributes);
    packet
}

fn sdp_value<'a>(sdp: &'a str, key: &str) -> &'a str {
    let at = sdp.find(key).unwrap() + key.len();
    sdp[at..].lines().next().unwrap().trim()
}

#[test]
fn a_source_that_proved_nothing_gets_not_one_byte_back() {
    let settings = Settings::default().with_signaling(Signaling::ByCaller);
    let (port, listener) = on_one_number(settings);
    let (tls, _) = tls();
    let quic = webtransport::Listener::on_port(&port, tls).unwrap();
    let forwarder = Forwarder::new(port.local_addr());

    // A session exists, so there are credentials to get wrong.
    let pair = dial(&listener, Some(settings));
    let near = pair.near.datagrams().unwrap();
    let _far = pair.far.datagrams().unwrap();
    let changes = near.path_changes().unwrap();
    let offer = pair.near.next_signal(Some(WAIT)).unwrap().unwrap();
    pair.far.deliver_signal(&offer).unwrap();
    let answer = pair.far.next_signal(Some(WAIT)).unwrap().unwrap();
    let answer_text = core::str::from_utf8(&answer[1..]).unwrap().to_owned();
    let offer_text = core::str::from_utf8(&offer[1..]).unwrap();
    let their_ufrag = sdp_value(&answer_text, "a=ice-ufrag:").to_owned();
    let our_ufrag = sdp_value(offer_text, "a=ice-ufrag:").to_owned();

    let probe = UdpSocket::bind(loopback()).unwrap();
    probe.set_read_timeout(Some(QUIET)).unwrap();
    probe.connect(port.local_addr()).unwrap();
    let mut packets: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![0x00, 0x01, 0, 0],
        vec![21, 0xfe, 0xfd, 0, 0],
        // A DTLS ClientHello's first bytes from nobody a session knows.
        {
            let mut hello = vec![22, 0xfe, 0xfd];
            hello.extend_from_slice(&[0; 200]);
            hello
        },
        vec![128; 64],
        vec![255; 1],
        stun_request("nobody:nothing"),
        stun_request(&format!("{their_ufrag}:nothing")),
        // The right names and a wrong key.
        stun_request(&format!("{their_ufrag}:{our_ufrag}")),
    ];
    for first in 0..=255_u8 {
        if !(64..128).contains(&first) && first < 192 {
            packets.push(vec![first; 40]);
        }
    }
    let mut buffer = [0_u8; 2048];
    for packet in &packets {
        probe.send(packet).unwrap();
    }
    probe
        .recv(&mut buffer)
        .expect_err("a packet with no credentials was answered");
    assert_eq!(port.data_channels(), 1);

    // The control: with the credentials, the port does answer that source.
    pair.near.deliver_signal(&answer).unwrap();
    assert_eq!(await_change(&changes), Delivery::Unreliable);
    drop((quic, forwarder));
}

#[test]
fn over_its_cap_a_port_refuses_an_offer_and_the_first_channel_goes_on() {
    let (port, listener) = on_one_number(Settings::default().with_max_sessions(1));
    let first = dial(&listener, Some(Settings::default()));
    let first_near = first.near.datagrams().unwrap();
    let first_far = first.far.datagrams().unwrap();
    let first_changes = first_near.path_changes().unwrap();
    assert_eq!(await_change(&first_changes), Delivery::Unreliable);

    let second = dial(&listener, Some(Settings::default()));
    let second_near = second.near.datagrams().unwrap();
    let second_far = second.far.datagrams().unwrap();
    let second_changes = second_near.path_changes().unwrap();
    assert_eq!(
        second_changes.recv_timeout(QUIET),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    assert_eq!(port.data_channels(), 1);
    assert_eq!(second_near.delivery(), Delivery::OverStream);
    arrives(second_near, second_far, b"on the socket");
    arrives(first_near, first_far, b"on the path");
}

#[test]
fn a_path_mtu_caps_the_datagram_and_one_of_that_size_takes_one_packet() {
    let forwarder = Forwarder::reserve();
    let (_port, listener) = on_forwarded(&forwarder);
    let Pair { near, far } = dial(&listener, Some(Settings::default()));
    let near_datagrams = near.datagrams().unwrap();
    let far_datagrams = far.datagrams().unwrap();
    let changes = near_datagrams.path_changes().unwrap();
    assert_eq!(await_change(&changes), Delivery::Unreliable);
    arrives(near_datagrams, far_datagrams, b"ready");

    let limit = near_datagrams.max_size().unwrap();
    let up = forwarder.large_upstream.load(Ordering::SeqCst);
    let down = forwarder.large_downstream.load(Ordering::SeqCst);
    let (mut sent, mut got) = (0, 0);
    for _ in 0..20 {
        near_datagrams.send(&vec![9; limit]).unwrap();
        sent += 1;
        if far_datagrams
            .receive(Some(Duration::from_secs(2)))
            .unwrap()
            .is_some_and(|datagram| datagram.len() == limit)
        {
            got += 1;
        }
    }
    assert_eq!(got, sent, "a lossless path lost some");
    assert_eq!(forwarder.large_upstream.load(Ordering::SeqCst) - up, sent);
    for _ in 0..20 {
        far_datagrams.send(&vec![9; limit]).unwrap();
        near_datagrams
            .receive(Some(Duration::from_secs(2)))
            .unwrap()
            .unwrap();
    }
    assert_eq!(
        forwarder.large_downstream.load(Ordering::SeqCst) - down,
        sent
    );

    let small = dial(&listener, Some(Settings::default().with_path_mtu(600)));
    let small_datagrams = small.near.datagrams().unwrap();
    let _far = small.far.datagrams().unwrap();
    let changes = small_datagrams.path_changes().unwrap();
    assert_eq!(await_change(&changes), Delivery::Unreliable);
    let limit = small_datagrams.max_size().unwrap();
    assert!(limit < 600 - 48, "{limit}");
    assert_eq!(
        small_datagrams.send(&vec![9; limit + 1]),
        Err(Failure::Protocol)
    );
}

#[test]
fn a_lossy_path_loses_datagrams_and_holds_nothing_up() {
    let forwarder = Forwarder::reserve();
    let (_port, listener) = on_forwarded(&forwarder);
    let Pair { near, far } = dial(&listener, Some(Settings::default()));
    let near_datagrams = near.datagrams().unwrap();
    let far_datagrams = far.datagrams().unwrap();
    let changes = near_datagrams.path_changes().unwrap();
    assert_eq!(await_change(&changes), Delivery::Unreliable);
    arrives(near_datagrams, far_datagrams, b"ready");

    forwarder.drop_each.store(4, Ordering::SeqCst);
    const SENT: u32 = 300;
    // Read while sending: a reader behind would lose some here too, which is not what this is about.
    let got = thread::scope(|scope| {
        let reading = scope.spawn(|| {
            let mut got = Vec::new();
            while let Ok(Some(datagram)) = far_datagrams.receive(Some(Duration::from_secs(2))) {
                got.push(u32::from_be_bytes(datagram.try_into().unwrap()));
            }
            got
        });
        for number in 0..SENT {
            near_datagrams.send(&number.to_be_bytes()).unwrap();
            thread::sleep(Duration::from_millis(2));
        }
        reading.join().unwrap()
    });
    forwarder.drop_each.store(0, Ordering::SeqCst);
    assert_eq!(far_datagrams.dropped(), 0);
    assert_eq!(near_datagrams.dropped(), 0);
    assert!(
        !got.is_empty() && got.len() < SENT as usize,
        "{} of {SENT} with one packet in four dropped",
        got.len()
    );
    // Nothing waited for what was lost: the last ones came through.
    assert!(*got.iter().max().unwrap() >= SENT - 8, "{got:?}");

    // The channel's messages cross the socket, whatever the path does.
    forwarder.drop_each.store(2, Ordering::SeqCst);
    for _ in 0..50 {
        near.send(b"message").unwrap();
    }
    for _ in 0..50 {
        assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), b"message");
    }
}

#[test]
fn webtransport_through_a_port_carries_every_datagram() {
    let port = Port::bind(loopback(), Settings::default()).unwrap();
    let (tls, pin) = tls();
    let listener = webtransport::Listener::on_port(&port, tls).unwrap();
    assert_eq!(listener.local_addr(), port.local_addr());
    let url = Url::parse(&format!("https://127.0.0.1:{}/", port.local_addr().port())).unwrap();
    thread::scope(|scope| {
        let accepted = scope.spawn(|| listener.accept(Some(WAIT)).unwrap());
        let near = webtransport::Dialer::pinned(&[pin])
            .unwrap()
            .dial(Kind::WebTransport, &url, WAIT)
            .unwrap();
        near.send(b"open").unwrap();
        let far = accepted.join().unwrap();
        assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), b"open");

        let datagrams = near.datagrams().unwrap();
        let far_datagrams = far.datagrams().unwrap();
        assert_eq!(datagrams.delivery(), Delivery::Unreliable);
        assert!(datagrams.path_changes().is_none());
        arrives(datagrams, far_datagrams, b"ready");
        let mut back = 0;
        for number in 0..100_u8 {
            datagrams.send(&[number]).unwrap();
            let got = far_datagrams.receive(Some(Duration::from_secs(2))).unwrap();
            far_datagrams.send(&got.unwrap()).unwrap();
            if datagrams
                .receive(Some(Duration::from_secs(2)))
                .is_ok_and(|datagram| datagram == Some(vec![number]))
            {
                back += 1;
            }
        }
        assert_eq!(back, 100);
    });
}

#[test]
fn webtransport_a_data_channel_and_a_websocket_run_on_one_number_at_once() {
    let (port, listener) = on_one_number(Settings::default());
    let (tls, pin) = tls();
    let quic = webtransport::Listener::on_port(&port, tls).unwrap();
    let pair = dial(&listener, Some(Settings::default()));
    let near_climbing = pair.near.datagrams().unwrap();
    let far_climbing = pair.far.datagrams().unwrap();
    let changes = near_climbing.path_changes().unwrap();
    assert_eq!(await_change(&changes), Delivery::Unreliable);

    let url = Url::parse(&format!("https://127.0.0.1:{}/", port.local_addr().port())).unwrap();
    thread::scope(|scope| {
        let accepted = scope.spawn(|| quic.accept(Some(WAIT)).unwrap());
        let near = webtransport::Dialer::pinned(&[pin])
            .unwrap()
            .dial(Kind::WebTransport, &url, WAIT)
            .unwrap();
        near.send(b"open").unwrap();
        let far = accepted.join().unwrap();
        assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), b"open");
        let near_quic = near.datagrams().unwrap();
        let far_quic = far.datagrams().unwrap();
        for round in 0..50_u8 {
            arrives(near_quic, far_quic, &[round]);
            arrives(near_climbing, far_climbing, &[round]);
            pair.near.send(&[round]).unwrap();
            assert_eq!(pair.far.receive(Some(WAIT)).unwrap().unwrap(), [round]);
        }
    });
}

/// A pair over TLS, as a WebSocket beyond loopback has to be, with its data channel on the same address.
fn climbs_over_tls(address: SocketAddr) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let certificate = rcgen::CertificateParams::new(vec![address.ip().to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
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

    let port = Port::bind(address, Settings::default()).unwrap();
    let listener = websocket::Listener::bind(address, Some(Arc::new(server)))
        .unwrap()
        .with_frames(Frames::Binary)
        .with_webrtc(&port);
    let url = Url::parse(&format!("wss://{}/", listener.local_addr().unwrap())).unwrap();
    thread::scope(|scope| {
        let accepted = scope.spawn(|| listener.accept(Some(WAIT)).unwrap());
        let near = websocket::Dialer::new()
            .with_tls(Arc::new(client))
            .with_frames(Frames::Binary)
            .with_webrtc(Settings::default())
            .dial(Kind::WebSocket, &url, WAIT)
            .unwrap();
        let far = accepted.join().unwrap();
        let near_datagrams = near.datagrams().unwrap();
        let far_datagrams = far.datagrams().unwrap();
        let changes = near_datagrams.path_changes().unwrap();
        assert_eq!(await_change(&changes), Delivery::Unreliable);
        arrives(near_datagrams, far_datagrams, b"over tls");
        arrives(far_datagrams, near_datagrams, b"and back");
    });
}

#[test]
fn a_wss_channel_climbs_the_same() {
    climbs_over_tls(loopback());
}

/// Beyond loopback, on this machine's own address. Opt-in: a firewall may ask about it, or may block it.
#[test]
fn a_candidate_on_a_real_address_works() {
    if std::env::var_os("COQUI_WEB_TEST_REAL_ADDRESS").is_none() {
        println!("skipped: COQUI_WEB_TEST_REAL_ADDRESS is not set");
        return;
    }
    let route = UdpSocket::bind("0.0.0.0:0").unwrap();
    route.connect("192.0.2.1:9").unwrap();
    let mut address = route.local_addr().unwrap();
    address.set_port(0);
    assert!(!address.ip().is_loopback());
    climbs_over_tls(address);
}

#[test]
fn ipv6_works_the_same_on_all_three() {
    let any: SocketAddr = "[::1]:0".parse().unwrap();
    let Ok(port) = Port::bind(any, Settings::default()) else {
        println!("skipped: no IPv6 loopback here");
        return;
    };
    let listener = websocket::Listener::bind(any, None)
        .unwrap()
        .with_frames(Frames::Binary)
        .with_webrtc(&port);
    let pair = dial(&listener, Some(Settings::default()));
    let near = pair.near.datagrams().unwrap();
    let far = pair.far.datagrams().unwrap();
    let changes = near.path_changes().unwrap();
    assert_eq!(await_change(&changes), Delivery::Unreliable);
    arrives(near, far, b"over six");
    let (tls, pin) = tls();
    let quic = webtransport::Listener::on_port(&port, tls).unwrap();
    let url = Url::parse(&format!("https://[::1]:{}/", port.local_addr().port())).unwrap();
    thread::scope(|scope| {
        let accepted = scope.spawn(|| quic.accept(Some(WAIT)).unwrap());
        let near = webtransport::Dialer::pinned(&[pin])
            .unwrap()
            .dial(Kind::WebTransport, &url, WAIT)
            .unwrap();
        near.send(b"open").unwrap();
        let far = accepted.join().unwrap();
        assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), b"open");
    });
}

#[test]
fn admission_judges_the_real_source_and_not_the_relay() {
    let port = Port::bind(loopback(), Settings::default()).unwrap();
    let forwarder = Forwarder::new(port.local_addr());
    let (tls, pin) = tls();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let noting = Arc::clone(&seen);
    let deny = Arc::new(AtomicBool::new(false));
    let denying = Arc::clone(&deny);
    let listener = webtransport::Listener::on_port(&port, tls)
        .unwrap()
        .with_admission(move |source| {
            noting
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(source);
            !denying.load(Ordering::SeqCst)
        });
    let url = Url::parse(&format!("https://127.0.0.1:{}/", forwarder.address.port())).unwrap();
    thread::scope(|scope| {
        let accepted = scope.spawn(|| listener.accept(Some(WAIT)).unwrap());
        let near = webtransport::Dialer::pinned(&[pin])
            .unwrap()
            .dial(Kind::WebTransport, &url, WAIT)
            .unwrap();
        near.send(b"open").unwrap();
        let far = accepted.join().unwrap();
        let sources = forwarder
            .sources
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let judged = seen.lock().unwrap_or_else(PoisonError::into_inner).clone();
        assert_eq!(judged.len(), 1);
        assert!(
            sources.contains(&judged[0]),
            "{judged:?} not in {sources:?}"
        );
        let shown = format!("{far:?}");
        assert!(shown.contains(&judged[0].to_string()), "{shown}");
    });
    // A refused source gets no session.
    deny.store(true, Ordering::SeqCst);
    let refused = webtransport::Dialer::pinned(&[pin]).unwrap().dial(
        Kind::WebTransport,
        &url,
        Duration::from_millis(100),
    );
    assert!(refused.is_err());
    assert!(matches!(
        listener.next(Some(Duration::from_millis(500))),
        Err(Failure::Timeout)
    ));
}

#[test]
fn a_flood_of_sources_cannot_pass_the_cap_or_keep_a_real_client_out() {
    const CAP: usize = 64;
    let port = Port::bind(
        loopback(),
        Settings::default()
            .with_max_relays(CAP)
            .with_relay_idle(Duration::from_secs(600)),
    )
    .unwrap();
    let (tls, pin) = tls();
    let listener = webtransport::Listener::on_port(&port, tls).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let target = port.local_addr();

    let flooding = Arc::clone(&stop);
    let flood = thread::spawn(move || {
        let packet = [0xc0_u8; 1200];
        while !flooding.load(Ordering::SeqCst) {
            // Enough to fill the map and turn it over, and no more than it can take with room for one real client.
            for _ in 0..16 {
                let source = UdpSocket::bind(loopback()).unwrap();
                let _ = source.send_to(&packet, target);
            }
            thread::sleep(Duration::from_millis(250));
        }
    });
    let deadline = Instant::now() + WAIT;
    while port.relays() < CAP {
        assert!(Instant::now() < deadline, "the flood never filled the map");
        thread::sleep(Duration::from_millis(5));
    }
    let url = Url::parse(&format!("https://127.0.0.1:{}/", target.port())).unwrap();
    thread::scope(|scope| {
        let accepted = scope.spawn(|| listener.accept(Some(WAIT)).unwrap());
        let near = webtransport::Dialer::pinned(&[pin])
            .unwrap()
            .dial(Kind::WebTransport, &url, WAIT)
            .unwrap();
        near.send(b"open").unwrap();
        let far = accepted.join().unwrap();
        assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), b"open");
        for round in 0..=255_u8 {
            assert!(port.relays() <= CAP, "{}", port.relays());
            near.send(&[round]).unwrap();
            assert_eq!(far.receive(Some(WAIT)).unwrap().unwrap(), [round]);
            thread::sleep(Duration::from_millis(5));
        }
    });
    stop.store(true, Ordering::SeqCst);
    flood.join().unwrap();
}

#[test]
fn a_relay_ends_after_silence() {
    let port = Port::bind(
        loopback(),
        Settings::default().with_relay_idle(Duration::from_millis(300)),
    )
    .unwrap();
    let (tls, _) = tls();
    let _listener = webtransport::Listener::on_port(&port, tls).unwrap();
    let source = UdpSocket::bind(loopback()).unwrap();
    // Let the listener's address reach the worker.
    let deadline = Instant::now() + WAIT;
    while port.relays() == 0 {
        assert!(Instant::now() < deadline, "no relay was made");
        source.send_to(&[0xc0; 1200], port.local_addr()).unwrap();
        thread::sleep(Duration::from_millis(5));
    }
    let deadline = Instant::now() + WAIT;
    while port.relays() > 0 {
        assert!(Instant::now() < deadline, "the relay never ended");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn closing_frees_the_number_and_ends_the_channels_reader() {
    let (port, listener) = on_one_number(Settings::default());
    let address = port.local_addr();
    let (tls, _) = tls();
    let quic = webtransport::Listener::on_port(&port, tls).unwrap();
    let pair = dial(&listener, Some(Settings::default()));
    let near = pair.near.datagrams().unwrap();
    let far = pair.far.datagrams().unwrap();
    let changes = near.path_changes().unwrap();
    assert_eq!(await_change(&changes), Delivery::Unreliable);
    arrives(near, far, b"up");
    let source = UdpSocket::bind(loopback()).unwrap();
    source.send_to(&[0xc0; 1200], address).unwrap();

    pair.near.close();
    assert_eq!(far.receive(Some(WAIT)), Ok(None));
    assert_eq!(near.receive(Some(WAIT)), Ok(None));
    assert_eq!(near.send(b"x"), Err(Failure::PathLost));
    let Pair { near, far } = pair;
    drop((near, far, listener, quic, port));
    assert!(
        UdpSocket::bind(address).is_ok(),
        "the port's socket is still open"
    );
}

impl Forwarder {
    /// A forwarder whose target [`on_forwarded`] sets.
    fn reserve() -> Self {
        Self::new(loopback())
    }
}
