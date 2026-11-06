//! What one peer can do to a port and to the other peers on it, over real sockets on loopback: point it elsewhere, take over another's
//! session, hold its room, or add datagrams inside the WebSocket.
#![allow(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::result_large_err
)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use coqui_web_channel::webrtc::{Port, Settings, Signaling};
use coqui_web_channel::websocket::{self, Frames};
use coqui_web_channel::{
    CertificatePin, Channel, Datagrams, Delivery, Dialer, Failure, Kind, webtransport,
};
use hmac::{Hmac, Mac};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha1::Sha1;
use str0m::ice::{StunMessage, TransId};
use url::Url;

const WAIT: Duration = Duration::from_secs(30);
/// Long enough to see nothing come back from a loopback socket.
const QUIET: Duration = Duration::from_millis(800);

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn carried() -> Settings {
    Settings::default().with_signaling(Signaling::ByCaller)
}

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

fn on_one_number(settings: Settings) -> (Port, websocket::Listener) {
    for _ in 0..64 {
        let port = Port::bind(loopback(), settings).unwrap();
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

fn dial_to(listener: &websocket::Listener, to: SocketAddr, settings: Settings) -> Pair {
    let url = Url::parse(&format!("ws://{to}/")).unwrap();
    thread::scope(|scope| {
        let accepted = scope.spawn(|| listener.accept(Some(WAIT)).unwrap());
        let near = websocket::Dialer::new()
            .with_frames(Frames::Binary)
            .with_webrtc(settings)
            .dial(Kind::WebSocket, &url, WAIT)
            .unwrap();
        Pair {
            near,
            far: accepted.join().unwrap(),
        }
    })
}

fn dial(listener: &websocket::Listener, settings: Settings) -> Pair {
    dial_to(listener, listener.local_addr().unwrap(), settings)
}

/// Sends until one comes back within `limit`, and says whether it did.
fn arrives_within(
    from: &dyn Datagrams,
    to: &dyn Datagrams,
    payload: &[u8],
    limit: Duration,
) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        from.send(payload).unwrap();
        if let Ok(Some(got)) = to.receive(Some(Duration::from_millis(50)))
            && got == payload
        {
            while let Ok(Some(_)) = to.receive(Some(Duration::from_millis(20))) {}
            return true;
        }
    }
    false
}

fn arrives(from: &dyn Datagrams, to: &dyn Datagrams, payload: &[u8]) {
    assert!(arrives_within(from, to, payload, WAIT), "nothing arrived");
}

fn sdp_value(sdp: &str, key: &str) -> String {
    let at = sdp.find(key).unwrap() + key.len();
    sdp[at..].lines().next().unwrap().trim().to_owned()
}

/// What a client learns from its own offer and the listener's answer.
struct Credentials {
    listener_ufrag: String,
    listener_password: String,
    client_ufrag: String,
}

/// Carries an offer and its answer as a caller would, and waits for both ends to switch.
fn climb(pair: &Pair) -> Credentials {
    let near = pair.near.datagrams().unwrap();
    let far = pair.far.datagrams().unwrap();
    let changes = near.path_changes().unwrap();
    let offer = pair.near.next_signal(Some(WAIT)).unwrap().unwrap();
    pair.far.deliver_signal(&offer).unwrap();
    let answer = pair.far.next_signal(Some(WAIT)).unwrap().unwrap();
    pair.near.deliver_signal(&answer).unwrap();
    assert_eq!(changes.recv_timeout(WAIT), Ok(Delivery::Unreliable));
    let started = Instant::now();
    while far.delivery() != Delivery::Unreliable {
        assert!(started.elapsed() < WAIT, "the far end never switched");
        thread::sleep(Duration::from_millis(5));
    }
    let offer = core::str::from_utf8(&offer[1..]).unwrap();
    let answer = core::str::from_utf8(&answer[1..]).unwrap();
    Credentials {
        listener_ufrag: sdp_value(answer, "a=ice-ufrag:"),
        listener_password: sdp_value(answer, "a=ice-pwd:"),
        client_ufrag: sdp_value(offer, "a=ice-ufrag:"),
    }
}

fn hmac_sha1(key: &[u8], parts: &[&[u8]]) -> [u8; 20] {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).unwrap();
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// A binding request with the client's credentials that nominates wherever it comes from, at the highest priority.
fn nominating(credentials: &Credentials) -> Vec<u8> {
    let username = format!(
        "{}:{}",
        credentials.listener_ufrag, credentials.client_ufrag
    );
    let request =
        StunMessage::binding_request(&username, TransId::new(), true, 7, 0x7fff_ffff, true);
    let mut buffer = vec![0_u8; 1500];
    let written = request
        .to_bytes(
            Some(credentials.listener_password.as_bytes()),
            &mut buffer,
            hmac_sha1,
        )
        .unwrap();
    buffer.truncate(written);
    buffer
}

fn nothing_arrives(socket: &UdpSocket) -> bool {
    socket.set_read_timeout(Some(QUIET)).unwrap();
    let mut buffer = [0_u8; 2048];
    socket.recv_from(&mut buffer).is_err()
}

/// A client nominating another address: nothing of the session may go there, and its own client keeps getting it.
fn nominate_elsewhere(settings: Settings, elsewhere: &UdpSocket) {
    let (port, listener) = on_one_number(settings);
    let pair = dial(&listener, carried());
    let credentials = climb(&pair);
    let near = pair.near.datagrams().unwrap();
    let far = pair.far.datagrams().unwrap();
    arrives(far, near, b"before");
    elsewhere
        .send_to(&nominating(&credentials), port.local_addr())
        .unwrap();
    thread::sleep(Duration::from_millis(300));
    for round in 0..20_u8 {
        far.send(&[round]).unwrap();
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        nothing_arrives(elsewhere),
        "the listener sent something where the client pointed it"
    );
    assert_eq!(near.delivery(), Delivery::Unreliable);
    arrives(far, near, b"after");
}

#[test]
fn a_client_cannot_point_the_listener_at_another_address() {
    let Ok(elsewhere) = UdpSocket::bind("127.0.0.2:0") else {
        println!("skipped: 127.0.0.2 cannot be bound here");
        return;
    };
    nominate_elsewhere(carried(), &elsewhere);
}

#[test]
fn where_any_address_may_check_a_session_holds_to_the_one_it_chose() {
    let elsewhere = UdpSocket::bind(loopback()).unwrap();
    nominate_elsewhere(carried().with_any_candidate(), &elsewhere);
}

/// Packets to send, each from the far socket of the nth client.
type Injected = Vec<(usize, Vec<u8>)>;

/// A forwarder in front of a port that can also send as any client it has forwarded for.
struct Forwarder {
    address: SocketAddr,
    /// Where it forwards to, set once the port is bound.
    target: Arc<Mutex<SocketAddr>>,
    /// To send from the nth client's far socket.
    injected: Arc<Mutex<Injected>>,
    stop: Arc<AtomicBool>,
}

impl Forwarder {
    fn reserve() -> Self {
        let near = UdpSocket::bind(loopback()).unwrap();
        near.set_nonblocking(true).unwrap();
        let this = Self {
            address: near.local_addr().unwrap(),
            target: Arc::new(Mutex::new(loopback())),
            injected: Arc::default(),
            stop: Arc::default(),
        };
        let injected = Arc::clone(&this.injected);
        let stop = Arc::clone(&this.stop);
        let target = Arc::clone(&this.target);
        thread::spawn(move || {
            let mut far: HashMap<SocketAddr, UdpSocket> = HashMap::new();
            let mut order: Vec<SocketAddr> = Vec::new();
            let mut buffer = vec![0_u8; 65536];
            while !stop.load(Ordering::SeqCst) {
                let mut idle = true;
                for (index, packet) in injected
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .drain(..)
                {
                    let _ = far[&order[index]].send(&packet);
                }
                while let Ok((count, client)) = near.recv_from(&mut buffer) {
                    idle = false;
                    let socket = far.entry(client).or_insert_with(|| {
                        order.push(client);
                        let socket = UdpSocket::bind(loopback()).unwrap();
                        socket.set_nonblocking(true).unwrap();
                        socket
                            .connect(*target.lock().unwrap_or_else(PoisonError::into_inner))
                            .unwrap();
                        socket
                    });
                    let _ = socket.send(&buffer[..count]);
                }
                for (client, socket) in &far {
                    while let Ok(count) = socket.recv(&mut buffer) {
                        idle = false;
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

    fn send_as(&self, client: usize, packet: Vec<u8>) {
        self.injected
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((client, packet));
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

#[test]
fn one_client_cannot_take_over_another_s_session() {
    let forwarder = Forwarder::reserve();
    let port = Port::bind(loopback(), carried().with_public_address(forwarder.address)).unwrap();
    *forwarder
        .target
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = port.local_addr();
    let listener = websocket::Listener::bind(loopback(), None)
        .unwrap()
        .with_frames(Frames::Binary)
        .with_webrtc(&port);
    let first = dial(&listener, carried());
    let first_credentials = climb(&first);
    let second = dial(&listener, carried());
    climb(&second);
    let second_changes = second.near.datagrams().unwrap().path_changes().unwrap();

    // The first client's credentials, nominating from where the second client is.
    forwarder.send_as(1, nominating(&first_credentials));
    thread::sleep(Duration::from_millis(300));

    let (first_near, first_far) = (
        first.near.datagrams().unwrap(),
        first.far.datagrams().unwrap(),
    );
    let (second_near, second_far) = (
        second.near.datagrams().unwrap(),
        second.far.datagrams().unwrap(),
    );
    assert!(
        arrives_within(first_far, first_near, b"first", Duration::from_secs(5)),
        "the first session's datagrams went elsewhere"
    );
    assert!(
        arrives_within(second_near, second_far, b"second", Duration::from_secs(5)),
        "the second session lost its path"
    );
    assert!(arrives_within(
        second_far,
        second_near,
        b"second back",
        Duration::from_secs(5)
    ));
    assert_eq!(
        second_changes.recv_timeout(QUIET),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    assert_eq!(second_near.delivery(), Delivery::Unreliable);
}

#[test]
fn one_address_cannot_hold_more_data_channels_than_its_share() {
    let (port, listener) = on_one_number(Settings::default().with_max_per_address(1));
    let first = dial(&listener, Settings::default());
    let first_changes = first.near.datagrams().unwrap().path_changes().unwrap();
    let _ = first.far.datagrams().unwrap();
    assert_eq!(first_changes.recv_timeout(WAIT), Ok(Delivery::Unreliable));

    let second = dial(&listener, Settings::default());
    let second_changes = second.near.datagrams().unwrap().path_changes().unwrap();
    let _ = second.far.datagrams().unwrap();
    assert_eq!(
        second_changes.recv_timeout(Duration::from_secs(2)),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    assert_eq!(port.data_channels(), 1);
    arrives(
        second.near.datagrams().unwrap(),
        second.far.datagrams().unwrap(),
        b"on the socket",
    );
}

fn quic_session(
    listener: &webtransport::Listener,
    port: &Port,
    pin: CertificatePin,
    limit: Duration,
) -> Result<(), Failure> {
    let url = Url::parse(&format!("https://127.0.0.1:{}/", port.local_addr().port())).unwrap();
    thread::scope(|scope| {
        let accepted = scope.spawn(|| listener.accept(Some(limit)));
        let near = webtransport::Dialer::pinned(&[pin])?.dial(Kind::WebTransport, &url, limit);
        let far = accepted.join().unwrap();
        let (near, far) = (near?, far?);
        near.send(b"open")?;
        assert_eq!(far.receive(Some(WAIT))?.unwrap(), b"open");
        near.close();
        far.close();
        Ok(())
    })
}

#[test]
fn a_closed_webtransport_session_gives_its_relay_back() {
    let port = Port::bind(loopback(), Settings::default().with_max_relays(2)).unwrap();
    let (tls, pin) = tls();
    let listener = webtransport::Listener::on_port(&port, tls).unwrap();
    for _ in 0..2 {
        quic_session(&listener, &port, pin, WAIT).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while port.relays() > 0 {
        assert!(
            Instant::now() < deadline,
            "{} relays held for closed sessions",
            port.relays()
        );
        thread::sleep(Duration::from_millis(20));
    }
    quic_session(&listener, &port, pin, Duration::from_secs(5))
        .expect("a new client was kept out by sessions already closed");
}

#[test]
fn a_second_webtransport_listener_on_one_port_is_refused() {
    let port = Port::bind(loopback(), Settings::default()).unwrap();
    let (tls, _) = tls();
    let _first = webtransport::Listener::on_port(&port, Arc::clone(&tls)).unwrap();
    assert!(matches!(
        webtransport::Listener::on_port(&port, tls),
        Err(Failure::Permission)
    ));
}

#[test]
fn settings_that_leave_no_room_are_refused() {
    let none = Settings::default().with_path_mtu(116);
    assert!(matches!(
        Port::bind(loopback(), none),
        Err(Failure::Unsupported)
    ));
    for broken in [
        Settings::default().with_attempt(Duration::ZERO),
        Settings::default().with_max_sessions(0),
        Settings::default().with_max_relays(0),
        Settings::default().with_max_per_address(0),
        Settings::default().with_relay_idle(Duration::ZERO),
    ] {
        assert!(
            matches!(Port::bind(loopback(), broken), Err(Failure::Unsupported)),
            "{broken:?}"
        );
    }
    let listener = websocket::Listener::bind(loopback(), None).unwrap();
    let url = Url::parse(&format!("ws://{}/", listener.local_addr().unwrap())).unwrap();
    let dialed = websocket::Dialer::new()
        .with_webrtc(Settings::default().with_path_mtu(100))
        .dial(Kind::WebSocket, &url, Duration::from_secs(2));
    assert!(matches!(dialed, Err(Failure::Unsupported)));
}

/// Counts the address validation tokens a server hands this client.
#[derive(Default)]
struct Tokens(AtomicUsize);

impl wtransport::quinn::TokenStore for Tokens {
    fn insert(&self, _: &str, _: bytes::Bytes) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn take(&self, _: &str) -> Option<bytes::Bytes> {
        None
    }
}

#[test]
fn webtransport_on_a_port_hands_out_no_address_token() {
    let port = Port::bind(loopback(), Settings::default()).unwrap();
    let (tls, pin) = tls();
    let listener = webtransport::Listener::on_port(&port, tls).unwrap();
    thread::spawn(move || {
        let _ = listener.accept(Some(Duration::from_secs(10)));
    });
    let tokens = Arc::new(Tokens::default());
    let mut config = wtransport::ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(*pin.as_bytes())])
        .build();
    config
        .quic_config_mut()
        .token_store(Arc::clone(&tokens) as Arc<dyn wtransport::quinn::TokenStore>);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let url = format!("https://127.0.0.1:{}/", port.local_addr().port());
    runtime.block_on(async {
        let endpoint = wtransport::Endpoint::client(config).unwrap();
        let connection = endpoint.connect(url).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        drop(connection);
    });
    assert_eq!(
        tokens.0.load(Ordering::SeqCst),
        0,
        "a token bound to 127.0.0.1 would stand for every client the relay serves"
    );
}

/// A WebSocket proxy that can add a frame of its own to what the listener sends, between the listener's frames: someone inside the
/// TLS stream.
struct Injector {
    address: SocketAddr,
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Injector {
    fn new(target: SocketAddr) -> Self {
        let listener = TcpListener::bind(loopback()).unwrap();
        let this = Self {
            address: listener.local_addr().unwrap(),
            frames: Arc::default(),
        };
        let frames = Arc::clone(&this.frames);
        thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            let mut server = TcpStream::connect(target).unwrap();
            let mut client_reader = client.try_clone().unwrap();
            let mut server_writer = server.try_clone().unwrap();
            thread::spawn(move || {
                let _ = std::io::copy(&mut client_reader, &mut server_writer);
            });
            let mut handshake = Vec::new();
            let mut byte = [0_u8; 1];
            while !handshake.ends_with(b"\r\n\r\n") {
                if server.read_exact(&mut byte).is_err() {
                    return;
                }
                handshake.push(byte[0]);
            }
            client.write_all(&handshake).unwrap();
            loop {
                for frame in frames
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .drain(..)
                {
                    client.write_all(&frame).unwrap();
                }
                server
                    .set_read_timeout(Some(Duration::from_millis(20)))
                    .unwrap();
                let mut head = [0_u8; 2];
                match server.read(&mut head[..1]) {
                    Ok(0) => return,
                    Ok(_) => {}
                    Err(_) => continue,
                }
                server.set_read_timeout(None).unwrap();
                if server.read_exact(&mut head[1..]).is_err() {
                    return;
                }
                let mut frame = head.to_vec();
                let length = match head[1] & 0x7f {
                    126 => {
                        let mut extended = [0_u8; 2];
                        server.read_exact(&mut extended).unwrap();
                        frame.extend_from_slice(&extended);
                        usize::from(u16::from_be_bytes(extended))
                    }
                    127 => {
                        let mut extended = [0_u8; 8];
                        server.read_exact(&mut extended).unwrap();
                        frame.extend_from_slice(&extended);
                        usize::try_from(u64::from_be_bytes(extended)).unwrap()
                    }
                    short => usize::from(short),
                };
                let mut payload = vec![0_u8; length];
                if server.read_exact(&mut payload).is_err() {
                    return;
                }
                frame.extend_from_slice(&payload);
                if client.write_all(&frame).is_err() {
                    return;
                }
            }
        });
        this
    }

    /// A datagram as the listener would tag it, in an unmasked binary frame.
    fn datagram(&self, payload: &[u8]) {
        let mut frame = vec![0x82, u8::try_from(payload.len() + 1).unwrap(), 1];
        frame.extend_from_slice(payload);
        self.frames
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(frame);
    }
}

#[test]
fn with_carried_signals_nothing_inside_the_websocket_arrives_once_the_data_channel_is_open() {
    let (_port, listener) = on_one_number(carried());
    let injector = Injector::new(listener.local_addr().unwrap());
    let pair = dial_to(&listener, injector.address, carried());
    let near = pair.near.datagrams().unwrap();

    // The control: before the data channel opens, a datagram in the WebSocket arrives, as documented, so the injector works.
    injector.datagram(b"before");
    assert_eq!(near.receive(Some(WAIT)), Ok(Some(b"before".to_vec())));

    climb(&pair);
    let dropped = near.dropped();
    injector.datagram(b"forged");
    let mut got = Vec::new();
    while let Ok(Some(datagram)) = near.receive(Some(QUIET)) {
        got.push(datagram);
    }
    assert!(
        !got.contains(&b"forged".to_vec()),
        "a datagram injected into the WebSocket arrived on a sealed data channel"
    );
    let far = pair.far.datagrams().unwrap();
    assert!(arrives_within(far, near, b"real", Duration::from_secs(5)));
    assert!(
        near.dropped() > dropped,
        "the injected datagram was not counted"
    );
}
