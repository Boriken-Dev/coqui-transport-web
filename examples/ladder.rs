//! A peer for a browser to climb against, on loopback: prints its ports and pin as one JSON line and serves until killed.
//!
//! `direct` is WebTransport, a data channel and a WebSocket on one number. `forwarded` is a data channel whose candidate names a UDP
//! forwarder this peer controls, so a test can lose packets, count them or black-hole the path. `carried` leaves its signals to the
//! caller, carrying them in messages as `signal:<hex>`. Everything else is echoed, messages and datagrams alike, except an empty
//! datagram, which Rust cannot send on a data channel: that is answered with the message `an empty datagram`.
//!
//! On `forwarded`, a message `!loss N` drops one packet in N, `!hole` drops all, `!pass` none, `!counts` answers with the packets
//! that crossed each way and how many of them were large, and `!burst N` sends N numbered datagrams then the message `burst done`.
//!
//! Standard input closing ends it, since killing the `cargo run` that started it does not on Windows.
//!
//! `cargo run --all-features --example ladder`

#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use coqui_web::webrtc::{Port, Settings, Signaling};
use coqui_web::websocket::{self, Frames};
use coqui_web::{CertificatePin, Channel, webtransport};
use rustls::pki_types::PrivatePkcs8KeyDer;

const LARGE: usize = 1000;

#[derive(Default)]
struct Path {
    drop_each: AtomicU64,
    hole: AtomicBool,
    up: AtomicU64,
    down: AtomicU64,
    large_up: AtomicU64,
    large_down: AtomicU64,
}

impl Path {
    fn passes(&self, counted: &mut u64) -> bool {
        *counted += 1;
        let each = self.drop_each.load(Ordering::SeqCst);
        !self.hole.load(Ordering::SeqCst) && !(each > 0 && (*counted).is_multiple_of(each))
    }
}

/// Forwards to `target` from a socket per client, with the loss and counting `path` says.
fn forward(target: SocketAddr, path: Arc<Path>) -> std::io::Result<SocketAddr> {
    let near = UdpSocket::bind("127.0.0.1:0")?;
    near.set_nonblocking(true)?;
    let address = near.local_addr()?;
    thread::spawn(move || {
        let mut far: HashMap<SocketAddr, UdpSocket> = HashMap::new();
        let mut buffer = vec![0_u8; 65536];
        let mut counted = 0;
        loop {
            let mut idle = true;
            while let Ok((count, client)) = near.recv_from(&mut buffer) {
                idle = false;
                let socket = far.entry(client).or_insert_with(|| {
                    let socket = UdpSocket::bind("127.0.0.1:0").expect("a socket");
                    socket.set_nonblocking(true).expect("nonblocking");
                    socket.connect(target).expect("connected");
                    socket
                });
                if path.passes(&mut counted) {
                    path.up.fetch_add(1, Ordering::SeqCst);
                    if count >= LARGE {
                        path.large_up.fetch_add(1, Ordering::SeqCst);
                    }
                    let _ = socket.send(&buffer[..count]);
                }
            }
            for (client, socket) in &far {
                while let Ok(count) = socket.recv(&mut buffer) {
                    idle = false;
                    if path.passes(&mut counted) {
                        path.down.fetch_add(1, Ordering::SeqCst);
                        if count >= LARGE {
                            path.large_down.fetch_add(1, Ordering::SeqCst);
                        }
                        let _ = near.send_to(&buffer[..count], client);
                    }
                }
            }
            if idle {
                thread::sleep(Duration::from_millis(1));
            }
        }
    });
    Ok(address)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .filter_map(|at| u8::from_str_radix(text.get(at * 2..at * 2 + 2)?, 16).ok())
        .collect()
}

/// Echoes until the channel ends, and acts on what a test tells the path to do.
fn serve<C: Channel>(channel: &C, path: Option<&Path>, carried: Option<&websocket::Channel>) {
    thread::scope(|scope| {
        if let Some(datagrams) = channel.datagrams() {
            scope.spawn(move || {
                while let Ok(Some(datagram)) = datagrams.receive(None) {
                    if datagram.is_empty() {
                        let _ = channel.send(b"an empty datagram");
                    } else {
                        let _ = datagrams.send(&datagram);
                    }
                }
            });
        }
        if let Some(signalled) = carried {
            scope.spawn(move || {
                while let Ok(Some(signal)) = signalled.next_signal(None) {
                    let _ = signalled.send(format!("signal:{}", hex(&signal)).as_bytes());
                }
            });
        }
        while let Ok(Some(message)) = channel.receive(None) {
            let text = String::from_utf8_lossy(&message);
            if let (Some(signalled), Some(signal)) = (carried, text.strip_prefix("signal:")) {
                let _ = signalled.deliver_signal(&unhex(signal));
                continue;
            }
            if let Some(path) = path
                && let Some(command) = text.strip_prefix('!')
            {
                let answer = act(channel, path, command);
                if channel.send(answer.as_bytes()).is_err() {
                    break;
                }
                continue;
            }
            if channel.send(&message).is_err() {
                break;
            }
        }
        channel.close();
    });
}

fn act<C: Channel>(channel: &C, path: &Path, command: &str) -> String {
    let mut words = command.split(' ');
    let number = |word: Option<&str>| word.and_then(|word| word.parse::<u64>().ok()).unwrap_or(0);
    match words.next() {
        Some("loss") => {
            path.drop_each.store(number(words.next()), Ordering::SeqCst);
            "ok".to_owned()
        }
        Some("hole") => {
            path.hole.store(true, Ordering::SeqCst);
            "ok".to_owned()
        }
        Some("pass") => {
            path.hole.store(false, Ordering::SeqCst);
            path.drop_each.store(0, Ordering::SeqCst);
            "ok".to_owned()
        }
        Some("counts") => format!(
            "{{\"up\":{},\"down\":{},\"largeUp\":{},\"largeDown\":{}}}",
            path.up.load(Ordering::SeqCst),
            path.down.load(Ordering::SeqCst),
            path.large_up.load(Ordering::SeqCst),
            path.large_down.load(Ordering::SeqCst),
        ),
        Some("burst") => {
            if let Some(datagrams) = channel.datagrams() {
                for sent in 0..number(words.next()) {
                    let _ = datagrams.send(&(sent as u32).to_be_bytes());
                    thread::sleep(Duration::from_millis(2));
                }
            }
            "burst done".to_owned()
        }
        _ => "unknown".to_owned(),
    }
}

/// A port and a WebSocket listener on one number.
fn on_one_number(settings: Settings) -> Result<(Port, websocket::Listener), coqui_web::Failure> {
    let loopback: SocketAddr = "127.0.0.1:0".parse().expect("an address");
    for _ in 0..64 {
        let port = Port::bind(loopback, settings)?;
        if TcpListener::bind(port.local_addr()).is_ok()
            && let Ok(listener) = websocket::Listener::bind(port.local_addr(), None)
        {
            let listener = listener.with_frames(Frames::Binary).with_webrtc(&port);
            return Ok((port, listener));
        }
    }
    Err(coqui_web::Failure::Unsupported)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])?;
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    params.not_after = params.not_before + time::Duration::days(10);
    let certificate = params.self_signed(&key)?;
    let der = certificate.der().clone();
    let tls = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![der.clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )?,
    );
    let hash = wtransport::tls::Certificate::from_der(der.to_vec())?.hash();
    let pin = CertificatePin::from_bytes(*hash.as_ref());

    let (direct_port, direct) = on_one_number(Settings::default())?;
    let quic = webtransport::Listener::on_port(&direct_port, tls)?;

    // The forwarder needs the port's number and the port needs the forwarder's, so the number is found first.
    let holder = UdpSocket::bind("127.0.0.1:0")?;
    let hidden = holder.local_addr()?;
    drop(holder);
    let path = Arc::new(Path::default());
    let forwarder = forward(hidden, Arc::clone(&path))?;
    let forwarded_port = Port::bind(
        hidden,
        Settings::default()
            .with_attempt(Duration::from_secs(3))
            .with_public_address(forwarder),
    )?;
    let forwarded = websocket::Listener::bind("127.0.0.1:0".parse()?, None)?
        .with_frames(Frames::Binary)
        .with_webrtc(&forwarded_port);

    let carried_port = Port::bind(
        "127.0.0.1:0".parse()?,
        Settings::default()
            .with_attempt(Duration::from_secs(3))
            .with_signaling(Signaling::ByCaller),
    )?;
    let carried = websocket::Listener::bind("127.0.0.1:0".parse()?, None)?
        .with_frames(Frames::Binary)
        .with_webrtc(&carried_port);

    println!(
        "{{\"direct\":{},\"forwarded\":{},\"forwarder\":{},\"carried\":{},\"pin\":\"{pin}\"}}",
        direct_port.local_addr().port(),
        forwarded.local_addr()?.port(),
        forwarder.port(),
        carried.local_addr()?.port(),
    );

    thread::spawn(|| {
        let _ = std::io::copy(&mut std::io::stdin(), &mut std::io::sink());
        std::process::exit(0);
    });
    thread::spawn(move || {
        while let Ok(channel) = direct.accept(None) {
            thread::spawn(move || serve(&channel, None, None));
        }
    });
    thread::spawn(move || {
        while let Ok(channel) = forwarded.accept(None) {
            let path = Arc::clone(&path);
            thread::spawn(move || serve(&channel, Some(&path), None));
        }
    });
    thread::spawn(move || {
        while let Ok(channel) = carried.accept(None) {
            thread::spawn(move || serve(&channel, None, Some(&channel)));
        }
    });
    while let Ok(channel) = quic.accept(None) {
        thread::spawn(move || serve(&channel, None, None));
    }
    drop((direct_port, forwarded_port, carried_port));
    Ok(())
}
