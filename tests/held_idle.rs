//! What channels held at their read-ahead cost while their readers wait, measured for the whole process, so this file holds one
//! test.
#![cfg(all(feature = "websocket", feature = "webtransport"))]
#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]

mod cpu;

use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use coqui_transport_web::{CertificatePin, Channel, Dialer, Kind, Limits, websocket, webtransport};
use cpu::process_cpu;
use rustls::pki_types::PrivatePkcs8KeyDer;
use url::Url;

const WAIT: Duration = Duration::from_secs(10);
const REST: Duration = Duration::from_secs(5);
/// Channels of each kind. Many more WebTransport connections cost QUIC's own timers more than 1% here.
const HELD: usize = 16;
/// Messages each client sends: the server's driver holds the first, and the rest wait at the client.
const SENT: usize = 3;

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

type Pair = (Box<dyn Channel>, Box<dyn Channel>);

/// WebTransport pairs whose servers start at one message ahead, from their listener's limits.
fn webtransport_pairs(listener: &webtransport::Listener, pin: CertificatePin) -> Vec<Pair> {
    let url = Url::parse(&format!(
        "https://127.0.0.1:{}/",
        listener.local_addr().port()
    ))
    .unwrap();
    let mut dialer = webtransport::Dialer::pinned(&[pin]).unwrap();
    (0..HELD)
        .map(|_| {
            thread::scope(|scope| {
                let accepted = scope.spawn(|| listener.accept(Some(WAIT)).unwrap());
                let near = dialer.dial(Kind::WebTransport, &url, WAIT).unwrap();
                // A server has no stream to accept until the client's carries something.
                near.send(b"open").unwrap();
                let far = accepted.join().unwrap();
                assert_eq!(far.receive(Some(WAIT)), Ok(Some(b"open".to_vec())));
                let pair: Pair = (Box::new(near), Box::new(far));
                pair
            })
        })
        .collect()
}

/// WebSocket pairs whose servers are lowered to one message ahead once open.
fn websocket_pairs(listener: &websocket::Listener) -> Vec<Pair> {
    let url = Url::parse(&format!("ws://{}/", listener.local_addr().unwrap())).unwrap();
    (0..HELD)
        .map(|_| {
            thread::scope(|scope| {
                let accepted = scope.spawn(|| listener.accept(Some(WAIT)).unwrap());
                let near = websocket::Dialer::new()
                    .dial(Kind::WebSocket, &url, WAIT)
                    .unwrap();
                let far = accepted.join().unwrap();
                far.set_pending(1).unwrap();
                let pair: Pair = (Box::new(near), Box::new(far));
                pair
            })
        })
        .collect()
}

#[test]
fn channels_held_at_their_read_ahead_take_no_cpu_while_their_readers_wait() {
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (tls, pin) = server_tls();
    let quic = webtransport::Listener::bind(any, tls)
        .unwrap()
        .with_limits(Limits::default().with_pending(1));
    let tcp = websocket::Listener::bind(any, None).unwrap();
    let mut pairs = webtransport_pairs(&quic, pin);
    pairs.extend(websocket_pairs(&tcp));
    for (near, _) in &pairs {
        for n in 0..SENT {
            near.send(format!("held {n}").as_bytes()).unwrap();
        }
    }
    thread::sleep(Duration::from_millis(500));

    let cpu = process_cpu();
    let started = Instant::now();
    thread::sleep(REST);
    let used = process_cpu().saturating_sub(cpu);
    let share = used.as_secs_f64() / started.elapsed().as_secs_f64();
    println!("held: {used:?} of CPU in {:?}", started.elapsed());
    assert!(
        share < 0.01,
        "{used:?} of CPU in {:?} while every reader waits",
        started.elapsed()
    );

    // Held back, not lost: each reader gets everything, in order.
    for (near, far) in &pairs {
        for n in 0..SENT {
            assert_eq!(
                far.receive(Some(WAIT)),
                Ok(Some(format!("held {n}").into_bytes()))
            );
        }
        near.close();
        far.close();
    }
}
