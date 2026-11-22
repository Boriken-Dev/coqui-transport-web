//! The UDP payload size settings of the WebTransport dialer and listener: that they reach quinn, and what they do on a path
//! that refuses datagrams over a size, which a relay between the two ends stands in for.
#![cfg(feature = "webtransport")]
#![allow(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::result_large_err
)]

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use coqui_builder::Partial;
use coqui_transport_web::webtransport::{self, MIN_MTU, Mtu};
use coqui_transport_web::{CertificatePin, Channel, Dialer as _, Failure, Kind};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use url::Url;

const WAIT: Duration = Duration::from_secs(20);

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

fn sized(initial: u16, discovery: bool, upper_bound: u16) -> Mtu {
    let mut mtu = Mtu::default();
    mtu.initial = initial;
    mtu.discovery = discovery;
    mtu.upper_bound = upper_bound;
    mtu
}

/// A connected pair; the dialer goes through `through` when given a relay's address.
fn pair(
    listening: Mtu,
    dialing: Mtu,
    through: impl FnOnce(SocketAddr) -> SocketAddr,
) -> (webtransport::Channel, webtransport::Channel) {
    let id = identity();
    let listener = webtransport::Listener::builder(loopback(), server_tls(&id))
        .mtu(listening)
        .build()
        .unwrap();
    let reached = through(listener.local_addr());
    let accepted = thread::spawn(move || listener.accept(Some(WAIT)).unwrap());
    let client =
        webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::from([pin(&id)])))
            .mtu(dialing)
            .build()
            .unwrap()
            .dial(
                Kind::WebTransport,
                &Url::parse(&format!("https://127.0.0.1:{}/channel", reached.port())).unwrap(),
                WAIT,
            )
            .unwrap();
    client.send(b"open").unwrap();
    let server = accepted.join().unwrap();
    assert_eq!(server.receive(Some(WAIT)).unwrap().unwrap(), b"open");
    (client, server)
}

/// A UDP relay between a dialer and a listener that discards every datagram over `cap` bytes, as a path whose MTU is smaller
/// does, and counts what it discarded.
struct Relay {
    dropped: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Relay {
    fn start(server: SocketAddr, cap: usize) -> (Self, SocketAddr) {
        let near = Arc::new(UdpSocket::bind(loopback()).unwrap());
        let far = Arc::new(UdpSocket::bind(loopback()).unwrap());
        far.connect(server).unwrap();
        for socket in [&near, &far] {
            socket
                .set_read_timeout(Some(Duration::from_millis(20)))
                .unwrap();
        }
        let address = near.local_addr().unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let client = Arc::new(std::sync::Mutex::new(None::<SocketAddr>));
        {
            let (near, far, dropped, stop, client) = (
                near.clone(),
                far.clone(),
                dropped.clone(),
                stop.clone(),
                client.clone(),
            );
            thread::spawn(move || {
                let mut buffer = vec![0; 65536];
                while !stop.load(Ordering::Relaxed) {
                    if let Ok((length, from)) = near.recv_from(&mut buffer) {
                        *client.lock().unwrap() = Some(from);
                        if length > cap {
                            dropped.fetch_add(1, Ordering::Relaxed);
                        } else {
                            let _ = far.send(&buffer[..length]);
                        }
                    }
                }
            });
        }
        {
            let (dropped, stop) = (dropped.clone(), stop.clone());
            thread::spawn(move || {
                let mut buffer = vec![0; 65536];
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(length) = far.recv(&mut buffer) {
                        let Some(to) = *client.lock().unwrap() else {
                            continue;
                        };
                        if length > cap {
                            dropped.fetch_add(1, Ordering::Relaxed);
                        } else {
                            let _ = near.send_to(&buffer[..length], to);
                        }
                    }
                }
            });
        }
        (Self { dropped, stop }, address)
    }

    fn dropped(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// What one transfer over a relay took and how many datagrams the relay refused.
struct Run {
    elapsed: Duration,
    refused: usize,
}

/// Sends `megabytes` MiB from the dialer to the listener over a path that carries `cap` bytes, and has the listener answer.
fn transfer(listening: Mtu, dialing: Mtu, cap: usize, megabytes: usize) -> Result<Run, Failure> {
    let mut relay = None;
    let (client, server) = pair(listening, dialing, |server| {
        let (started, address) = Relay::start(server, cap);
        relay = Some(started);
        address
    });
    let relay = relay.unwrap();
    let begun = Instant::now();
    let reader = thread::spawn(move || {
        let mut received = 0;
        while received < megabytes * 1024 * 1024 {
            match server.receive(Some(WAIT)) {
                Ok(Some(message)) => received += message.len(),
                other => return Err(other.err().unwrap_or(Failure::PathLost)),
            }
        }
        server.send(b"done")
    });
    let chunk = vec![7u8; 32 * 1024];
    for _ in 0..megabytes * 32 {
        client.send_timeout(&chunk, Some(WAIT))?;
    }
    reader.join().unwrap()?;
    assert_eq!(client.receive(Some(WAIT))?.unwrap(), b"done");
    Ok(Run {
        elapsed: begun.elapsed(),
        refused: relay.dropped(),
    })
}

#[test]
fn the_defaults_are_quinns_and_nothing_else_is_reported() {
    let mtu = Mtu::default();
    assert_eq!(
        (mtu.initial, mtu.min, mtu.discovery, mtu.upper_bound),
        (1200, 1200, true, 1452)
    );
    assert_eq!(MIN_MTU, 1200);
    let dialer = webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::new()))
        .build()
        .unwrap();
    assert!(dialer.non_defaults().is_empty());
    let id = identity();
    let listener = webtransport::Listener::builder(loopback(), server_tls(&id))
        .build()
        .unwrap();
    assert!(listener.non_defaults().is_empty());
    assert_eq!(listener.settings().mtu, Mtu::default());
}

#[test]
fn every_setting_is_reported_and_read_from_a_file() {
    let mtu = sized(1350, false, 1300);
    let dialer = webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::new()))
        .mtu(mtu)
        .build()
        .unwrap();
    assert_eq!(dialer.settings().mtu, mtu);
    let found: Vec<String> = dialer
        .non_defaults()
        .into_iter()
        .map(|setting| setting.setting)
        .collect();
    assert_eq!(found, ["mtu.discovery", "mtu.initial", "mtu.upper_bound"]);
    let read = toml::from_str::<Partial<webtransport::ListenerSettings>>(
        "[mtu]\ninitial = 1300\nmin = 1250\ndiscovery = false\nupper_bound = 1400\n",
    )
    .unwrap()
    .build()
    .unwrap();
    assert_eq!(
        (
            read.mtu.initial,
            read.mtu.min,
            read.mtu.discovery,
            read.mtu.upper_bound
        ),
        (1300, 1250, false, 1400)
    );
    assert!(toml::from_str::<Partial<webtransport::DialerSettings>>("[mtu]\nmax = 1\n").is_err());
}

#[test]
fn a_size_below_quinns_minimum_is_refused_naming_the_value() {
    let mut mtu = Mtu::default();
    mtu.initial = 1100;
    let error = mtu.check().unwrap_err();
    assert_eq!((error.key(), error.value()), ("initial", 1100));
    assert!(error.to_string().contains("1100"), "{error}");
    assert!(error.to_string().contains("1200"), "{error}");
    let mut mtu = Mtu::default();
    mtu.min = 900;
    assert_eq!(mtu.check().unwrap_err().key(), "min");
    let dialer = webtransport::Dialer::builder(webtransport::ClientTrust::Pinned(Vec::new()))
        .mtu(mtu)
        .build();
    assert!(dialer.is_err());
    let id = identity();
    assert!(
        webtransport::Listener::builder(loopback(), server_tls(&id))
            .mtu(mtu)
            .build()
            .is_err()
    );
}

/// What each side may put in a datagram follows the connection's size, so it shows what quinn was given.
fn largest(channel: &webtransport::Channel) -> usize {
    channel.datagrams().unwrap().max_size().unwrap()
}

#[test]
fn the_sizes_reach_the_connection_of_both_ends() {
    // Discovery off: the size stays where it started, so the initial size alone decides what fits.
    let (small, small_far) = pair(sized(1200, false, 1452), sized(1200, false, 1452), |a| a);
    let (large, large_far) = pair(sized(1400, false, 1452), sized(1400, false, 1452), |a| a);
    assert_eq!(largest(&large) - largest(&small), 200);
    assert_eq!(largest(&large_far) - largest(&small_far), 200);

    // Discovery on, bounded: it finds the bound and no more, which the same size fixed from the start fits exactly.
    let (bounded, _far) = pair(sized(1200, true, 1300), sized(1200, true, 1300), |a| a);
    let (exact, _exact_far) = pair(sized(1300, false, 1452), sized(1300, false, 1452), |a| a);
    let until = Instant::now() + WAIT;
    while largest(&bounded) < largest(&exact) {
        assert!(
            Instant::now() < until,
            "discovery stopped at {}",
            largest(&bounded)
        );
        thread::sleep(Duration::from_millis(20));
    }
    thread::sleep(Duration::from_millis(500));
    assert_eq!(largest(&bounded), largest(&exact));
}

#[test]
fn a_lowered_bound_loses_no_datagram_on_a_path_that_carries_less() {
    let cap = 1300;
    let default = transfer(Mtu::default(), Mtu::default(), cap, 8).unwrap();
    let bounded = sized(1200, true, 1300);
    let lowered = transfer(bounded, bounded, cap, 8).unwrap();
    let off = sized(1200, false, 1452);
    let fixed = transfer(off, off, cap, 8).unwrap();
    eprintln!(
        "path of {cap}: default refused {} in {:?}; upper_bound 1300 refused {} in {:?}; discovery off refused {} in {:?}",
        default.refused,
        default.elapsed,
        lowered.refused,
        lowered.elapsed,
        fixed.refused,
        fixed.elapsed
    );
    // The default probes past the path, and each probe is a datagram the path refused: on a real path, a send error.
    assert!(default.refused > 0, "the default never probed past {cap}");
    assert_eq!(lowered.refused, 0);
    assert_eq!(fixed.refused, 0);
}

#[test]
fn an_initial_size_above_the_path_stalls_and_a_lowered_one_does_not() {
    let cap = 1300;
    let above = sized(1452, false, 1452);
    let level = sized(1200, false, 1452);
    let lowered = transfer(level, level, cap, 4).unwrap();
    let stalled = transfer(above, above, cap, 4);
    eprintln!(
        "path of {cap}: initial 1200 took {:?} refusing {}; initial 1452 gave {:?}",
        lowered.elapsed,
        lowered.refused,
        stalled
            .as_ref()
            .map(|run| (run.elapsed, run.refused))
            .map_err(|failure| *failure)
    );
    assert_eq!(lowered.refused, 0);
    if let Ok(run) = stalled {
        assert!(run.refused > 0, "no packet over {cap} was sent");
    }
}
