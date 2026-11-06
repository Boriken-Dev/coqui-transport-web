//! What a climbed channel costs at rest and leaves behind, measured for the whole process, so this file holds one test.
#![allow(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::result_large_err
)]

use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

use coqui_web_channel::webrtc::{Port, Settings};
use coqui_web_channel::websocket::{self, Frames};
use coqui_web_channel::{Channel, Delivery, Dialer, Kind};
use url::Url;

mod cpu;

use cpu::process_cpu;

const WAIT: Duration = Duration::from_secs(30);
const REST: Duration = Duration::from_secs(10);

#[cfg(target_os = "linux")]
fn thread_count() -> Option<usize> {
    Some(std::fs::read_dir("/proc/self/task").unwrap().count())
}

#[cfg(not(target_os = "linux"))]
fn thread_count() -> Option<usize> {
    None
}

#[test]
fn a_climbed_channel_at_rest_takes_no_cpu_and_closing_ends_every_thread() {
    let before = thread_count();
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let port = Port::bind(any, Settings::default()).unwrap();
    let listener = websocket::Listener::bind(any, None)
        .unwrap()
        .with_frames(Frames::Binary)
        .with_webrtc(&port);
    let url = Url::parse(&format!("ws://{}/", listener.local_addr().unwrap())).unwrap();
    let (near, far) = thread::scope(|scope| {
        let accepted = scope.spawn(|| listener.accept(Some(WAIT)).unwrap());
        let near = websocket::Dialer::new()
            .with_frames(Frames::Binary)
            .with_webrtc(Settings::default())
            .dial(Kind::WebSocket, &url, WAIT)
            .unwrap();
        (near, accepted.join().unwrap())
    });
    let near_datagrams = near.datagrams().unwrap();
    let far_datagrams = far.datagrams().unwrap();
    let changes = near_datagrams.path_changes().unwrap();
    assert_eq!(changes.recv_timeout(WAIT), Ok(Delivery::Unreliable));
    let started = Instant::now();
    while far_datagrams.delivery() != Delivery::Unreliable {
        assert!(started.elapsed() < WAIT);
        thread::sleep(Duration::from_millis(5));
    }
    near_datagrams.send(b"up").unwrap();
    let _ = far_datagrams.receive(Some(Duration::from_secs(1)));

    let cpu = process_cpu();
    let started = Instant::now();
    thread::sleep(REST);
    let used = process_cpu().saturating_sub(cpu);
    let share = used.as_secs_f64() / started.elapsed().as_secs_f64();
    println!("at rest: {used:?} of CPU in {:?}", started.elapsed());
    assert!(
        share < 0.01,
        "{used:?} of CPU in {:?} with nothing to do",
        started.elapsed()
    );
    assert_eq!(near_datagrams.delivery(), Delivery::Unreliable);

    near.close();
    far.close();
    drop((near, far, listener, port));
    if let Some(before) = before {
        let started = Instant::now();
        while thread_count() != Some(before) {
            assert!(
                started.elapsed() < WAIT,
                "{:?} threads, from {before}",
                thread_count()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}
