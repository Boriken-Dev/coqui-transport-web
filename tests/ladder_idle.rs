//! What a climbed channel costs at rest and leaves behind, measured for the whole process, so this file holds one test.
#![allow(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::result_large_err
)]

use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

use coqui_web::webrtc::{Port, Settings};
use coqui_web::websocket::{self, Frames};
use coqui_web::{Channel, Delivery, Dialer, Kind};
use url::Url;

const WAIT: Duration = Duration::from_secs(30);
const REST: Duration = Duration::from_secs(10);

#[cfg(windows)]
fn process_cpu() -> Duration {
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
        fn GetProcessTimes(
            process: isize,
            created: *mut FileTime,
            exited: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
    }
    let mut times = [FileTime::default(); 4];
    let [created, exited, kernel, user] = &mut times;
    // SAFETY: each pointer is a live out-parameter of the size the call writes.
    let done = unsafe { GetProcessTimes(GetCurrentProcess(), created, exited, kernel, user) };
    assert_ne!(done, 0);
    let ticks = |time: &FileTime| (u64::from(time.high) << 32) | u64::from(time.low);
    Duration::from_nanos((ticks(kernel) + ticks(user)) * 100)
}

#[cfg(target_os = "linux")]
fn process_cpu() -> Duration {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let after_name = stat.rsplit(')').next().unwrap();
    let fields: Vec<&str> = after_name.split_whitespace().collect();
    // utime and stime, counted from the state field, in clock ticks of 10 ms on every kernel this runs on.
    let ticks: u64 = fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap();
    Duration::from_millis(ticks * 10)
}

#[cfg(not(any(windows, target_os = "linux")))]
fn process_cpu() -> Duration {
    Duration::ZERO
}

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
