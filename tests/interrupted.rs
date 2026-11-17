//! A signal that reaches a dialer while it waits for the server's handshake does not end the dial.
#![cfg(all(feature = "websocket", unix))]
#![allow(clippy::std_instead_of_core, clippy::std_instead_of_alloc)]

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use coqui_transport_web::websocket;
use coqui_transport_web::{Channel, Dialer, Kind};
use url::Url;

const WAIT: Duration = Duration::from_secs(30);

extern "C" fn noted(_signal: libc::c_int) {}

#[test]
fn a_signal_while_the_server_is_slow_to_answer_does_not_lose_the_path() {
    // A handler, as a program that watches its children has: with a timeout set on the socket, a receive is
    // interrupted by it even where the handler asks for calls to restart.
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = noted as extern "C" fn(libc::c_int) as usize;
    action.sa_flags = libc::SA_RESTART;
    // SAFETY: `action` is fully initialised, and the handler does nothing.
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(
            libc::sigaction(libc::SIGUSR1, &action, core::ptr::null_mut()),
            0
        );
    }

    let listener =
        websocket::Listener::builder("127.0.0.1:0".parse().unwrap(), websocket::ServerTls::Plain)
            .build()
            .unwrap();
    let url = Url::parse(&format!("ws://{}/channel", listener.local_addr().unwrap())).unwrap();
    let server = thread::spawn(move || {
        let pending = listener.next(Some(WAIT)).unwrap();
        // The dialer is by now blocked reading the answer.
        thread::sleep(Duration::from_millis(600));
        pending.handshake().unwrap()
    });
    let (who, ready) = mpsc::channel();
    let client = thread::spawn(move || {
        // SAFETY: `pthread_self` has no preconditions.
        who.send(unsafe { libc::pthread_self() }).unwrap();
        websocket::Dialer::builder()
            .build()
            .unwrap()
            .dial(Kind::WebSocket, &url, WAIT)
            .map(|channel| channel.close())
    });
    let client_thread = ready.recv().unwrap();
    for _ in 0..3 {
        thread::sleep(Duration::from_millis(100));
        // SAFETY: the dialing thread is alive until the server has answered, which waits for the signals below.
        unsafe { libc::pthread_kill(client_thread, libc::SIGUSR1) };
    }
    let channel = server.join().unwrap();
    assert_eq!(client.join().unwrap(), Ok(()));
    channel.close();
}
