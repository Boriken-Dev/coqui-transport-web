//! The channel contract, and choosing a transport.

use alloc::vec::Vec;
use core::time::Duration;

use url::Url;

use crate::endpoints::Endpoints;
use crate::failure::{Failure, Phase, Recovery};

/// A transport a channel runs over.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// One reliable bidirectional stream of a WebTransport session.
    WebTransport,
    /// A WebSocket: one protocol message per WebSocket message.
    WebSocket,
}

/// A reliable, ordered channel of whole messages.
///
/// It says nothing about whether the remote application acted on a message, and it is not
/// authenticated: see [`Unverified`]. Every method takes `&self`, so one thread can read while
/// another writes.
pub trait Channel: Send + Sync {
    /// Queues one message, in order.
    ///
    /// # Errors
    ///
    /// [`Failure::Protocol`] for a message outside its bounds; otherwise why the channel ended.
    fn send(&self, message: &[u8]) -> Result<(), Failure>;

    /// The next message, or `None` when the peer closed in an orderly way.
    ///
    /// # Errors
    ///
    /// [`Failure::Timeout`] when nothing arrived within `timeout`, after which the channel is still
    /// usable; `None` waits without limit. Any other failure ended the channel.
    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure>;

    /// Ends the channel and releases its resources. Safe to call more than once, and after a failure.
    fn close(&self);

    /// Changes the largest message this channel takes from now on, both ways, so a server can hold an unproven peer
    /// to a small limit and raise it once the peer is proven. A channel with no limit of its own ignores it.
    fn set_max_message(&self, _bytes: usize) {}

    /// Changes the largest message this channel reads from now on, leaving what it sends as it was. A peer's answer to anything
    /// sent after this call meets it. A channel with no limit of its own ignores it.
    fn set_max_receive(&self, _bytes: usize) {}

    /// Stages a change to the largest message this channel reads, fixed by position: the next `messages` that `receive` has not yet
    /// returned are held to the bound in force now, and every one after them to `bytes`. A driver reading ahead judges each message
    /// by its position, so a peer cannot slip a larger one in early, and one the bound allows is not refused for arriving early.
    ///
    /// Positions count from what `receive` has returned when this is called. A message the driver had already read before this
    /// call keeps the judgement it had. A later call to this, [`set_max_receive`](Self::set_max_receive) or
    /// [`set_max_message`](Self::set_max_message) replaces a change that has not taken effect yet.
    ///
    /// # Errors
    ///
    /// [`Failure::Unsupported`] from a channel that cannot stage one, which then changes nothing: the default, for any `messages`
    /// but 0, which is [`set_max_receive`](Self::set_max_receive).
    fn set_max_receive_after(&self, messages: usize, bytes: usize) -> Result<(), Failure> {
        if messages == 0 {
            self.set_max_receive(bytes);
            return Ok(());
        }
        Err(Failure::Unsupported)
    }

    /// Changes the largest message this channel sends from now on, leaving what it reads as it was, so a side that reads under a
    /// small limit can still answer up to the peer's. A channel with no limit of its own ignores it.
    fn set_max_send(&self, _bytes: usize) {}

    /// Queues one message as [`send`](Self::send) does, but waits up to `timeout` for room behind what is already queued rather
    /// than refusing at once; `None` waits for as long as the channel lives. A channel with nothing to wait for sends at once.
    ///
    /// # Errors
    ///
    /// [`Failure::Timeout`] when there was no room in time, after which the channel is still usable and the message was not sent;
    /// otherwise as [`send`](Self::send).
    fn send_timeout(&self, message: &[u8], _timeout: Option<Duration>) -> Result<(), Failure> {
        self.send(message)
    }

    /// This channel's raw datagrams, or `None` if it has none, as a WebSocket has none unless both ends agreed. There is deliberately
    /// no datagram call on the channel itself, so a caller finds out here. [`Datagrams::delivery`] says what they then are.
    fn datagrams(&self) -> Option<&dyn Datagrams> {
        None
    }

    /// The certificate chain the peer presented and this side's TLS configuration accepted, as DER, the peer's own certificate first:
    /// the server's on a client, and on a server the client's, when its configuration asked for one. `None` on a channel with no TLS
    /// or when the peer presented none. What it proves is what that configuration's verifier checked.
    fn peer_certificates(&self) -> Option<&[Vec<u8>]> {
        None
    }
}

/// How a channel's datagrams actually travel, which decides what a caller can do with them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Delivery {
    /// On the network as datagrams: lost, reordered or repeated without notice, and never held up by anything lost before them.
    Unreliable,
    /// Inside the channel's own ordered stream: in order and late rather than lost on the way, so one lost packet holds up everything
    /// behind it. One is lost only where a queue at either end is full, which [`Datagrams::dropped`] counts.
    OverStream,
}

/// Raw datagrams beside a channel's messages: delivered whole or not at all, and with no promise of arriving.
///
/// They are outside any identity proof run on the channel's messages, so a peer proof says nothing about them and TLS is all that
/// protects them. Anything that must know who sent a datagram has to establish that itself. A channel wrapping another, such as one
/// sealing its messages, has none of these unless it says so.
pub trait Datagrams: Send + Sync {
    /// The largest payload that fits one datagram now. It can change as the path does, and `None` means none can be sent, because
    /// the peer did not agree to them.
    fn max_size(&self) -> Option<usize>;

    /// Hands one datagram to the transport, which does not wait or report whether it arrived.
    ///
    /// # Errors
    ///
    /// [`Failure::Protocol`] for one larger than [`Self::max_size`], which leaves the channel usable;
    /// [`Failure::Unsupported`] when the peer does not take them; [`Failure::PathLost`] when the connection has ended.
    fn send(&self, payload: &[u8]) -> Result<(), Failure>;

    /// The next datagram, or `None` once the connection has ended.
    ///
    /// # Errors
    ///
    /// [`Failure::Timeout`] when none arrived within `timeout`; `None` waits without limit.
    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure>;

    /// How many this side discarded: arriving for a reader behind, or, for [`Delivery::OverStream`], waiting to be sent on a link
    /// that is behind. What the network lost cannot be seen from this side.
    fn dropped(&self) -> u64;

    /// How these travel now. On a channel that climbs it changes during the connection: see [`Self::path_changes`].
    fn delivery(&self) -> Delivery;

    /// Each change of path from this call on, as the [`Delivery`] now in force, or `None` for a channel whose path never changes.
    /// [`Self::max_size`] follows the path, and a datagram over it is refused rather than moved to another one.
    fn path_changes(&self) -> Option<std::sync::mpsc::Receiver<Delivery>> {
        None
    }
}

impl Channel for alloc::boxed::Box<dyn Channel> {
    fn send(&self, message: &[u8]) -> Result<(), Failure> {
        (**self).send(message)
    }

    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
        (**self).receive(timeout)
    }

    fn close(&self) {
        (**self).close();
    }

    fn set_max_message(&self, bytes: usize) {
        (**self).set_max_message(bytes);
    }

    fn set_max_receive(&self, bytes: usize) {
        (**self).set_max_receive(bytes);
    }

    fn set_max_receive_after(&self, messages: usize, bytes: usize) -> Result<(), Failure> {
        (**self).set_max_receive_after(messages, bytes)
    }

    fn set_max_send(&self, bytes: usize) {
        (**self).set_max_send(bytes);
    }

    fn send_timeout(&self, message: &[u8], timeout: Option<Duration>) -> Result<(), Failure> {
        (**self).send_timeout(message, timeout)
    }

    fn datagrams(&self) -> Option<&dyn Datagrams> {
        (**self).datagrams()
    }

    fn peer_certificates(&self) -> Option<&[Vec<u8>]> {
        (**self).peer_certificates()
    }
}

/// Opens a channel of one kind. A driver, or a test.
pub trait Dialer {
    /// The channel it opens.
    type Connection: Channel;

    /// Opens a channel to `endpoint`, giving up after `timeout`.
    ///
    /// # Errors
    ///
    /// Why it could not open, as precisely as this platform can tell.
    fn dial(
        &mut self,
        kind: Kind,
        endpoint: &Url,
        timeout: Duration,
    ) -> Result<Self::Connection, Failure>;
}

/// An optional liveness probe on a channel that just opened, before any authentication or
/// application message. It needs support at both ends.
pub trait Preflight<C: Channel> {
    /// Checks the channel.
    ///
    /// # Errors
    ///
    /// Why the channel should not be used. A path failure lets [`connect`] try WebSocket, which is
    /// how a QUIC path that opens and then stalls is caught.
    fn check(&mut self, kind: Kind, channel: &C) -> Result<(), Failure>;
}

/// No probe.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPreflight;

impl<C: Channel> Preflight<C> for NoPreflight {
    fn check(&mut self, _: Kind, _: &C) -> Result<(), Failure> {
        Ok(())
    }
}

/// A channel that is open and **not yet trusted**. Run the peer's identity proof on it before
/// delivering any application message. Neither a URL, a host name nor TLS alone proves a peer.
#[derive(Debug)]
#[must_use = "an opened channel does nothing until its peer is proven"]
pub struct Unverified<C: Channel> {
    kind: Kind,
    channel: C,
}

impl<C: Channel> Unverified<C> {
    /// The transport that opened.
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// The channel, to run the peer proof on.
    pub const fn channel(&self) -> &C {
        &self.channel
    }

    /// Gives the channel to the application. Call this only after the proof succeeded.
    pub fn into_verified(self) -> C {
        self.channel
    }
}

/// Opens WebTransport first, and WebSocket when that fails on the path before anything crossed.
///
/// Certificate, proof and protocol failures never fall back, and a pinned WebTransport failure
/// never reaches WebSocket. Nothing is retried once a channel is returned: recovering a live
/// session is the application's to do, by [`Failure::recovery`].
///
/// # Errors
///
/// The failure that ended the attempt; [`Failure::Unsupported`] when nothing was usable.
pub fn connect<D, P>(
    endpoints: &Endpoints,
    dialer: &mut D,
    probe: &mut P,
    timeout: Duration,
) -> Result<Unverified<D::Connection>, Failure>
where
    D: Dialer,
    P: Preflight<D::Connection>,
{
    if let Some(endpoint) = endpoints.webtransport() {
        match open(Kind::WebTransport, endpoint, dialer, probe, timeout) {
            Ok(link) => return Ok(link),
            Err(reason)
                if endpoints.certificate_pins().is_empty()
                    && reason.recovery(
                        Kind::WebTransport,
                        Phase::Opening,
                        endpoints.websocket().is_some(),
                    ) == Recovery::VerifyFallback => {}
            Err(reason) => return Err(reason),
        }
    }
    match endpoints.websocket() {
        Some(endpoint) => open(Kind::WebSocket, endpoint, dialer, probe, timeout),
        None => Err(Failure::Unsupported),
    }
}

fn open<D, P>(
    kind: Kind,
    endpoint: &Url,
    dialer: &mut D,
    probe: &mut P,
    timeout: Duration,
) -> Result<Unverified<D::Connection>, Failure>
where
    D: Dialer,
    P: Preflight<D::Connection>,
{
    let channel = dialer.dial(kind, endpoint, timeout)?;
    if let Err(reason) = probe.check(kind, &channel) {
        channel.close();
        return Err(reason);
    }
    Ok(Unverified { kind, channel })
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::rc::Rc;
    use alloc::string::{String, ToString};
    use core::cell::RefCell;

    use super::*;
    use crate::endpoints::CertificatePin;

    type Log = Rc<RefCell<Vec<String>>>;

    struct TestChannel {
        closed: core::sync::atomic::AtomicUsize,
    }

    impl Channel for TestChannel {
        fn send(&self, _: &[u8]) -> Result<(), Failure> {
            Ok(())
        }
        fn receive(&self, _: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
            Ok(None)
        }
        fn close(&self) {
            self.closed
                .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        }
    }

    struct TestDialer {
        log: Log,
        webtransport: Result<(), Failure>,
    }

    impl Dialer for TestDialer {
        type Connection = TestChannel;

        fn dial(&mut self, kind: Kind, _: &Url, _: Duration) -> Result<TestChannel, Failure> {
            self.log.borrow_mut().push(format!("dial:{kind:?}"));
            if kind == Kind::WebTransport {
                self.webtransport?;
            }
            Ok(TestChannel { closed: 0.into() })
        }
    }

    struct TestProbe {
        log: Log,
        problem: Failure,
    }

    impl Preflight<TestChannel> for TestProbe {
        fn check(&mut self, kind: Kind, channel: &TestChannel) -> Result<(), Failure> {
            self.log.borrow_mut().push(format!("probe:{kind:?}"));
            if kind == Kind::WebTransport {
                let _ = channel;
                return Err(self.problem);
            }
            Ok(())
        }
    }

    fn both() -> Endpoints {
        Endpoints::builder()
            .webtransport("https://peer.example:4433/")
            .websocket("wss://peer.example/")
            .build()
            .unwrap()
    }

    fn log() -> Log {
        Rc::new(RefCell::new(Vec::new()))
    }

    fn logged(log: &Log) -> Vec<String> {
        log.borrow().clone()
    }

    #[test]
    fn webtransport_wins_when_it_opens() {
        let log = log();
        let mut dialer = TestDialer {
            log: log.clone(),
            webtransport: Ok(()),
        };
        let link = connect(
            &both(),
            &mut dialer,
            &mut NoPreflight,
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(link.kind(), Kind::WebTransport);
        assert_eq!(logged(&log), ["dial:WebTransport".to_string()]);
    }

    #[test]
    fn a_probe_failing_on_the_path_falls_back_and_closes_the_first_channel() {
        for problem in [Failure::SuspectedMtu, Failure::Timeout] {
            let log = log();
            let mut dialer = TestDialer {
                log: log.clone(),
                webtransport: Ok(()),
            };
            let mut probe = TestProbe {
                log: log.clone(),
                problem,
            };
            let link = connect(&both(), &mut dialer, &mut probe, Duration::from_secs(1)).unwrap();
            assert_eq!(link.kind(), Kind::WebSocket);
            assert_eq!(
                logged(&log),
                [
                    "dial:WebTransport",
                    "probe:WebTransport",
                    "dial:WebSocket",
                    "probe:WebSocket"
                ]
            );
        }
    }

    #[test]
    fn a_certificate_failure_never_touches_websocket() {
        let log = log();
        let mut dialer = TestDialer {
            log: log.clone(),
            webtransport: Err(Failure::Certificate),
        };
        let result = connect(
            &both(),
            &mut dialer,
            &mut NoPreflight,
            Duration::from_secs(1),
        );
        assert!(matches!(result, Err(Failure::Certificate)));
        assert_eq!(logged(&log), ["dial:WebTransport".to_string()]);
    }

    #[test]
    fn a_pinned_endpoint_never_downgrades_even_on_a_path_failure() {
        let pinned = Endpoints::builder()
            .webtransport("https://peer.example:4433/")
            .websocket("wss://peer.example/")
            .certificate_pin(CertificatePin::from_bytes([0xab; 32]))
            .build()
            .unwrap();
        let log = log();
        let mut dialer = TestDialer {
            log: log.clone(),
            webtransport: Err(Failure::Timeout),
        };
        let result = connect(
            &pinned,
            &mut dialer,
            &mut NoPreflight,
            Duration::from_secs(1),
        );
        assert!(matches!(result, Err(Failure::Timeout)));
        assert_eq!(logged(&log), ["dial:WebTransport".to_string()]);
    }

    /// A driver of its own that stages a bound, which the default would refuse.
    struct Staging;

    impl Channel for Staging {
        fn send(&self, _: &[u8]) -> Result<(), Failure> {
            Ok(())
        }
        fn receive(&self, _: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
            Ok(None)
        }
        fn close(&self) {}
        fn set_max_receive_after(&self, _: usize, _: usize) -> Result<(), Failure> {
            Ok(())
        }
    }

    /// A channel that only says what it reads.
    struct Plain(core::sync::atomic::AtomicUsize);

    impl Channel for Plain {
        fn send(&self, _: &[u8]) -> Result<(), Failure> {
            Ok(())
        }
        fn receive(&self, _: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
            Ok(None)
        }
        fn close(&self) {}
        fn set_max_receive(&self, bytes: usize) {
            self.0.store(bytes, core::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn a_channel_that_cannot_stage_a_bound_refuses_and_changes_nothing() {
        let plain = Plain(5.into());
        assert_eq!(plain.set_max_receive_after(1, 9), Err(Failure::Unsupported));
        assert_eq!(plain.0.load(core::sync::atomic::Ordering::SeqCst), 5);
        // No message waits under the old bound: that is the bound itself.
        assert_eq!(plain.set_max_receive_after(0, 9), Ok(()));
        assert_eq!(plain.0.load(core::sync::atomic::Ordering::SeqCst), 9);
    }

    #[test]
    fn a_boxed_channel_stages_through_its_driver() {
        let boxed: alloc::boxed::Box<dyn Channel> = alloc::boxed::Box::new(Staging);
        assert_eq!(Channel::set_max_receive_after(&boxed, 2, 7), Ok(()));
    }

    #[test]
    fn direct_websocket_remains_supported() {
        let only = Endpoints::builder()
            .websocket("wss://peer.example/")
            .build()
            .unwrap();
        let log = log();
        let mut dialer = TestDialer {
            log: log.clone(),
            webtransport: Ok(()),
        };
        let link = connect(&only, &mut dialer, &mut NoPreflight, Duration::from_secs(1)).unwrap();
        assert_eq!(link.kind(), Kind::WebSocket);
    }
}
