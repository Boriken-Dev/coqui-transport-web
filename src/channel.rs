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
