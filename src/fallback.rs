//! Choosing a transport: WebTransport first, WebSocket where the path stops it, and never past a
//! rejection.
//!
//! [`connect`] dials the endpoints a peer advertised, probes the channel that opened, and returns
//! it as [`Unverified`]: connection fallback ends there, and proving who answered, and
//! reconciling an application's session after a failure, are the application's. [`FailureExt`]
//! says what a failure allows next.

use core::time::Duration;

use coqui_transport::{Channel, Failure};
use url::Url;

use crate::endpoint::Endpoints;

/// A transport a channel runs over.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// One reliable bidirectional stream of a WebTransport session.
    WebTransport,
    /// A WebSocket: one protocol message per WebSocket message.
    WebSocket,
}

/// Whether application traffic has already crossed the channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Before any peer authentication or application message.
    Opening,
    /// A live authenticated channel, which may have unacknowledged operations.
    Active,
}

/// What a failed channel allows next. A new channel is never trusted until proven.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Recovery {
    /// Fail closed.
    Deny,
    /// Dial WebSocket, prove the same peer, then start the application.
    VerifyFallback,
    /// Dial WebSocket, prove the same peer, and reconcile the application's session. An
    /// operation of uncertain outcome is never replayed automatically.
    VerifyAndReconcile,
}

/// What a [`Failure`] allows next, which `coqui-transport` leaves to the transports that fall back.
pub trait FailureExt {
    /// Whether WebSocket may be tried after this failure on `failed`.
    ///
    /// `has_websocket` means the peer explicitly advertised a WebSocket endpoint: one is never
    /// derived from the WebTransport URL. A confirmed certificate or key rejection is never
    /// treated as path loss, so it can never cause a downgrade. While opening, a peer that breaks
    /// the wire format may simply not offer this transport, and the same peer must still prove
    /// itself on the other. Once open, it is a proven peer or someone on the path breaking it.
    fn recovery(self, failed: Kind, phase: Phase, has_websocket: bool) -> Recovery;
}

impl FailureExt for Failure {
    fn recovery(self, failed: Kind, phase: Phase, has_websocket: bool) -> Recovery {
        let worth_trying =
            self.is_path() || (matches!(self, Self::Protocol) && matches!(phase, Phase::Opening));
        if !has_websocket || !matches!(failed, Kind::WebTransport) || !worth_trying {
            return Recovery::Deny;
        }
        match phase {
            Phase::Opening => Recovery::VerifyFallback,
            Phase::Active => Recovery::VerifyAndReconcile,
        }
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
/// session is the application's to do, by [`FailureExt::recovery`].
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
    use alloc::vec::Vec;
    use core::cell::RefCell;

    use super::*;
    use crate::endpoint::CertificatePin;

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

    const PATH: [Failure; 5] = [
        Failure::Unsupported,
        Failure::Timeout,
        Failure::PathLost,
        Failure::NoProgress,
        Failure::SuspectedMtu,
    ];
    const PEER: [Failure; 4] = [
        Failure::Certificate,
        Failure::PeerProof,
        Failure::Permission,
        Failure::Cancelled,
    ];

    #[test]
    fn a_path_failure_falls_back_with_identity_verification() {
        for failure in PATH {
            assert_eq!(
                failure.recovery(Kind::WebTransport, Phase::Opening, true),
                Recovery::VerifyFallback
            );
            assert_eq!(
                failure.recovery(Kind::WebTransport, Phase::Active, true),
                Recovery::VerifyAndReconcile
            );
        }
    }

    #[test]
    fn a_protocol_failure_falls_back_only_while_opening() {
        assert_eq!(
            Failure::Protocol.recovery(Kind::WebTransport, Phase::Opening, true),
            Recovery::VerifyFallback
        );
        assert_eq!(
            Failure::Protocol.recovery(Kind::WebTransport, Phase::Active, true),
            Recovery::Deny
        );
        assert_eq!(
            Failure::Protocol.recovery(Kind::WebTransport, Phase::Opening, false),
            Recovery::Deny
        );
    }

    #[test]
    fn a_peer_or_certificate_rejection_never_downgrades() {
        for failure in PEER {
            for phase in [Phase::Opening, Phase::Active] {
                assert_eq!(
                    failure.recovery(Kind::WebTransport, phase, true),
                    Recovery::Deny
                );
            }
        }
    }

    #[test]
    fn no_recovery_from_websocket_or_without_an_advertised_endpoint() {
        assert_eq!(
            Failure::PathLost.recovery(Kind::WebSocket, Phase::Active, true),
            Recovery::Deny
        );
        assert_eq!(
            Failure::PathLost.recovery(Kind::WebTransport, Phase::Active, false),
            Recovery::Deny
        );
    }
}
