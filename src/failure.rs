//! What can go wrong on a channel, and whether another transport may be tried.

use core::fmt;

use crate::channel::Kind;

/// A failure a driver can distinguish.
///
/// A browser's generic error is not proof of an MTU problem or a certificate rejection, so a
/// driver reports only what it knows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Failure {
    /// The transport is not available here.
    Unsupported,
    /// A deadline passed before the operation finished.
    Timeout,
    /// The network path was lost.
    PathLost,
    /// A live channel stopped making forward progress.
    NoProgress,
    /// A probe suggests a path that drops large packets; never proven by a browser.
    SuspectedMtu,
    /// A certificate or pin was positively rejected.
    Certificate,
    /// The peer failed its identity proof.
    PeerProof,
    /// The peer broke the wire format, or a message was outside its bounds.
    Protocol,
    /// The peer or a policy refused.
    Permission,
    /// The caller cancelled.
    Cancelled,
}

impl Failure {
    /// Whether this says something about the network path rather than about the peer.
    #[must_use]
    pub const fn is_path(self) -> bool {
        matches!(
            self,
            Self::Unsupported
                | Self::Timeout
                | Self::PathLost
                | Self::NoProgress
                | Self::SuspectedMtu
        )
    }

    /// Whether WebSocket may be tried after this failure on `failed`.
    ///
    /// `has_websocket` means the peer explicitly advertised a WebSocket endpoint: one is never
    /// derived from the WebTransport URL. A confirmed certificate or key rejection is never
    /// treated as path loss, so it can never cause a downgrade. While opening, a peer that breaks
    /// the wire format may simply not offer this transport, and the same peer must still prove
    /// itself on the other. Once open, it is a proven peer or someone on the path breaking it.
    #[must_use]
    pub const fn recovery(self, failed: Kind, phase: Phase, has_websocket: bool) -> Recovery {
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

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "the transport is not available",
            Self::Timeout => "a deadline passed",
            Self::PathLost => "the network path was lost",
            Self::NoProgress => "the channel stopped making progress",
            Self::SuspectedMtu => "the path may be dropping large packets",
            Self::Certificate => "a certificate or pin was rejected",
            Self::PeerProof => "the peer failed its identity proof",
            Self::Protocol => "the peer broke the wire format",
            Self::Permission => "the operation was refused",
            Self::Cancelled => "the operation was cancelled",
        })
    }
}

impl core::error::Error for Failure {}

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

#[cfg(test)]
mod tests {
    use super::*;

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
