//! What the drivers share: the bounds, and the one place a received message waits.

use alloc::vec::Vec;
use core::time::Duration;
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::sync::{Mutex, PoisonError};

use crate::failure::Failure;
use crate::frame::DEFAULT_MAX_MESSAGE;

/// The bounds a peer cannot exceed. Every value has a finite default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Limits {
    /// The largest message accepted or sent, in bytes. Larger ends the channel.
    pub max_message: usize,
    /// Messages held for a slow reader, after which the driver stops reading from the peer.
    pub pending: usize,
    /// How long opening may take: TCP or QUIC, TLS, and the HTTP upgrade.
    pub handshake: Duration,
}

impl Limits {
    /// Sets the largest message.
    #[must_use]
    pub const fn with_max_message(mut self, bytes: usize) -> Self {
        self.max_message = bytes;
        self
    }

    /// Sets how many messages wait for a slow reader.
    #[must_use]
    pub const fn with_pending(mut self, messages: usize) -> Self {
        self.pending = messages;
        self
    }

    /// Sets how long opening may take.
    #[must_use]
    pub const fn with_handshake(mut self, limit: Duration) -> Self {
        self.handshake = limit;
        self
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message: DEFAULT_MAX_MESSAGE,
            pending: 64,
            handshake: Duration::from_secs(10),
        }
    }
}

/// Decides whether a source address may start a handshake.
#[cfg(any(feature = "websocket", feature = "webtransport"))]
pub(crate) type Admission = alloc::sync::Arc<dyn Fn(core::net::SocketAddr) -> bool + Send + Sync>;

/// What the driver's worker hands to the channel's reader. An `Err` ends the channel.
pub(crate) type Received = Result<Vec<u8>, Failure>;

/// The receiving half of a channel. A failure stays: every later read reports it again.
#[derive(Debug)]
pub(crate) struct Inbox {
    queue: Mutex<Receiver<Received>>,
    ended: Mutex<Option<Result<(), Failure>>>,
}

impl Inbox {
    pub(crate) fn new(queue: Receiver<Received>) -> Self {
        Self {
            queue: Mutex::new(queue),
            ended: Mutex::new(None),
        }
    }

    /// The next message; `Ok(None)` when the worker ended in order, which it does by dropping its
    /// sender, or by sending the failure that ended it.
    pub(crate) fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure> {
        if let Some(ended) = *self.ended.lock().unwrap_or_else(PoisonError::into_inner) {
            return ended.map(|()| None);
        }
        let queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        let next = match timeout {
            None => queue.recv().map_err(|_| RecvTimeoutError::Disconnected),
            Some(limit) if limit.is_zero() => queue.try_recv().map_err(|error| match error {
                TryRecvError::Empty => RecvTimeoutError::Timeout,
                TryRecvError::Disconnected => RecvTimeoutError::Disconnected,
            }),
            Some(limit) => queue.recv_timeout(limit),
        };
        match next {
            Ok(Ok(message)) => Ok(Some(message)),
            Ok(Err(failure)) => {
                *self.ended.lock().unwrap_or_else(PoisonError::into_inner) = Some(Err(failure));
                Err(failure)
            }
            Err(RecvTimeoutError::Timeout) => Err(Failure::Timeout),
            Err(RecvTimeoutError::Disconnected) => {
                *self.ended.lock().unwrap_or_else(PoisonError::into_inner) = Some(Ok(()));
                Ok(None)
            }
        }
    }
}
