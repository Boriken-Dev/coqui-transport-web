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
    /// How long opening may take in total: TCP or QUIC, TLS, and the HTTP upgrade.
    pub handshake: Duration,
    /// Bytes queued to send, past which `send` answers `Failure::NoProgress` rather than growing.
    pub queued_bytes: usize,
    /// How long a peer may take nothing while there is something to send, where a driver waits at all. It ends the channel
    /// with `Failure::NoProgress`.
    pub send: Duration,
    /// Silence after which a WebSocket peer is pinged, and twice this after which it is gone: `Failure::NoProgress`.
    pub idle: Duration,
    /// Datagrams held for a slow reader, past which new ones are discarded and counted. Unlike a message, a datagram slows nobody.
    /// Over a WebSocket it also bounds those waiting to be sent.
    pub pending_datagrams: usize,
    /// The largest datagram over a WebSocket, in bytes, whichever way it goes. There is no packet to fit there, so it is a choice,
    /// and one over it is refused here and discarded from a peer. WebTransport's comes from the path.
    pub websocket_datagram: usize,
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

    /// Sets how long opening may take in total.
    #[must_use]
    pub const fn with_handshake(mut self, limit: Duration) -> Self {
        self.handshake = limit;
        self
    }

    /// Sets how many bytes may wait to be sent.
    #[must_use]
    pub const fn with_queued_bytes(mut self, bytes: usize) -> Self {
        self.queued_bytes = bytes;
        self
    }

    /// Sets how long one send may wait.
    #[must_use]
    pub const fn with_send(mut self, limit: Duration) -> Self {
        self.send = limit;
        self
    }

    /// Sets the silence after which a peer is pinged.
    #[must_use]
    pub const fn with_idle(mut self, limit: Duration) -> Self {
        self.idle = limit;
        self
    }

    /// Sets how many datagrams wait for a slow reader.
    #[must_use]
    pub const fn with_pending_datagrams(mut self, datagrams: usize) -> Self {
        self.pending_datagrams = datagrams;
        self
    }

    /// Sets the largest datagram over a WebSocket.
    #[must_use]
    pub const fn with_websocket_datagram(mut self, bytes: usize) -> Self {
        self.websocket_datagram = bytes;
        self
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message: DEFAULT_MAX_MESSAGE,
            pending: 64,
            handshake: Duration::from_secs(10),
            queued_bytes: 64 * 1024 * 1024,
            send: Duration::from_secs(30),
            idle: Duration::from_secs(60),
            pending_datagrams: 256,
            websocket_datagram: 64 * 1024,
        }
    }
}

/// Abandons one pending handshake from another thread, from [`websocket::Pending::canceller`](crate::websocket::Pending::canceller)
/// or [`webtransport::Pending::canceller`](crate::webtransport::Pending::canceller). Cloning it gives another handle on the same one.
#[derive(Clone)]
pub struct Cancel(alloc::sync::Arc<Abandon>);

impl Cancel {
    /// Stops the handshake if it has not finished: it returns [`Failure::Cancelled`] and its connection closes. Returns whether
    /// this call stopped it; once a handshake has finished, or was already stopped, it does nothing.
    pub fn cancel(&self) -> bool {
        let mut stage = self.0.stage.lock().unwrap_or_else(PoisonError::into_inner);
        let Stage::Waiting(interrupt) = core::mem::replace(&mut *stage, Stage::Cancelled) else {
            return false;
        };
        drop(stage);
        if let Some(interrupt) = interrupt {
            interrupt();
        }
        true
    }
}

impl core::fmt::Debug for Cancel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let stage = self.0.stage.lock().unwrap_or_else(PoisonError::into_inner);
        f.write_str(match *stage {
            Stage::Waiting(_) => "Cancel(waiting)",
            Stage::Cancelled => "Cancel(cancelled)",
            Stage::Finished => "Cancel(finished)",
        })
    }
}

/// What a [`Cancel`] acts on: one handshake, and how to stop it while it waits on the network.
#[derive(Default)]
pub(crate) struct Abandon {
    stage: Mutex<Stage>,
}

enum Stage {
    Waiting(Option<alloc::boxed::Box<dyn FnOnce() + Send>>),
    Cancelled,
    Finished,
}

impl Default for Stage {
    fn default() -> Self {
        Self::Waiting(None)
    }
}

impl Abandon {
    pub(crate) fn handle(self: &alloc::sync::Arc<Self>) -> Cancel {
        Cancel(alloc::sync::Arc::clone(self))
    }

    /// Sets how a cancel interrupts the wait, made only the first time and only while the handshake waits.
    pub(crate) fn interrupt_with(
        &self,
        make: impl FnOnce() -> Option<alloc::boxed::Box<dyn FnOnce() + Send>>,
    ) {
        let mut stage = self.stage.lock().unwrap_or_else(PoisonError::into_inner);
        if let Stage::Waiting(interrupt @ None) = &mut *stage {
            *interrupt = make();
        }
    }

    pub(crate) fn cancelled(&self) -> bool {
        matches!(
            *self.stage.lock().unwrap_or_else(PoisonError::into_inner),
            Stage::Cancelled
        )
    }

    /// Ends the wait: a cancel that came first wins, and one that comes later does nothing.
    pub(crate) fn finish(&self) -> Result<(), Failure> {
        let mut stage = self.stage.lock().unwrap_or_else(PoisonError::into_inner);
        if matches!(*stage, Stage::Cancelled) {
            return Err(Failure::Cancelled);
        }
        *stage = Stage::Finished;
        Ok(())
    }

    /// Finishes the wait when dropped, so a handshake that returns early releases what the interrupt holds.
    pub(crate) const fn finishing(&self) -> Finishing<'_> {
        Finishing(self)
    }
}

pub(crate) struct Finishing<'a>(&'a Abandon);

impl Drop for Finishing<'_> {
    fn drop(&mut self) {
        let _ = self.0.finish();
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
