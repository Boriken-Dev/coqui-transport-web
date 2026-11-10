//! What the drivers share: the bounds, and the one place a received message waits.

use alloc::vec::Vec;
use core::time::Duration;
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::sync::{Mutex, PoisonError};

use crate::frame::DEFAULT_MAX_MESSAGE;
use coqui_transport::Failure;

/// The bounds a peer cannot exceed. Every value has a finite default.
///
/// A [`coqui_builder::Describe`] type a file fills: every key is optional (an absent one is its default), an unknown key is
/// refused, and a duration is a number with an optional unit (`30`, `250ms`, `1.5h`). It is `#[non_exhaustive]`: start from
/// [`Default`] and assign the fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq, coqui_builder::Describe)]
#[map(deny_unknown_fields)]
#[non_exhaustive]
pub struct Limits {
    /// The largest message accepted or sent, in bytes. Larger ends the channel.
    #[map(default = Limits::default().max_message)]
    pub max_message: usize,
    /// Messages read and held for a slow reader, after which the driver stops reading from the peer. Each channel starts here,
    /// and [`Channel::set_pending`](crate::Channel::set_pending) changes it for one. 0 is 1.
    #[map(default = Limits::default().pending)]
    pub pending: usize,
    /// How long opening may take in total: TCP or QUIC, TLS, and the HTTP upgrade.
    #[map(default = Limits::default().handshake)]
    pub handshake: Duration,
    /// Bytes queued to send, past which `send` answers `Failure::NoProgress` rather than growing.
    #[map(default = Limits::default().queued_bytes)]
    pub queued_bytes: usize,
    /// How long a peer may take nothing while there is something to send, where a driver waits at all. It ends the channel
    /// with `Failure::NoProgress`.
    #[map(default = Limits::default().send)]
    pub send: Duration,
    /// Silence after which a WebSocket peer is pinged, and twice this after which it is gone: `Failure::NoProgress`.
    #[map(default = Limits::default().idle)]
    pub idle: Duration,
    /// Datagrams held for a slow reader, past which new ones are discarded and counted. Unlike a message, a datagram slows nobody.
    /// Over a WebSocket it also bounds those waiting to be sent.
    #[map(default = Limits::default().pending_datagrams)]
    pub pending_datagrams: usize,
    /// The largest datagram over a WebSocket, in bytes, whichever way it goes. There is no packet to fit there, so it is a choice,
    /// and one over it is refused here and discarded from a peer. WebTransport's comes from the path.
    #[map(default = Limits::default().websocket_datagram)]
    pub websocket_datagram: usize,
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

/// What a channel's reader lets its driver read: the largest message, by the message's position in the stream, and how many
/// messages ahead of the reader. A staged bound takes effect at a position fixed when it is staged, however far the driver has
/// read ahead.
#[derive(Debug)]
pub(crate) struct Reading {
    bounds: Mutex<Bounds>,
    // Messages the reader has taken: the position the next `receive` returns.
    taken: core::sync::atomic::AtomicU64,
    // Messages read that the reader has not taken, past which the driver reads nothing more. At least 1.
    ahead: core::sync::atomic::AtomicUsize,
}

#[derive(Debug)]
struct Bounds {
    now: usize,
    // From this position on, this bound.
    staged: Option<(u64, usize)>,
}

impl Reading {
    pub(crate) const fn new(bytes: usize, ahead: usize) -> Self {
        Self {
            bounds: Mutex::new(Bounds {
                now: bytes,
                staged: None,
            }),
            taken: core::sync::atomic::AtomicU64::new(0),
            ahead: core::sync::atomic::AtomicUsize::new(at_least_one(ahead)),
        }
    }

    /// Sets how many messages the driver may hold for the reader. 0 is 1: a message is read before `receive` returns it.
    pub(crate) fn set_ahead(&self, messages: usize) {
        self.ahead
            .store(at_least_one(messages), core::sync::atomic::Ordering::SeqCst);
    }

    /// Whether the driver may read the message at `position`, counted from the first it read: whether it holds fewer than the
    /// limit for the reader.
    pub(crate) fn may_read(&self, position: u64) -> bool {
        let held = position.saturating_sub(self.taken.load(core::sync::atomic::Ordering::SeqCst));
        let ahead = self.ahead.load(core::sync::atomic::Ordering::SeqCst);
        held < u64::try_from(ahead).unwrap_or(u64::MAX)
    }

    /// Replaces the bound for every message not yet read, and any staged change.
    pub(crate) fn set(&self, bytes: usize) {
        let mut bounds = self.bounds.lock().unwrap_or_else(PoisonError::into_inner);
        bounds.now = bytes;
        bounds.staged = None;
    }

    /// The next `messages` the reader has not taken keep the bound in force; those after them are held to `bytes`.
    pub(crate) fn stage(&self, messages: usize, bytes: usize) {
        let from = self
            .taken
            .load(core::sync::atomic::Ordering::SeqCst)
            .saturating_add(u64::try_from(messages).unwrap_or(u64::MAX));
        let mut bounds = self.bounds.lock().unwrap_or_else(PoisonError::into_inner);
        bounds.staged = Some((from, bytes));
    }

    /// Called by the reader for each message `receive` returns.
    pub(crate) fn taken(&self) {
        self.taken
            .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }

    /// The bound for the message at `position`, counted from the first the channel read. Positions only grow, so a staged change
    /// is made the bound in force once reached.
    pub(crate) fn at(&self, position: u64) -> usize {
        let mut bounds = self.bounds.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((from, bytes)) = bounds.staged
            && position >= from
        {
            bounds.now = bytes;
            bounds.staged = None;
        }
        bounds.now
    }

    /// The bound in force now, for `Debug`.
    pub(crate) fn current(&self) -> usize {
        self.bounds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .now
    }
}

const fn at_least_one(messages: usize) -> usize {
    if messages == 0 { 1 } else { messages }
}

/// Why a local address could not be bound: taken or not allowed, or not this host's to bind.
pub(crate) fn bind_failure(error: &std::io::Error) -> Failure {
    match error.kind() {
        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied => Failure::Permission,
        _ => Failure::Unsupported,
    }
}

/// Decides whether a source address may start a handshake, before any handshake work: a listener's `admission` input.
///
/// Any `Fn(SocketAddr) -> bool + Send + Sync + 'static` converts into one, so a closure is passed as it is. It is called on each
/// connection.
#[cfg(any(feature = "websocket", feature = "webtransport"))]
#[derive(Clone)]
pub struct Admission(alloc::sync::Arc<dyn Fn(core::net::SocketAddr) -> bool + Send + Sync>);

#[cfg(any(feature = "websocket", feature = "webtransport"))]
impl Admission {
    /// Whether `source` may start a handshake.
    pub(crate) fn admits(&self, source: core::net::SocketAddr) -> bool {
        (self.0)(source)
    }
}

#[cfg(any(feature = "websocket", feature = "webtransport"))]
impl<F> From<F> for Admission
where
    F: Fn(core::net::SocketAddr) -> bool + Send + Sync + 'static,
{
    fn from(admit: F) -> Self {
        Self(alloc::sync::Arc::new(admit))
    }
}

#[cfg(any(feature = "websocket", feature = "webtransport"))]
impl core::fmt::Debug for Admission {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Admission(..)")
    }
}

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

#[cfg(test)]
mod tests {
    use super::Reading;

    #[test]
    fn a_staged_bound_starts_at_its_position_counted_from_what_the_reader_took() {
        let bound = Reading::new(10, 64);
        bound.taken();
        bound.stage(1, 99);
        // The driver may ask in any order of time, but only ever for a later position.
        assert_eq!(bound.at(1), 10);
        assert_eq!(bound.at(1), 10);
        assert_eq!(bound.at(2), 99);
        assert_eq!(bound.at(3), 99);
        assert_eq!(bound.current(), 99);
    }

    #[test]
    fn setting_a_bound_replaces_a_staged_one() {
        let bound = Reading::new(10, 64);
        bound.stage(2, 99);
        bound.set(20);
        assert_eq!(bound.at(5), 20);
        bound.stage(0, 30);
        assert_eq!(bound.at(5), 30);
    }

    #[test]
    fn a_driver_reads_ahead_only_as_far_as_the_reader_allows() {
        let reading = Reading::new(10, 1);
        assert!(reading.may_read(0));
        assert!(!reading.may_read(1));
        reading.taken();
        assert!(reading.may_read(1));
        reading.set_ahead(3);
        assert!(reading.may_read(3));
        assert!(!reading.may_read(4));
        // Lowered below what is held: nothing more is read until the reader has taken enough.
        reading.set_ahead(1);
        assert!(!reading.may_read(3));
        reading.taken();
        assert!(!reading.may_read(3));
        reading.taken();
        assert!(reading.may_read(3));
    }

    #[test]
    fn a_read_ahead_of_0_is_1() {
        let reading = Reading::new(10, 0);
        assert!(reading.may_read(0));
        assert!(!reading.may_read(1));
        reading.set_ahead(0);
        assert!(reading.may_read(0));
        assert!(!reading.may_read(1));
    }
}
