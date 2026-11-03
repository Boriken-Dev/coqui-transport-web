//! One WebSocket channel's climb onto a data channel, shared between its callers, its WebSocket worker and the port's worker.

use alloc::sync::Arc;
use core::net::SocketAddr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use std::sync::mpsc::{self, Sender, SyncSender};
use std::sync::{Mutex, PoisonError};

use super::worker::{Command, Opening, Role};
use super::{Port, Settings, Signaling, sdp};
use crate::channel::Delivery;
use crate::failure::Failure;
use crate::pump::{Inbox, Received};

/// What a signal is: its first byte, before the description.
pub(super) const OFFER: u8 = 1;
pub(super) const ANSWER: u8 = 2;
pub(super) const REFUSED: u8 = 3;

/// A session description is a few kilobytes. A peer gets no further than this.
const MAX_SIGNAL: usize = 16 * 1024;
/// An offer, an answer or a refusal: there is never more than one on its way.
const SIGNALS: usize = 2;
/// SCTP, DTLS and padding on a data channel's message, and UDP and IPv6 under them.
const OVERHEAD: usize = 116;
/// What fits one SCTP chunk whichever implementation is at the other end: str0m's and a browser's fragment points are near this.
const LARGEST: usize = 1100;

/// Which end of a channel this is.
pub(crate) enum Plan {
    /// Opened the connection, so it makes the offer, from the address that connection uses.
    Dialing {
        settings: Settings,
        local: SocketAddr,
        peer: SocketAddr,
    },
    /// Answers on `port`, naming `candidate`.
    Listening { port: Port, candidate: SocketAddr },
}

/// Where a signal goes.
enum Outgoing {
    /// To the WebSocket's worker, which is then woken.
    Worker(SyncSender<Vec<u8>>, Box<dyn Fn() + Send + Sync>),
    /// To a caller to carry.
    Caller(SyncSender<Received>),
}

/// The channel's data path as both workers and its callers see it.
pub(crate) struct Path {
    open: AtomicBool,
    max_size: usize,
    inbox: Mutex<Option<SyncSender<Received>>>,
    dropped: Arc<AtomicU64>,
    watchers: Mutex<Vec<Sender<Delivery>>>,
    outgoing: Mutex<Option<Outgoing>>,
}

impl Path {
    pub(super) fn signal(&self, kind: u8, description: &str) {
        let mut signal = Vec::with_capacity(description.len() + 1);
        signal.push(kind);
        signal.extend_from_slice(description.as_bytes());
        match &*self.outgoing.lock().unwrap_or_else(PoisonError::into_inner) {
            Some(Outgoing::Worker(queue, wake)) => {
                if queue.try_send(signal).is_ok() {
                    wake();
                }
            }
            Some(Outgoing::Caller(queue)) => {
                let _ = queue.try_send(Ok(signal));
            }
            None => {}
        }
    }

    fn notify(&self, delivery: Delivery) {
        self.watchers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|watcher| watcher.send(delivery).is_ok());
    }

    pub(super) fn opened(&self) {
        self.open.store(true, Ordering::SeqCst);
        self.notify(Delivery::Unreliable);
    }

    /// The data channel is over: whatever was on it goes back to the WebSocket, once. An attempt that never opened changed nothing.
    pub(super) fn ended(&self) {
        if self.open.swap(false, Ordering::SeqCst) {
            self.notify(Delivery::OverStream);
        }
    }

    pub(super) fn arrive(&self, datagram: Vec<u8>) {
        let kept = datagram.len() <= LARGEST
            && self
                .inbox
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .is_some_and(|inbox| inbox.try_send(Ok(datagram)).is_ok());
        if !kept {
            self.count_dropped();
        }
    }

    pub(super) fn count_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
struct State {
    started: bool,
    attempted: bool,
    closed: bool,
    held_offer: Option<String>,
    // The port this channel's session is on: a dialer's own, or the listener's.
    on: Option<(Port, u64)>,
}

/// One channel's climb.
pub(crate) struct Climb {
    plan: Plan,
    settings: Settings,
    path: Arc<Path>,
    to_send: SyncSender<Vec<u8>>,
    to_session: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    from_caller: Option<Inbox>,
    state: Mutex<State>,
}

impl Climb {
    /// `signals` takes what the WebSocket's worker is to send, and `wake` tells it to look.
    pub(crate) fn new(
        plan: Plan,
        inbox: SyncSender<Received>,
        dropped: Arc<AtomicU64>,
        pending: usize,
        signals: SyncSender<Vec<u8>>,
        wake: Box<dyn Fn() + Send + Sync>,
    ) -> Self {
        let settings = match &plan {
            Plan::Dialing { settings, .. } => *settings,
            Plan::Listening { port, .. } => port.settings(),
        };
        let (outgoing, from_caller) = match settings.signaling {
            Signaling::OnChannel => (Outgoing::Worker(signals, wake), None),
            Signaling::ByCaller => {
                let (queue, caller) = mpsc::sync_channel(SIGNALS);
                (Outgoing::Caller(queue), Some(Inbox::new(caller)))
            }
        };
        let (to_send, to_session) = mpsc::sync_channel(pending.max(1));
        Self {
            plan,
            settings,
            path: Arc::new(Path {
                open: AtomicBool::new(false),
                max_size: settings.path_mtu.saturating_sub(OVERHEAD).min(LARGEST),
                inbox: Mutex::new(Some(inbox)),
                dropped,
                watchers: Mutex::new(Vec::new()),
                outgoing: Mutex::new(Some(outgoing)),
            }),
            to_send,
            to_session: Mutex::new(Some(to_session)),
            from_caller,
            state: Mutex::new(State::default()),
        }
    }

    /// Starts the attempt, at the first asking for datagrams at this end: a peer that has proved nothing costs a held offer and no
    /// more, and a dialer offers nothing before its caller wants datagrams.
    pub(crate) fn start(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.started || state.closed {
            return;
        }
        state.started = true;
        match &self.plan {
            Plan::Dialing { local, .. } => {
                if let Ok(port) = Port::dialing(local.ip(), self.settings) {
                    self.open(&mut state, &port, Role::Offer);
                }
            }
            Plan::Listening { port, candidate } => {
                if let Some(offer) = state.held_offer.take() {
                    self.open(
                        &mut state,
                        port,
                        Role::Answer {
                            offer,
                            candidate: *candidate,
                        },
                    );
                }
            }
        }
    }

    /// Only ever once: another offer from a peer that has already made one is not looked at.
    fn open(&self, state: &mut State, port: &Port, role: Role) {
        if state.attempted {
            return;
        }
        state.attempted = true;
        let Some(to_send) = self
            .to_session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return;
        };
        let id = port.new_session();
        state.on = Some((port.clone(), id));
        port.command(Command::Open(Box::new(Opening {
            id,
            path: Arc::clone(&self.path),
            to_send,
            role,
            attempt: self.settings.attempt,
        })));
    }

    /// A signal from the WebSocket itself, which a caller carrying them never trusts.
    pub(crate) fn signal_from_channel(&self, signal: &[u8]) {
        if self.settings.signaling == Signaling::OnChannel {
            self.signal_arrived(signal);
        }
    }

    fn signal_arrived(&self, signal: &[u8]) {
        if signal.len() > MAX_SIGNAL {
            return;
        }
        let Some((&kind, description)) = signal.split_first() else {
            return;
        };
        let Ok(description) = core::str::from_utf8(description) else {
            return;
        };
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.closed {
            return;
        }
        match (&self.plan, kind) {
            (Plan::Listening { port, candidate }, OFFER) => {
                if state.attempted || state.held_offer.is_some() {
                    return;
                }
                let Some(offer) = sdp::offer(description) else {
                    self.path.signal(REFUSED, "");
                    return;
                };
                if state.started {
                    self.open(
                        &mut state,
                        port,
                        Role::Answer {
                            offer,
                            candidate: *candidate,
                        },
                    );
                } else {
                    state.held_offer = Some(offer);
                }
            }
            (Plan::Dialing { peer, .. }, ANSWER) => {
                let Some((port, id)) = &state.on else {
                    return;
                };
                match sdp::answer(description, peer.ip(), self.settings.any_candidate) {
                    Some((sdp, candidate)) => port.command(Command::Answer {
                        id: *id,
                        sdp,
                        candidate,
                    }),
                    None => port.command(Command::Close(*id)),
                }
            }
            (Plan::Dialing { .. }, REFUSED) => {
                if let Some((port, id)) = &state.on {
                    port.command(Command::Close(*id));
                }
            }
            _ => {}
        }
    }

    /// A signal a caller carried.
    pub(crate) fn deliver_signal(&self, signal: &[u8]) -> Result<(), Failure> {
        if self.settings.signaling != Signaling::ByCaller {
            return Err(Failure::Unsupported);
        }
        self.signal_arrived(signal);
        Ok(())
    }

    /// The next signal for a caller to carry.
    pub(crate) fn next_signal(
        &self,
        timeout: Option<Duration>,
    ) -> Result<Option<Vec<u8>>, Failure> {
        self.from_caller
            .as_ref()
            .ok_or(Failure::Unsupported)?
            .receive(timeout)
    }

    pub(crate) fn is_open(&self) -> bool {
        self.path.open.load(Ordering::SeqCst)
    }

    pub(crate) fn max_size(&self) -> usize {
        self.path.max_size
    }

    /// Hands one to the data channel, or counts it gone if too many are waiting.
    pub(crate) fn send(&self, payload: &[u8]) -> Result<(), Failure> {
        // str0m writes nothing for an empty message, so one is refused rather than vanishing without a count.
        if payload.is_empty() || payload.len() > self.path.max_size {
            return Err(Failure::Protocol);
        }
        if self.to_send.try_send(payload.to_vec()).is_err() {
            self.path.count_dropped();
            return Ok(());
        }
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((port, _)) = &state.on {
            port.wake();
        }
        Ok(())
    }

    /// Each change of path from now on.
    pub(crate) fn changes(&self) -> mpsc::Receiver<Delivery> {
        let (watcher, changes) = mpsc::channel();
        self.path
            .watchers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(watcher);
        changes
    }

    /// Ends the session and what it holds, so nothing keeps a reader waiting. Safe to call more than once.
    pub(crate) fn close(&self) {
        let on = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.closed = true;
            state.held_offer = None;
            state.on.take()
        };
        self.path.ended();
        *self
            .path
            .inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        *self
            .path
            .outgoing
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        if let Some((port, id)) = on {
            port.command(Command::Close(id));
        }
    }
}
