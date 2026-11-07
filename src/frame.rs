//! The wire formats of the web transports: a WebTransport stream's length prefix, and the tags a
//! WebSocket carries once both ends agreed to datagrams. This module does no I/O.
//!
//! A WebTransport bidirectional stream carries [`WEBTRANSPORT`] frames, the `coqui-transport`
//! length-prefix codec set to a little-endian `u32` that refuses an empty body; this crate holds
//! the choice, not the algorithm. A WebSocket message is already whole and carries no prefix,
//! unless both ends agreed to datagrams, which tags it.

use alloc::vec::Vec;

use coqui_transport::frame::{Codec, Decode, LengthDecoder, LengthPrefix};

pub use coqui_transport::frame::{DEFAULT_MAX_MESSAGE, FrameError};

/// The framing of a WebTransport stream: a little-endian `u32` body length, then the body, which
/// is never empty.
pub const WEBTRANSPORT: LengthPrefix = LengthPrefix::u32_le().refuse_empty();

/// Prefixes a non-empty body of at most `maximum` bytes with its length, as [`WEBTRANSPORT`] does.
///
/// # Errors
///
/// [`FrameError::Size`] when `body` is empty or over `maximum`.
pub fn encode(body: &[u8], maximum: usize) -> Result<Vec<u8>, FrameError> {
    WEBTRANSPORT.encode(body, maximum)
}

/// An incremental decoder of [`WEBTRANSPORT`] frames for fragmented or coalesced stream bytes.
///
/// [`push`](Self::push) what arrived, then call [`next_frame`](Self::next_frame) until it answers
/// `None`. Frames that were complete before a bad header are returned before the error. Once it
/// fails, the decoder stays failed. It holds no more than one maximum frame and what arrived since.
#[derive(Debug)]
pub struct Decoder(LengthDecoder);

impl Decoder {
    /// Changes the largest body accepted from the next frame on.
    pub fn set_maximum(&mut self, maximum: usize) {
        self.0.set_maximum(maximum);
    }

    /// A decoder accepting bodies of at most `maximum` bytes.
    #[must_use]
    pub const fn new(maximum: usize) -> Self {
        Self(LengthDecoder::new(WEBTRANSPORT, maximum))
    }

    /// Adds bytes as they arrived.
    pub fn push(&mut self, part: &[u8]) {
        self.0.push(part);
    }

    /// The next complete frame, or `None` until more bytes arrive.
    ///
    /// # Errors
    ///
    /// [`FrameError::Size`] on an empty or oversized frame, and on every later call.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        self.0.next_frame()
    }
}

/// What a binary message on a WebSocket is, once both ends agreed to datagrams with [`WS_DATAGRAMS_PROTOCOL`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WsPart<'a> {
    /// One of the channel's messages.
    Message(&'a [u8]),
    /// A datagram, which may be empty.
    Datagram(&'a [u8]),
}

/// The WebSocket subprotocol that says both ends tag binary messages. Agreed in the handshake, so a peer that never asked for it is
/// sent what it always was.
pub const WS_DATAGRAMS_PROTOCOL: &str = "coqui-web-datagrams.1";
/// [`WS_DATAGRAMS_PROTOCOL`] and one tag more, for the signals that open a data channel on the same address. A server that can answer
/// them chooses this over that when a client offers both.
pub const WS_LADDER_PROTOCOL: &str = "coqui-web-ladder.1";
const WS_MESSAGE: u8 = 0;
const WS_DATAGRAM: u8 = 1;
const WS_SIGNAL: u8 = 2;

/// A message as a tagged binary message.
#[must_use]
pub fn ws_message(body: &[u8]) -> Vec<u8> {
    ws_tagged(WS_MESSAGE, body)
}

/// A datagram as a tagged binary message.
#[must_use]
pub fn ws_datagram(body: &[u8]) -> Vec<u8> {
    ws_tagged(WS_DATAGRAM, body)
}

/// A signal as a tagged binary message, under [`WS_LADDER_PROTOCOL`].
#[must_use]
pub fn ws_signal(body: &[u8]) -> Vec<u8> {
    ws_tagged(WS_SIGNAL, body)
}

/// The signal in a tagged binary message, or `None` if it holds something else. [`ws_part`] calls a signal an unknown tag, as it is
/// under any other subprotocol.
#[must_use]
pub fn ws_signal_part(tagged: &[u8]) -> Option<&[u8]> {
    match tagged.split_first() {
        Some((&WS_SIGNAL, body)) => Some(body),
        _ => None,
    }
}

fn ws_tagged(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut tagged = Vec::with_capacity(body.len() + 1);
    tagged.push(tag);
    tagged.extend_from_slice(body);
    tagged
}

/// Reads a tagged binary message.
///
/// # Errors
///
/// [`FrameError::Size`] for an empty message or an empty channel message, which no peer may send; [`FrameError::Tag`] for a tag this
/// does not know, which a later version would have agreed under another subprotocol.
pub fn ws_part(tagged: &[u8]) -> Result<WsPart<'_>, FrameError> {
    match tagged.split_first() {
        Some((&WS_MESSAGE, body)) if !body.is_empty() => Ok(WsPart::Message(body)),
        Some((&WS_DATAGRAM, body)) => Ok(WsPart::Datagram(body)),
        Some((&WS_MESSAGE, _)) | None => Err(FrameError::Size),
        Some(_) => Err(FrameError::Tag),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_survive_fragmentation_and_coalescing() {
        let mut bytes = encode(b"hello", 10).unwrap();
        bytes.extend(encode(b"world", 10).unwrap());
        let mut decoder = Decoder::new(10);
        decoder.push(&bytes[..3]);
        assert_eq!(decoder.next_frame(), Ok(None));
        decoder.push(&bytes[3..]);
        assert_eq!(decoder.next_frame(), Ok(Some(b"hello".to_vec())));
        assert_eq!(decoder.next_frame(), Ok(Some(b"world".to_vec())));
        assert_eq!(decoder.next_frame(), Ok(None));
    }

    #[test]
    fn complete_frames_come_before_a_bad_header_and_the_failure_sticks() {
        let mut bytes = encode(b"good", 10).unwrap();
        bytes.extend([11, 0, 0, 0]);
        let mut decoder = Decoder::new(10);
        decoder.push(&bytes);
        assert_eq!(decoder.next_frame(), Ok(Some(b"good".to_vec())));
        assert_eq!(decoder.next_frame(), Err(FrameError::Size));
        decoder.push(&encode(b"later", 10).unwrap());
        assert_eq!(decoder.next_frame(), Err(FrameError::Size));
    }

    #[test]
    fn a_signal_is_its_own_tag_and_no_part_of_the_datagram_wire() {
        let signal = ws_signal(b"sdp");
        assert_eq!(signal, [2, b's', b'd', b'p']);
        assert_eq!(ws_signal_part(&signal), Some(&b"sdp"[..]));
        assert_eq!(ws_part(&signal), Err(FrameError::Tag));
        assert_eq!(ws_signal_part(&ws_datagram(b"x")), None);
    }

    #[test]
    fn an_empty_body_is_refused_both_ways() {
        assert_eq!(encode(b"", 10), Err(FrameError::Size));
        let mut decoder = Decoder::new(10);
        decoder.push(&[0, 0, 0, 0]);
        assert_eq!(decoder.next_frame(), Err(FrameError::Size));
    }
}
