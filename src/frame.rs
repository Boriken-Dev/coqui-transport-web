//! The stream wire format: a little-endian `u32` body length, then the body.
//!
//! WebTransport bidirectional streams use it. A WebSocket message is already whole and carries no
//! prefix, unless both ends agreed to datagrams, which tags it. This module does no I/O.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;

/// The largest body a peer may send unless the application chooses otherwise: 1 MiB.
pub const DEFAULT_MAX_MESSAGE: usize = 1024 * 1024;

const PREFIX: usize = 4;

/// A frame outside the bounds this side accepts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FrameError {
    /// The body is empty or over the limit. Fatal on a stream: the framing cannot resynchronize.
    Size,
    /// A tag this does not know.
    Tag,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Size => "a frame is empty or over the size limit",
            Self::Tag => "a message has a tag this does not know",
        })
    }
}

impl core::error::Error for FrameError {}

/// Prefixes a non-empty body of at most `maximum` bytes with its length.
///
/// # Errors
///
/// [`FrameError::Size`] when `body` is empty or over `maximum`.
pub fn encode(body: &[u8], maximum: usize) -> Result<Vec<u8>, FrameError> {
    if body.is_empty() || body.len() > maximum {
        return Err(FrameError::Size);
    }
    let size = u32::try_from(body.len()).map_err(|_| FrameError::Size)?;
    let mut out = Vec::with_capacity(PREFIX + body.len());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// An incremental decoder for fragmented or coalesced stream bytes.
///
/// [`push`](Self::push) what arrived, then call [`next_frame`](Self::next_frame) until it answers
/// `None`. Frames that were complete before a bad header are returned before the error. Once it
/// fails, the decoder stays failed. It holds no more than one chunk beyond one maximum frame.
#[derive(Debug)]
pub struct Decoder {
    buffered: VecDeque<u8>,
    maximum: usize,
    failed: bool,
}

impl Decoder {
    /// Changes the largest body accepted from the next frame on.
    pub const fn set_maximum(&mut self, maximum: usize) {
        self.maximum = maximum;
    }

    /// A decoder accepting bodies of at most `maximum` bytes.
    #[must_use]
    pub const fn new(maximum: usize) -> Self {
        Self {
            buffered: VecDeque::new(),
            maximum,
            failed: false,
        }
    }

    /// Adds bytes as they arrived.
    pub fn push(&mut self, part: &[u8]) {
        if !self.failed {
            self.buffered.extend(part);
        }
    }

    /// The next complete frame, or `None` until more bytes arrive.
    ///
    /// # Errors
    ///
    /// [`FrameError::Size`] on an empty or oversized frame, and on every later call.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        if self.failed {
            return Err(FrameError::Size);
        }
        if self.buffered.len() < PREFIX {
            return Ok(None);
        }
        let mut prefix = [0_u8; PREFIX];
        for (slot, byte) in prefix.iter_mut().zip(&self.buffered) {
            *slot = *byte;
        }
        let size = u32::from_le_bytes(prefix);
        let size = usize::try_from(size).unwrap_or(usize::MAX);
        if size == 0 || size > self.maximum {
            self.failed = true;
            self.buffered = VecDeque::new();
            return Err(FrameError::Size);
        }
        // `size` is at most `maximum`, and a stored frame fits in memory, so this cannot overflow
        // for any frame that could complete.
        if self.buffered.len() - PREFIX < size {
            return Ok(None);
        }
        self.buffered.drain(..PREFIX);
        Ok(Some(self.buffered.drain(..size).collect()))
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
const WS_MESSAGE: u8 = 0;
const WS_DATAGRAM: u8 = 1;

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
    fn an_empty_body_is_refused_both_ways() {
        assert_eq!(encode(b"", 10), Err(FrameError::Size));
        let mut decoder = Decoder::new(10);
        decoder.push(&[0, 0, 0, 0]);
        assert_eq!(decoder.next_frame(), Err(FrameError::Size));
    }
}
