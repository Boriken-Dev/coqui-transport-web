//! The stream wire format: a little-endian `u32` body length, then the body.
//!
//! WebTransport bidirectional streams use it. A WebSocket message is already whole and carries no
//! prefix. This module does no I/O.

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
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a frame is empty or over the size limit")
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
