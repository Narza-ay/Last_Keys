//! Length-prefixed frames: a 32-bit little-endian body length, then a UTF-8
//! JSON body. The same format is used on both hops (native messaging uses
//! the platform's byte order, little-endian on every supported platform).

use std::io::{self, Read, Write};

use thiserror::Error;
use zeroize::Zeroizing;

/// Largest accepted body, in both directions (1 MiB, the native messaging
/// limit for messages sent to the browser).
pub const MAX_FRAME: usize = 1024 * 1024;

/// A frame that cannot be accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum FrameError {
    /// The announced or actual body length exceeds [`MAX_FRAME`].
    #[error("frame of {0} bytes exceeds the limit")]
    TooLarge(usize),
    /// A frame with an empty body.
    #[error("empty frame")]
    Empty,
}

impl From<FrameError> for io::Error {
    fn from(e: FrameError) -> Self {
        Self::new(io::ErrorKind::InvalidData, e)
    }
}

/// Header of a body of `len` bytes.
///
/// # Errors
/// [`FrameError`] for an empty or oversized body.
pub fn header(len: usize) -> Result<[u8; 4], FrameError> {
    if len == 0 {
        return Err(FrameError::Empty);
    }
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let len = u32::try_from(len).map_err(|_| FrameError::TooLarge(len))?;
    Ok(len.to_le_bytes())
}

/// Body length announced by a header.
///
/// # Errors
/// [`FrameError`] for an empty or oversized body.
pub fn body_len(header: [u8; 4]) -> Result<usize, FrameError> {
    let len = usize::try_from(u32::from_le_bytes(header)).unwrap_or(usize::MAX);
    if len == 0 {
        return Err(FrameError::Empty);
    }
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    Ok(len)
}

/// Header and body in one buffer (wiped when dropped).
///
/// # Errors
/// [`FrameError`] for an empty or oversized body.
pub fn encode(body: &[u8]) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    let mut out = Zeroizing::new(Vec::with_capacity(body.len().saturating_add(4)));
    out.extend_from_slice(&header(body.len())?);
    out.extend_from_slice(body);
    Ok(out)
}

/// Reads one frame; `None` when the stream ends cleanly before a header.
///
/// # Errors
/// I/O errors; `InvalidData` for an unacceptable length; `UnexpectedEof`
/// when the stream ends inside a frame.
pub fn read_frame(reader: &mut impl Read) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut head = [0_u8; 4];
    let mut filled = 0;
    while filled < head.len() {
        let Some(rest) = head.get_mut(filled..) else {
            break;
        };
        match reader.read(rest) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let len = body_len(head)?;
    let mut body = Zeroizing::new(vec![0_u8; len]);
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Writes one frame and flushes.
///
/// # Errors
/// I/O errors; `InvalidData` for an unacceptable length.
pub fn write_frame(writer: &mut impl Write, body: &[u8]) -> io::Result<()> {
    writer.write_all(&encode(body)?)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn round_trip_and_limits() {
        let mut buf = Vec::new();
        write_frame(&mut buf, br#"{"id":1}"#).unwrap();
        write_frame(&mut buf, b"x").unwrap();
        assert_eq!(buf.get(..4).unwrap(), &[8, 0, 0, 0]);
        let mut r = buf.as_slice();
        assert_eq!(
            read_frame(&mut r).unwrap().unwrap().as_slice(),
            br#"{"id":1}"#
        );
        assert_eq!(read_frame(&mut r).unwrap().unwrap().as_slice(), b"x");
        assert!(read_frame(&mut r).unwrap().is_none());

        assert_eq!(header(0), Err(FrameError::Empty));
        assert_eq!(
            header(MAX_FRAME + 1),
            Err(FrameError::TooLarge(MAX_FRAME + 1))
        );
        assert!(header(MAX_FRAME).is_ok());
        assert_eq!(body_len([0, 0, 0, 0]), Err(FrameError::Empty));
        assert_eq!(body_len([0, 0, 0x10, 0]), Ok(MAX_FRAME));
        assert_eq!(
            body_len([1, 0, 0x10, 0]),
            Err(FrameError::TooLarge(MAX_FRAME + 1))
        );
        assert!(body_len([0xff; 4]).is_err());
        assert!(write_frame(&mut Vec::new(), b"").is_err());
    }

    #[test]
    fn truncated_and_oversized_streams() {
        // Ends inside the header, inside the body.
        for bytes in [&[5_u8, 0][..], &[5, 0, 0, 0, b'a', b'b'][..]] {
            let e = read_frame(&mut &bytes[..]).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        }
        // An oversized announcement is refused before allocating.
        let e = read_frame(&mut &[0xff_u8, 0xff, 0xff, 0x7f][..]).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }
}
