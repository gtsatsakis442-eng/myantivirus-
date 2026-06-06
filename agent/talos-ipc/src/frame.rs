//! Length-prefixed JSON message framing over any byte stream.

use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::Serialize;

/// Upper bound on a single framed message (16 MiB) — a guard against a corrupt
/// or hostile length prefix.
pub const MAX_MSG_BYTES: usize = 16 * 1024 * 1024;

/// Serialize `msg` to JSON and write it as a 4-byte big-endian length followed
/// by the payload, then flush.
pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(msg).map_err(to_io)?;
    if bytes.len() > MAX_MSG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let len = (bytes.len() as u32).to_be_bytes();
    w.write_all(&len)?;
    w.write_all(&bytes)?;
    w.flush()
}

/// Read one length-prefixed JSON message and deserialize it into `T`.
pub fn read_msg<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "framed message too large",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map_err(to_io)
}

fn to_io(e: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Request, Response};

    #[test]
    fn request_round_trips_through_a_buffer() {
        let mut buf: Vec<u8> = Vec::new();
        let req = Request::StartScan {
            paths: vec!["/tmp/x".into()],
            quarantine: true,
        };
        write_msg(&mut buf, &req).unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let back: Request = read_msg(&mut cursor).unwrap();
        match back {
            Request::StartScan { paths, quarantine } => {
                assert_eq!(paths, vec!["/tmp/x".to_string()]);
                assert!(quarantine);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn response_round_trips_through_a_buffer() {
        let mut buf: Vec<u8> = Vec::new();
        write_msg(&mut buf, &Response::ScanStarted { scan_id: 7 }).unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let back: Response = read_msg(&mut cursor).unwrap();
        assert!(matches!(back, Response::ScanStarted { scan_id: 7 }));
    }

    #[test]
    fn truncated_stream_is_an_error() {
        // Only two bytes of a 4-byte length prefix.
        let mut cursor = std::io::Cursor::new(vec![0u8, 1u8]);
        let got: io::Result<Response> = read_msg(&mut cursor);
        assert!(got.is_err());
    }
}
