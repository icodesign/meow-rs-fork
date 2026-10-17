//! `random_head` obfuscation plugin.
//!
//! The client first sends a short random blob with a CRC32 trailer. The server
//! validates that frame, replies with a short random acknowledgement, and only
//! then does the client release the buffered encrypted payload as raw bytes.

use std::io;

use crc32fast::Hasher;
use rand::RngCore;

use super::ObfsPlugin;

const MIN_RANDOM_HEAD_LEN: usize = 4;
const RANDOM_HEAD_RANGE: usize = 96;
const CRC_LEN: usize = 4;
const MAX_CLIENT_HEADER_LEN: usize = MIN_RANDOM_HEAD_LEN + RANDOM_HEAD_RANGE - 1 + CRC_LEN;

pub struct RandomHead {
    is_server: bool,
    sent_header: bool,
    recv_header: bool,
    raw_transport_ready: bool,
    buffered_payload: Vec<u8>,
    pending_output: Vec<u8>,
}

impl RandomHead {
    pub fn new(is_server: bool) -> Self {
        Self {
            is_server,
            sent_header: false,
            recv_header: false,
            raw_transport_ready: false,
            buffered_payload: Vec::new(),
            pending_output: Vec::new(),
        }
    }

    fn random_len() -> usize {
        MIN_RANDOM_HEAD_LEN + (usize::from(rand::random::<u8>()) % RANDOM_HEAD_RANGE)
    }

    fn random_bytes(len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        rand::rng().fill_bytes(&mut out);
        out
    }

    fn client_header() -> Vec<u8> {
        let mut out = Self::random_bytes(Self::random_len());
        let mut hasher = Hasher::new();
        hasher.update(&out);
        let crc = !hasher.finalize();
        out.extend_from_slice(&crc.to_le_bytes());
        out
    }

    fn server_ack() -> Vec<u8> {
        Self::random_bytes(Self::random_len())
    }
}

impl ObfsPlugin for RandomHead {
    fn set_iv(&mut self, _iv: &[u8], _key: &[u8]) {}

    fn encode(&mut self, data: &[u8], is_first: bool) -> Vec<u8> {
        if self.is_server {
            if !self.sent_header && is_first {
                self.sent_header = true;
                self.buffered_payload.extend_from_slice(data);
                return Vec::new();
            }

            if self.raw_transport_ready {
                return data.to_vec();
            }

            self.buffered_payload.extend_from_slice(data);
            Vec::new()
        } else {
            if self.raw_transport_ready {
                return data.to_vec();
            }

            self.buffered_payload.extend_from_slice(data);
            if !self.sent_header && is_first {
                self.sent_header = true;
                return Self::client_header();
            }

            Vec::new()
        }
    }

    fn decode(&mut self, buf: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
        if self.recv_header {
            if buf.is_empty() {
                return Ok(None);
            }
            return Ok(Some(std::mem::take(buf)));
        }

        if self.is_server {
            if buf.len() < MIN_RANDOM_HEAD_LEN + CRC_LEN {
                return Ok(None);
            }

            let crc = crc32fast::hash(buf);
            if crc == u32::MAX {
                self.recv_header = true;
                self.raw_transport_ready = true;
                buf.clear();
                if !self.sent_header {
                    self.pending_output = Self::server_ack();
                    self.pending_output
                        .extend_from_slice(&self.buffered_payload);
                    self.buffered_payload.clear();
                    self.sent_header = true;
                }
                return Ok(Some(Vec::new()));
            }

            if buf.len() <= MAX_CLIENT_HEADER_LEN {
                return Ok(None);
            }

            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "random_head: invalid client header crc",
            ));
        }

        if buf.is_empty() {
            return Ok(None);
        }

        self.recv_header = true;
        self.raw_transport_ready = true;
        buf.clear();
        self.pending_output = std::mem::take(&mut self.buffered_payload);
        Ok(Some(Vec::new()))
    }

    fn awaiting_response(&self) -> bool {
        !self.is_server && self.sent_header && !self.raw_transport_ready
    }

    fn take_pending_output(&mut self) -> Option<Vec<u8>> {
        if self.pending_output.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.pending_output))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_header_crc_matches_reference_rule() {
        let mut plugin = RandomHead::new(false);
        let header = plugin.encode(b"payload", true);
        assert!((8..=103).contains(&header.len()));
        assert_eq!(crc32fast::hash(&header), u32::MAX);
    }

    #[test]
    fn server_ack_enables_pending_payload() {
        let mut client = RandomHead::new(false);
        let _ = client.encode(b"hello", true);
        assert!(client.awaiting_response());
        assert!(client.take_pending_output().is_none());

        let mut ack = vec![0u8; 12];
        client.decode(&mut ack).unwrap();
        assert!(!client.awaiting_response());
        assert_eq!(client.take_pending_output().as_deref(), Some(&b"hello"[..]));
    }
}
