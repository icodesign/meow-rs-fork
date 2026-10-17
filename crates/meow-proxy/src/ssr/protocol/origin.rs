//! `origin` protocol plugin — pass-through.
//!
//! The `origin` protocol adds no additional framing or authentication.  Data
//! is forwarded unchanged to/from the cipher layer.
//!
//! The address header (SOCKS5 format: ATYP + addr + port) is written by the
//! caller as part of the first data payload, identical to plain Shadowsocks
//! legacy stream behaviour.

use std::io;

use super::ProtocolPlugin;

pub struct Origin;

impl ProtocolPlugin for Origin {
    fn set_iv(&mut self, _iv: &[u8], _session_key: &[u8]) {}

    fn encode(&mut self, data: &[u8], _is_first: bool) -> io::Result<Vec<u8>> {
        Ok(data.to_vec())
    }

    fn decode(&mut self, data: &[u8]) -> io::Result<Option<Vec<u8>>> {
        if data.is_empty() {
            Ok(None)
        } else {
            Ok(Some(data.to_vec()))
        }
    }
}
