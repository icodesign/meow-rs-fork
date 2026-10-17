//! `plain` obfs: no-op pass-through.
//!
//! Data is forwarded unchanged.  This is also used as a fallback for
//! `http_post` (which is identical to `http_simple` for outbound-only use).

use std::io;

use super::ObfsPlugin;

/// Pass-through obfs plugin.
pub struct Plain;

impl ObfsPlugin for Plain {
    fn set_iv(&mut self, _iv: &[u8], _key: &[u8]) {}

    fn encode(&mut self, data: &[u8], _is_first: bool) -> Vec<u8> {
        data.to_vec()
    }

    fn decode(&mut self, buf: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
        if buf.is_empty() {
            Ok(None)
        } else {
            Ok(Some(std::mem::take(buf)))
        }
    }
}
