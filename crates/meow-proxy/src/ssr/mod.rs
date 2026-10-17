//! Native ShadowsocksR wire codec used by [`crate::ShadowsocksRAdapter`].
//!
//! SSR adds protocol framing and traffic obfuscation around the legacy
//! Shadowsocks stream cipher.  The codec deliberately lives beside the rest of
//! meow's proxy adapters so configuration, connection ownership, and protocol
//! evolution stay in one runtime rather than crossing an external boundary.

mod config;
mod legacy_cipher;
pub(super) mod obfs;
pub(super) mod protocol;
mod stream;

pub(super) use config::{CipherKind, SsrConfig};
pub(super) use obfs::ObfsKind;
pub(super) use protocol::ProtocolKind;
#[cfg(test)]
pub(super) use stream::inbound_accept;
pub(super) use stream::{outbound_connect, SsrStream};
