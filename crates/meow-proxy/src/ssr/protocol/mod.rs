//! SSR protocol plugin layer.
//!
//! The protocol plugin sits between the application data and the cipher layer:
//! - Outbound: application data → protocol.encode() → cipher
//! - Inbound:  cipher → protocol.decode() → application data
//!
//! It is responsible for packet framing, sequence numbering, and optional
//! connection authentication.

pub mod auth_aes128;
pub mod auth_chain_a;
pub mod auth_sha1_v4;
pub mod origin;

use std::io;

// ── ProtocolKind ─────────────────────────────────────────────────────────────

/// Supported protocol plugin variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolKind {
    Origin,
    AuthSha1V4,
    AuthAes128Md5,
    AuthAes128Sha1,
    AuthChainA,
    AuthChainB,
}

impl ProtocolKind {
    /// Parse a protocol name string (case-insensitive).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "origin" => Some(Self::Origin),
            "auth_sha1_v4" => Some(Self::AuthSha1V4),
            "auth_aes128_md5" => Some(Self::AuthAes128Md5),
            "auth_aes128_sha1" => Some(Self::AuthAes128Sha1),
            "auth_chain_a" => Some(Self::AuthChainA),
            "auth_chain_b" => Some(Self::AuthChainB),
            _ => None,
        }
    }
}

// ── ProtocolPlugin trait ──────────────────────────────────────────────────────

/// Protocol plugin interface.
///
/// All methods operate synchronously on byte slices / `Vec<u8>` to allow
/// them to be called from within `poll_read` / `poll_write`.
pub trait ProtocolPlugin: Send {
    /// Initialise the plugin with the connection's cipher IV and session key.
    ///
    /// Called once, before any encode/decode calls.
    fn set_iv(&mut self, iv: &[u8], session_key: &[u8]);

    /// Encode a plaintext data chunk before cipher encryption.
    ///
    /// `is_first` is `true` for the very first data chunk (after cipher IV
    /// exchange).  Auth protocols use this to emit the one-time connection
    /// authentication header.
    fn encode(&mut self, data: &[u8], is_first: bool) -> io::Result<Vec<u8>>;

    /// Decode a cipher-decrypted data chunk.
    ///
    /// Returns `Ok(None)` if more data is needed to complete a frame.
    fn decode(&mut self, data: &[u8]) -> io::Result<Option<Vec<u8>>>;
}

// ── Factory ───────────────────────────────────────────────────────────────────

/// Construct a protocol plugin for `kind` with the given `param` string and
/// session key (derived from the password via EVP_BytesToKey).
///
/// `is_server` controls decode behaviour: the client's first outbound frame
/// contains a connection auth header that only the server needs to strip.
pub fn make_protocol(
    kind: ProtocolKind,
    param: &str,
    session_key: Vec<u8>,
    is_server: bool,
) -> Box<dyn ProtocolPlugin> {
    match kind {
        ProtocolKind::Origin => Box::new(origin::Origin),
        ProtocolKind::AuthSha1V4 => Box::new(auth_sha1_v4::AuthSha1V4::new(session_key, is_server)),
        ProtocolKind::AuthAes128Md5 => Box::new(auth_aes128::AuthAes128::new(
            session_key,
            auth_aes128::HmacVariant::Md5,
            is_server,
        )),
        ProtocolKind::AuthAes128Sha1 => Box::new(auth_aes128::AuthAes128::new(
            session_key,
            auth_aes128::HmacVariant::Sha1,
            is_server,
        )),
        ProtocolKind::AuthChainA => Box::new(auth_chain_a::AuthChainA::new(
            session_key,
            param,
            auth_chain_a::AuthChainVariant::A,
            is_server,
        )),
        ProtocolKind::AuthChainB => Box::new(auth_chain_a::AuthChainA::new(
            session_key,
            param,
            auth_chain_a::AuthChainVariant::B,
            is_server,
        )),
    }
}
