//! SSR obfuscation plugin layer.
//!
//! Obfs plugins transform the encrypted byte stream to disguise it as
//! benign traffic (HTTP requests/responses or TLS handshakes).
//!
//! The obfs layer sits **outside** the cipher layer:
//! - Outbound: cipher-encrypted bytes → obfs.encode() → wire
//! - Inbound:  wire → obfs.decode() → cipher-encrypted bytes

pub mod http_simple;
pub mod plain;
pub mod random_head;
pub mod tls12_ticket;

use std::io;

// ── ObfsKind ──────────────────────────────────────────────────────────────────

/// Supported obfuscation plugin variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfsKind {
    Plain,
    HttpSimple,
    HttpPost,
    RandomHead,
    Tls12TicketAuth,
}

impl ObfsKind {
    /// Parse an obfs name string (case-insensitive).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "plain" => Some(Self::Plain),
            "http_simple" => Some(Self::HttpSimple),
            "http_post" => Some(Self::HttpPost),
            "random_head" | "random_head_compatible" => Some(Self::RandomHead),
            "tls1.2_ticket_auth" | "tls1.2_ticket_fastauth" => Some(Self::Tls12TicketAuth),
            _ => None,
        }
    }
}

// ── ObfsPlugin trait ──────────────────────────────────────────────────────────

/// Obfuscation plugin interface.
///
/// All methods operate synchronously on byte slices / `Vec<u8>` rather than
/// `AsyncRead`/`AsyncWrite` so that they can be called from within the
/// [`super::super::stream::SsrStream`] poll methods.
pub trait ObfsPlugin: Send {
    /// Initialise the plugin with the connection's cipher IV and session key.
    ///
    /// Called once, before any `encode` or `decode` calls.
    fn set_iv(&mut self, iv: &[u8], key: &[u8]);

    /// Encode outbound data (after cipher encryption).
    ///
    /// `is_first` is `true` for the very first encode call on this connection,
    /// which typically contains the cipher IV prepended to the encrypted data.
    fn encode(&mut self, data: &[u8], is_first: bool) -> Vec<u8>;

    /// Try to decode inbound data from the accumulation buffer `buf`.
    ///
    /// Removes consumed bytes from `buf` in-place and returns the decoded
    /// cipher-layer bytes.  Returns `Ok(None)` if more data is needed before a
    /// complete unit can be returned.
    fn decode(&mut self, buf: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>>;

    /// Returns true when the plugin is waiting for a peer response before
    /// releasing buffered application data.
    fn awaiting_response(&self) -> bool {
        false
    }

    /// Take a buffered post-obfs wire payload that should be sent before the
    /// next application write can be considered complete.
    fn take_pending_output(&mut self) -> Option<Vec<u8>> {
        None
    }
}

// ── Factory ───────────────────────────────────────────────────────────────────

/// Construct an obfs plugin for `kind` with the given `param` string.
///
/// `is_server` distinguishes the server role (sends ServerHello on first
/// encode) from the client role (sends ClientHello) for TLS-based obfs.
pub fn make_obfs(kind: ObfsKind, param: &str, is_server: bool) -> Box<dyn ObfsPlugin> {
    match kind {
        ObfsKind::Plain => Box::new(plain::Plain),
        ObfsKind::HttpPost => Box::new(http_simple::HttpSimple::new(
            param.to_string(),
            true,
            is_server,
        )),
        ObfsKind::HttpSimple => Box::new(http_simple::HttpSimple::new(
            param.to_string(),
            false,
            is_server,
        )),
        ObfsKind::RandomHead => Box::new(random_head::RandomHead::new(is_server)),
        ObfsKind::Tls12TicketAuth => Box::new(tls12_ticket::Tls12TicketAuth::new(
            param.to_string(),
            is_server,
        )),
    }
}
