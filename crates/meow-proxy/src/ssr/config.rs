//! SSR connection configuration.

use super::obfs::ObfsKind;
use super::protocol::ProtocolKind;

pub use super::legacy_cipher::LegacyCipherKind as CipherKind;

/// Complete SSR connection configuration.
#[derive(Debug, Clone)]
pub struct SsrConfig {
    /// Password (used for EVP_BytesToKey cipher key derivation).
    pub password: String,

    /// Stream cipher algorithm (e.g. `CipherKind::AES_128_CFB128`).
    pub cipher: CipherKind,

    /// Protocol plugin variant.
    pub protocol: ProtocolKind,

    /// Protocol plugin parameter (e.g. user ID or obfs config string).
    pub protocol_param: String,

    /// Obfuscation plugin variant.
    pub obfs: ObfsKind,

    /// Obfuscation plugin parameter (e.g. hostname for `http_simple`).
    pub obfs_param: String,
}
