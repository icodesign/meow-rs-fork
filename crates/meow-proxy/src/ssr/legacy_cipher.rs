use std::fmt;
use std::str::FromStr;

use shadowsocks_crypto::CipherKind as CompatCipherKind;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LegacyCipherKind(LegacyCipherRepr);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum LegacyCipherRepr {
    Compat(CompatCipherKind),
    BfCfb,
    Chacha20Legacy,
    Salsa20,
}

#[cfg(test)]
impl LegacyCipherKind {
    pub const NONE: Self = Self(LegacyCipherRepr::Compat(CompatCipherKind::NONE));
    pub const AES_128_CTR: Self = Self(LegacyCipherRepr::Compat(CompatCipherKind::AES_128_CTR));
    pub const AES_128_CFB128: Self =
        Self(LegacyCipherRepr::Compat(CompatCipherKind::AES_128_CFB128));
    pub const AES_256_CFB128: Self =
        Self(LegacyCipherRepr::Compat(CompatCipherKind::AES_256_CFB128));
}

impl LegacyCipherKind {
    pub const BF_CFB: Self = Self(LegacyCipherRepr::BfCfb);
    pub const CHACHA20_LEGACY: Self = Self(LegacyCipherRepr::Chacha20Legacy);
    pub const SALSA20: Self = Self(LegacyCipherRepr::Salsa20);

    pub fn compat_kind(self) -> Option<CompatCipherKind> {
        match self.0 {
            LegacyCipherRepr::Compat(kind) => Some(kind),
            _ => None,
        }
    }

    pub fn key_len(self) -> usize {
        match self.0 {
            LegacyCipherRepr::Compat(kind) => kind.key_len(),
            LegacyCipherRepr::BfCfb => 16,
            LegacyCipherRepr::Chacha20Legacy | LegacyCipherRepr::Salsa20 => 32,
        }
    }

    pub fn iv_len(self) -> usize {
        match self.0 {
            LegacyCipherRepr::Compat(kind) => kind.iv_len(),
            LegacyCipherRepr::BfCfb
            | LegacyCipherRepr::Chacha20Legacy
            | LegacyCipherRepr::Salsa20 => 8,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self.0 {
            LegacyCipherRepr::Compat(CompatCipherKind::NONE) => "none",
            LegacyCipherRepr::Compat(CompatCipherKind::SS_TABLE) => "table",
            LegacyCipherRepr::Compat(CompatCipherKind::SS_RC4_MD5) => "rc4-md5",
            LegacyCipherRepr::Compat(CompatCipherKind::AES_128_CTR) => "aes-128-ctr",
            LegacyCipherRepr::Compat(CompatCipherKind::AES_192_CTR) => "aes-192-ctr",
            LegacyCipherRepr::Compat(CompatCipherKind::AES_256_CTR) => "aes-256-ctr",
            LegacyCipherRepr::Compat(CompatCipherKind::AES_128_CFB1) => "aes-128-cfb1",
            LegacyCipherRepr::Compat(CompatCipherKind::AES_128_CFB8) => "aes-128-cfb8",
            LegacyCipherRepr::Compat(CompatCipherKind::AES_128_CFB128) => "aes-128-cfb",
            LegacyCipherRepr::Compat(CompatCipherKind::AES_192_CFB1) => "aes-192-cfb1",
            LegacyCipherRepr::Compat(CompatCipherKind::AES_192_CFB8) => "aes-192-cfb8",
            LegacyCipherRepr::Compat(CompatCipherKind::AES_192_CFB128) => "aes-192-cfb",
            LegacyCipherRepr::Compat(CompatCipherKind::AES_256_CFB1) => "aes-256-cfb1",
            LegacyCipherRepr::Compat(CompatCipherKind::AES_256_CFB8) => "aes-256-cfb8",
            LegacyCipherRepr::Compat(CompatCipherKind::AES_256_CFB128) => "aes-256-cfb",
            LegacyCipherRepr::Compat(CompatCipherKind::AES_128_OFB) => "aes-128-ofb",
            LegacyCipherRepr::Compat(CompatCipherKind::AES_192_OFB) => "aes-192-ofb",
            LegacyCipherRepr::Compat(CompatCipherKind::AES_256_OFB) => "aes-256-ofb",
            LegacyCipherRepr::Compat(CompatCipherKind::CAMELLIA_128_CTR) => "camellia-128-ctr",
            LegacyCipherRepr::Compat(CompatCipherKind::CAMELLIA_192_CTR) => "camellia-192-ctr",
            LegacyCipherRepr::Compat(CompatCipherKind::CAMELLIA_256_CTR) => "camellia-256-ctr",
            LegacyCipherRepr::Compat(CompatCipherKind::CAMELLIA_128_CFB1) => "camellia-128-cfb1",
            LegacyCipherRepr::Compat(CompatCipherKind::CAMELLIA_128_CFB8) => "camellia-128-cfb8",
            LegacyCipherRepr::Compat(CompatCipherKind::CAMELLIA_128_CFB128) => "camellia-128-cfb",
            LegacyCipherRepr::Compat(CompatCipherKind::CAMELLIA_192_CFB1) => "camellia-192-cfb1",
            LegacyCipherRepr::Compat(CompatCipherKind::CAMELLIA_192_CFB8) => "camellia-192-cfb8",
            LegacyCipherRepr::Compat(CompatCipherKind::CAMELLIA_192_CFB128) => "camellia-192-cfb",
            LegacyCipherRepr::Compat(CompatCipherKind::CAMELLIA_256_CFB1) => "camellia-256-cfb1",
            LegacyCipherRepr::Compat(CompatCipherKind::CAMELLIA_256_CFB8) => "camellia-256-cfb8",
            LegacyCipherRepr::Compat(CompatCipherKind::CAMELLIA_256_CFB128) => "camellia-256-cfb",
            LegacyCipherRepr::Compat(CompatCipherKind::CAMELLIA_128_OFB) => "camellia-128-ofb",
            LegacyCipherRepr::Compat(CompatCipherKind::CAMELLIA_192_OFB) => "camellia-192-ofb",
            LegacyCipherRepr::Compat(CompatCipherKind::CAMELLIA_256_OFB) => "camellia-256-ofb",
            LegacyCipherRepr::Compat(CompatCipherKind::RC4) => "rc4",
            LegacyCipherRepr::Compat(CompatCipherKind::CHACHA20) => "chacha20-ietf",
            LegacyCipherRepr::BfCfb => "bf-cfb",
            LegacyCipherRepr::Chacha20Legacy => "chacha20",
            LegacyCipherRepr::Salsa20 => "salsa20",
            LegacyCipherRepr::Compat(_) => "legacy-unknown",
        }
    }
}

impl fmt::Display for LegacyCipherKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for LegacyCipherKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Debug, Clone)]
pub struct ParseLegacyCipherKindError;

impl fmt::Display for ParseLegacyCipherKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid legacy Shadowsocks cipher")
    }
}

impl FromStr for LegacyCipherKind {
    type Err = ParseLegacyCipherKindError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "bf-cfb" => Ok(Self::BF_CFB),
            "chacha20" => Ok(Self::CHACHA20_LEGACY),
            "salsa20" => Ok(Self::SALSA20),
            _ => CompatCipherKind::from_str(s)
                .map(|kind| Self(LegacyCipherRepr::Compat(kind)))
                .map_err(|_| ParseLegacyCipherKindError),
        }
    }
}
