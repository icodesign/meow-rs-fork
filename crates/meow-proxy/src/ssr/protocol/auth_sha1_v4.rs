//! `auth_sha1_v4` protocol plugin compatible with the Python ShadowsocksR
//! implementation.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;

use super::ProtocolPlugin;

const AUTH_SALT: &[u8] = b"auth_sha1_v4";
const UNIT_LEN: usize = 8100;
const MAX_TIME_DIFF_SECS: i64 = 60 * 60 * 24;

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac = <Hmac<Sha1>>::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rng().fill_bytes(&mut buf);
    buf
}

fn random_u8() -> u8 {
    rand::random()
}

fn random_u16() -> u16 {
    rand::random()
}

fn current_unix_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

fn crc32_le(data: &[u8]) -> [u8; 4] {
    crc32fast::hash(data).to_le_bytes()
}

fn crc32_low16_le(data: &[u8]) -> [u8; 2] {
    (crc32fast::hash(data) as u16).to_le_bytes()
}

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in data {
        a = (a + byte as u32) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

fn get_head_size(buf: &[u8], default: usize) -> usize {
    if buf.len() < 2 {
        return default;
    }
    match buf[0] & 0x07 {
        0x01 => 7,
        0x04 => 19,
        0x03 => 4 + buf[1] as usize,
        _ => default,
    }
}

fn rnd_data(buf_size: usize) -> Vec<u8> {
    let rnd = if buf_size > 1200 {
        Vec::new()
    } else if buf_size > 400 {
        random_bytes(random_u8() as usize)
    } else {
        random_bytes((random_u16() % 512) as usize)
    };

    if rnd.is_empty() {
        return vec![1];
    }

    if rnd.len() < 128 {
        let mut out = Vec::with_capacity(rnd.len() + 1);
        out.push((rnd.len() + 1) as u8);
        out.extend_from_slice(&rnd);
        out
    } else {
        let mut out = Vec::with_capacity(rnd.len() + 3);
        out.push(0xFF);
        out.extend_from_slice(&((rnd.len() + 3) as u16).to_be_bytes());
        out.extend_from_slice(&rnd);
        out
    }
}

fn payload_offset(prefix: &[u8], base: usize) -> io::Result<usize> {
    if prefix.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "auth_sha1_v4: missing random prefix",
        ));
    }
    if prefix[0] < 0xFF {
        Ok(base + prefix[0] as usize)
    } else {
        if prefix.len() < 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "auth_sha1_v4: truncated long random prefix",
            ));
        }
        Ok(base + u16::from_be_bytes([prefix[1], prefix[2]]) as usize)
    }
}

pub struct AuthSha1V4 {
    session_key: Vec<u8>,
    cipher_iv: Vec<u8>,
    is_server: bool,
    has_sent_header: bool,
    has_recv_header: bool,
    recv_buf: Vec<u8>,
    local_client_id: Option<[u8; 4]>,
    connection_id: u32,
}

impl AuthSha1V4 {
    pub fn new(session_key: Vec<u8>, is_server: bool) -> Self {
        Self {
            session_key,
            cipher_iv: Vec::new(),
            is_server,
            has_sent_header: false,
            has_recv_header: false,
            recv_buf: Vec::new(),
            local_client_id: None,
            connection_id: 0,
        }
    }

    fn auth_data(&mut self) -> [u8; 12] {
        if self.local_client_id.is_none() || self.connection_id > 0xFF00_0000 {
            let mut client_id = [0u8; 4];
            rand::rng().fill_bytes(&mut client_id);
            self.local_client_id = Some(client_id);
            self.connection_id = (random_u16() as u32) | (((random_u16() & 0x00FF) as u32) << 16);
        }
        self.connection_id = self.connection_id.wrapping_add(1);

        let mut out = [0u8; 12];
        out[..4].copy_from_slice(&current_unix_secs().to_le_bytes());
        out[4..8].copy_from_slice(&self.local_client_id.unwrap());
        out[8..12].copy_from_slice(&self.connection_id.to_le_bytes());
        out
    }

    fn pack_data(&self, buf: &[u8]) -> Vec<u8> {
        let mut body = rnd_data(buf.len());
        body.extend_from_slice(buf);

        let total_len = (body.len() + 8) as u16;
        let mut out = Vec::with_capacity(total_len as usize);
        let total_len_be = total_len.to_be_bytes();
        out.extend_from_slice(&total_len_be);
        out.extend_from_slice(&crc32_low16_le(&total_len_be));
        out.extend_from_slice(&body);
        out.extend_from_slice(&adler32(&out).to_le_bytes());
        out
    }

    fn pack_auth_data(&self, auth_payload: &[u8]) -> Vec<u8> {
        let mut body = rnd_data(auth_payload.len());
        body.extend_from_slice(auth_payload);

        let total_len = (body.len() + 16) as u16;
        let total_len_be = total_len.to_be_bytes();

        let mut out = Vec::with_capacity(total_len as usize);
        out.extend_from_slice(&total_len_be);

        let mut crc_input = Vec::with_capacity(2 + AUTH_SALT.len() + self.session_key.len());
        crc_input.extend_from_slice(&total_len_be);
        crc_input.extend_from_slice(AUTH_SALT);
        crc_input.extend_from_slice(&self.session_key);
        out.extend_from_slice(&crc32_le(&crc_input));
        out.extend_from_slice(&body);

        let mut hmac_key = Vec::with_capacity(self.cipher_iv.len() + self.session_key.len());
        hmac_key.extend_from_slice(&self.cipher_iv);
        hmac_key.extend_from_slice(&self.session_key);
        out.extend_from_slice(&hmac_sha1(&hmac_key, &out)[..10]);
        out
    }

    fn decode_regular_frames(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut out = Vec::new();

        while self.recv_buf.len() > 4 {
            let expected_crc = crc32_low16_le(&self.recv_buf[..2]);
            if expected_crc != self.recv_buf[2..4] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_sha1_v4: frame CRC mismatch",
                ));
            }

            let length = u16::from_be_bytes([self.recv_buf[0], self.recv_buf[1]]) as usize;
            if !(7..8192).contains(&length) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_sha1_v4: invalid frame length",
                ));
            }
            if self.recv_buf.len() < length {
                break;
            }

            let expected_adler = adler32(&self.recv_buf[..length - 4]).to_le_bytes();
            if expected_adler != self.recv_buf[length - 4..length] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_sha1_v4: frame Adler32 mismatch",
                ));
            }

            let pos = payload_offset(&self.recv_buf[4..length - 4], 4)?;
            out.extend_from_slice(&self.recv_buf[pos..length - 4]);
            self.recv_buf.drain(..length);
        }

        if out.is_empty() {
            Ok(None)
        } else {
            Ok(Some(out))
        }
    }
}

impl ProtocolPlugin for AuthSha1V4 {
    fn set_iv(&mut self, iv: &[u8], _session_key: &[u8]) {
        self.cipher_iv = iv.to_vec();
    }

    fn encode(&mut self, data: &[u8], _is_first: bool) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut rest = data;

        if !self.has_sent_header {
            let head_size = get_head_size(rest, 30);
            let data_len = rest.len().min((random_u8() as usize % 32) + head_size);
            let mut auth_payload = self.auth_data().to_vec();
            auth_payload.extend_from_slice(&rest[..data_len]);
            out.extend_from_slice(&self.pack_auth_data(&auth_payload));
            rest = &rest[data_len..];
            self.has_sent_header = true;
        }

        while rest.len() > UNIT_LEN {
            out.extend_from_slice(&self.pack_data(&rest[..UNIT_LEN]));
            rest = &rest[UNIT_LEN..];
        }
        out.extend_from_slice(&self.pack_data(rest));

        Ok(out)
    }

    fn decode(&mut self, data: &[u8]) -> io::Result<Option<Vec<u8>>> {
        self.recv_buf.extend_from_slice(data);

        if self.is_server && !self.has_recv_header {
            if self.recv_buf.len() <= 6 {
                return Ok(None);
            }

            let mut crc_input = Vec::with_capacity(2 + AUTH_SALT.len() + self.session_key.len());
            crc_input.extend_from_slice(&self.recv_buf[..2]);
            crc_input.extend_from_slice(AUTH_SALT);
            crc_input.extend_from_slice(&self.session_key);
            if crc32_le(&crc_input) != self.recv_buf[2..6] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_sha1_v4: auth header CRC mismatch",
                ));
            }

            let length = u16::from_be_bytes([self.recv_buf[0], self.recv_buf[1]]) as usize;
            if self.recv_buf.len() < length {
                return Ok(None);
            }

            let mut hmac_key = Vec::with_capacity(self.cipher_iv.len() + self.session_key.len());
            hmac_key.extend_from_slice(&self.cipher_iv);
            hmac_key.extend_from_slice(&self.session_key);
            let expected_hmac = hmac_sha1(&hmac_key, &self.recv_buf[..length - 10]);
            if expected_hmac[..10] != self.recv_buf[length - 10..length] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_sha1_v4: auth header HMAC mismatch",
                ));
            }

            let pos = payload_offset(&self.recv_buf[6..length - 10], 6)?;
            let auth_payload = self.recv_buf[pos..length - 10].to_vec();
            if auth_payload.len() < 12 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_sha1_v4: auth payload too short",
                ));
            }

            let timestamp = u32::from_le_bytes(auth_payload[..4].try_into().unwrap()) as i64;
            let now = current_unix_secs() as i64;
            if (timestamp - now).abs() > MAX_TIME_DIFF_SECS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_sha1_v4: timestamp out of range",
                ));
            }

            let mut out = auth_payload[12..].to_vec();
            self.recv_buf.drain(..length);
            self.has_recv_header = true;

            if let Some(more) = self.decode_regular_frames()? {
                out.extend_from_slice(&more);
            }

            if out.is_empty() {
                Ok(None)
            } else {
                Ok(Some(out))
            }
        } else {
            self.has_recv_header = true;
            self.decode_regular_frames()
        }
    }
}
