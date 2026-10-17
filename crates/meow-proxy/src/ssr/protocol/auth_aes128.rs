//! `auth_aes128_md5` / `auth_aes128_sha1` protocol plugins compatible with the
//! Python ShadowsocksR implementation.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes128;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use md5::Md5;
use rand::RngCore;
use sha1::Sha1;
use shadowsocks_crypto::v1::openssl_bytes_to_key;

use super::ProtocolPlugin;

const SALT_MD5: &[u8] = b"auth_aes128_md5";
const SALT_SHA1: &[u8] = b"auth_aes128_sha1";
const UNIT_LEN: usize = 8100;
const MAX_TIME_DIFF_SECS: i64 = 60 * 60 * 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacVariant {
    Md5,
    Sha1,
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <Hmac<Md5>>::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac = <Hmac<Sha1>>::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hmac(variant: HmacVariant, key: &[u8], data: &[u8]) -> Vec<u8> {
    match variant {
        HmacVariant::Md5 => hmac_md5(key, data).to_vec(),
        HmacVariant::Sha1 => hmac_sha1(key, data).to_vec(),
    }
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

fn aes128_cbc_key(user_key: &[u8], salt: &[u8]) -> [u8; 16] {
    let mut password = BASE64_STANDARD.encode(user_key).into_bytes();
    password.extend_from_slice(salt);
    let mut key = [0u8; 16];
    openssl_bytes_to_key(&password, &mut key);
    key
}

fn aes128_cbc_encrypt_no_padding(key: &[u8; 16], plaintext: &[u8; 16]) -> [u8; 16] {
    let iv = [0u8; 16];
    let mut buf = *plaintext;
    let enc = cbc::Encryptor::<Aes128>::new(key.into(), (&iv).into())
        .encrypt_padded_mut::<NoPadding>(&mut buf, plaintext.len())
        .expect("fixed 16-byte input fits exactly");
    enc.try_into()
        .expect("ciphertext length must stay 16 bytes")
}

fn aes128_cbc_decrypt_no_padding(key: &[u8; 16], ciphertext: &[u8; 16]) -> io::Result<[u8; 16]> {
    let iv = [0u8; 16];
    let mut buf = *ciphertext;
    let dec = cbc::Decryptor::<Aes128>::new(key.into(), (&iv).into())
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "auth_aes128: AES decrypt failed",
            )
        })?;
    dec.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "auth_aes128: invalid plaintext size",
        )
    })
}

fn rnd_data(buf_size: usize) -> Vec<u8> {
    if buf_size > 1300 {
        return vec![1];
    }

    let data_len = if buf_size > 900 {
        random_u16() % 512
    } else {
        random_u16() % 1024
    } as usize;

    if data_len < 128 {
        let mut out = Vec::with_capacity(data_len + 1);
        out.push((data_len + 1) as u8);
        out.extend_from_slice(&random_bytes(data_len));
        out
    } else {
        let mut out = Vec::with_capacity(data_len + 1);
        out.push(0xFF);
        out.extend_from_slice(&((data_len + 1) as u16).to_le_bytes());
        out.extend_from_slice(&random_bytes(data_len.saturating_sub(2)));
        out
    }
}

fn payload_offset(frame: &[u8]) -> io::Result<usize> {
    if frame.len() < 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "auth_aes128: frame too short",
        ));
    }
    if frame[4] < 0xFF {
        Ok(4 + frame[4] as usize)
    } else {
        if frame.len() < 7 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "auth_aes128: truncated long random prefix",
            ));
        }
        Ok(4 + u16::from_le_bytes([frame[5], frame[6]]) as usize)
    }
}

pub struct AuthAes128 {
    variant: HmacVariant,
    session_key: Vec<u8>,
    cipher_iv: Vec<u8>,
    is_server: bool,
    has_sent_header: bool,
    has_recv_header: bool,
    recv_buf: Vec<u8>,
    local_client_id: Option<[u8; 4]>,
    connection_id: u32,
    user_key: Vec<u8>,
    pack_id: u32,
    recv_id: u32,
}

impl AuthAes128 {
    pub fn new(session_key: Vec<u8>, variant: HmacVariant, is_server: bool) -> Self {
        Self {
            variant,
            session_key: session_key.clone(),
            cipher_iv: Vec::new(),
            is_server,
            has_sent_header: false,
            has_recv_header: false,
            recv_buf: Vec::new(),
            local_client_id: None,
            connection_id: 0,
            user_key: session_key,
            pack_id: 1,
            recv_id: 1,
        }
    }

    fn salt(&self) -> &'static [u8] {
        match self.variant {
            HmacVariant::Md5 => SALT_MD5,
            HmacVariant::Sha1 => SALT_SHA1,
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

    fn pack_auth_data(&mut self, buf: &[u8]) -> Vec<u8> {
        let rnd_len = if buf.len() > 400 {
            (random_u16() % 512) as usize
        } else {
            (random_u16() % 1024) as usize
        };

        let total_len = (35 + rnd_len + buf.len()) as u16;
        let mut header = [0u8; 16];
        header[..12].copy_from_slice(&self.auth_data());
        header[12..14].copy_from_slice(&total_len.to_le_bytes());
        header[14..16].copy_from_slice(&(rnd_len as u16).to_le_bytes());

        let uid = random_bytes(4);
        let aes_key = aes128_cbc_key(&self.user_key, self.salt());
        let ciphertext = aes128_cbc_encrypt_no_padding(&aes_key, &header);

        let mut mac_key = self.cipher_iv.clone();
        mac_key.extend_from_slice(&self.session_key);

        let mut auth_part = Vec::with_capacity(24);
        auth_part.extend_from_slice(&uid);
        auth_part.extend_from_slice(&ciphertext);
        auth_part.extend_from_slice(&hmac(self.variant, &mac_key, &auth_part)[..4]);

        let check_head = [random_u8()];
        let mut out = Vec::with_capacity(total_len as usize);
        out.extend_from_slice(&check_head);
        out.extend_from_slice(&hmac(self.variant, &mac_key, &check_head)[..6]);
        out.extend_from_slice(&auth_part);
        out.extend_from_slice(&random_bytes(rnd_len));
        out.extend_from_slice(buf);
        out.extend_from_slice(&hmac(self.variant, &self.user_key, &out)[..4]);
        out
    }

    fn pack_data(&mut self, buf: &[u8]) -> Vec<u8> {
        let mut body = rnd_data(buf.len());
        body.extend_from_slice(buf);

        let total_len = (body.len() + 8) as u16;
        let total_len_le = total_len.to_le_bytes();

        let mut mac_key = self.user_key.clone();
        mac_key.extend_from_slice(&self.pack_id.to_le_bytes());

        let mut out = Vec::with_capacity(total_len as usize);
        out.extend_from_slice(&total_len_le);
        out.extend_from_slice(&hmac(self.variant, &mac_key, &total_len_le)[..2]);
        out.extend_from_slice(&body);
        out.extend_from_slice(&hmac(self.variant, &mac_key, &out)[..4]);
        self.pack_id = self.pack_id.wrapping_add(1);
        out
    }

    fn decode_regular_frames(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut out = Vec::new();

        while self.recv_buf.len() > 4 {
            let mut mac_key = self.user_key.clone();
            mac_key.extend_from_slice(&self.recv_id.to_le_bytes());

            if hmac(self.variant, &mac_key, &self.recv_buf[..2])[..2] != self.recv_buf[2..4] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_aes128: frame MAC mismatch",
                ));
            }

            let length = u16::from_le_bytes([self.recv_buf[0], self.recv_buf[1]]) as usize;
            if !(7..8192).contains(&length) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_aes128: invalid frame length",
                ));
            }
            if self.recv_buf.len() < length {
                break;
            }

            if hmac(self.variant, &mac_key, &self.recv_buf[..length - 4])[..4]
                != self.recv_buf[length - 4..length]
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_aes128: frame checksum mismatch",
                ));
            }

            let pos = payload_offset(&self.recv_buf[..length])?;
            out.extend_from_slice(&self.recv_buf[pos..length - 4]);
            self.recv_buf.drain(..length);
            self.recv_id = self.recv_id.wrapping_add(1);
        }

        if out.is_empty() {
            Ok(None)
        } else {
            Ok(Some(out))
        }
    }
}

impl ProtocolPlugin for AuthAes128 {
    fn set_iv(&mut self, iv: &[u8], _session_key: &[u8]) {
        self.cipher_iv = iv.to_vec();
    }

    fn encode(&mut self, data: &[u8], _is_first: bool) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut rest = data;

        if !self.has_sent_header {
            let head_size = get_head_size(rest, 30);
            let data_len = rest.len().min((random_u8() as usize % 32) + head_size);
            out.extend_from_slice(&self.pack_auth_data(&rest[..data_len]));
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
            if self.recv_buf.len() >= 2
                && (self.recv_buf.len() == 2
                    || self.recv_buf.len() == 3
                    || self.recv_buf.len() >= 7)
            {
                let recv_len = self.recv_buf.len().min(7);
                let mut mac_key = self.cipher_iv.clone();
                mac_key.extend_from_slice(&self.session_key);
                if hmac(self.variant, &mac_key, &self.recv_buf[..1])[..recv_len - 1]
                    != self.recv_buf[1..recv_len]
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "auth_aes128: check head mismatch",
                    ));
                }
            }

            if self.recv_buf.len() < 31 {
                return Ok(None);
            }

            let mut mac_key = self.cipher_iv.clone();
            mac_key.extend_from_slice(&self.session_key);
            if hmac(self.variant, &mac_key, &self.recv_buf[7..27])[..4] != self.recv_buf[27..31] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_aes128: auth header MAC mismatch",
                ));
            }

            let aes_key = aes128_cbc_key(&self.user_key, self.salt());
            let ciphertext: [u8; 16] = self.recv_buf[11..27].try_into().unwrap();
            let header = aes128_cbc_decrypt_no_padding(&aes_key, &ciphertext)?;
            let length = u16::from_le_bytes(header[12..14].try_into().unwrap()) as usize;
            let rnd_len = u16::from_le_bytes(header[14..16].try_into().unwrap()) as usize;
            if self.recv_buf.len() < length {
                return Ok(None);
            }

            if hmac(self.variant, &self.user_key, &self.recv_buf[..length - 4])[..4]
                != self.recv_buf[length - 4..length]
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_aes128: auth packet checksum mismatch",
                ));
            }

            let timestamp = u32::from_le_bytes(header[..4].try_into().unwrap()) as i64;
            let now = current_unix_secs() as i64;
            if (timestamp - now).abs() > MAX_TIME_DIFF_SECS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_aes128: timestamp out of range",
                ));
            }

            let mut out = self.recv_buf[31 + rnd_len..length - 4].to_vec();
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
