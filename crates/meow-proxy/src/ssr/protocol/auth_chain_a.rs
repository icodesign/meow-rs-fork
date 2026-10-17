//! `auth_chain_a` / `auth_chain_b` protocol plugins compatible with the Python
//! ShadowsocksR implementation.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes128;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use md5::Md5;
use rand::RngCore;
use shadowsocks_crypto::v1::openssl_bytes_to_key;

use super::ProtocolPlugin;

const MAX_TIME_DIFF_SECS: i64 = 60 * 60 * 24;
const DEFAULT_TCP_MSS: u16 = 1460;
const OVERHEAD: u16 = 4;
const UNIT_LEN: usize = 2800;
const SALT_A: &[u8] = b"auth_chain_a";
const SALT_B: &[u8] = b"auth_chain_b";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthChainVariant {
    A,
    B,
}

impl AuthChainVariant {
    fn salt(self) -> &'static [u8] {
        match self {
            Self::A => SALT_A,
            Self::B => SALT_B,
        }
    }
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <Hmac<Md5>>::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rand::rng().fill_bytes(&mut out);
    out
}

fn random_u8() -> u8 {
    rand::random()
}

fn random_u32() -> u32 {
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
        .expect("fixed-size input always fits");
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
                "auth_chain: AES-CBC decrypt failed",
            )
        })?;
    dec.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "auth_chain: invalid AES-CBC plaintext size",
        )
    })
}

fn partition_point(data: &[u16], target: u16) -> usize {
    let mut left = 0usize;
    let mut right = data.len();
    while left < right {
        let mid = left + (right - left) / 2;
        if data[mid] < target {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    left
}

struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        debug_assert!(!key.is_empty());

        let mut state = [0u8; 256];
        for (idx, byte) in state.iter_mut().enumerate() {
            *byte = idx as u8;
        }

        let mut j = 0u8;
        for i in 0..256usize {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, j as usize);
        }

        Self { state, i: 0, j: 0 }
    }

    fn process(&mut self, buf: &mut [u8]) {
        for byte in buf {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[self.i as usize]);
            self.state.swap(self.i as usize, self.j as usize);
            let idx =
                self.state[self.i as usize].wrapping_add(self.state[self.j as usize]) as usize;
            *byte ^= self.state[idx];
        }
    }
}

#[derive(Debug, Clone)]
struct XorShift128Plus {
    v0: u64,
    v1: u64,
}

impl XorShift128Plus {
    const MAX_INT: u64 = (1u64 << 63).wrapping_mul(2).wrapping_sub(1);
    const MOV_MASK: u64 = (1u64 << (64 - 23)) - 1;

    fn new() -> Self {
        Self { v0: 0, v1: 0 }
    }

    fn next(&mut self) -> u64 {
        let mut x = self.v0;
        let y = self.v1;
        self.v0 = y;
        x ^= (x & Self::MOV_MASK) << 23;
        x ^= (y ^ (x >> 17) ^ (y >> 26)) & Self::MAX_INT;
        self.v1 = x;
        x.wrapping_add(y)
    }

    fn init_from_bin_len(&mut self, seed: &[u8], length: u16) {
        let mut buf = [0u8; 16];
        let copy_len = seed.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&seed[..copy_len]);
        buf[..2].copy_from_slice(&length.to_le_bytes());
        self.v0 = u64::from_le_bytes(buf[..8].try_into().unwrap());
        self.v1 = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        for _ in 0..4 {
            let _ = self.next();
        }
    }

    fn init_from_bin(&mut self, seed: &[u8]) {
        let mut buf = [0u8; 16];
        let copy_len = seed.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&seed[..copy_len]);
        self.v0 = u64::from_le_bytes(buf[..8].try_into().unwrap());
        self.v1 = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    }
}

fn parse_protocol_param(param: &str) -> Option<(u32, Vec<u8>)> {
    let (uid, key) = param.split_once(':')?;
    let uid = uid.parse::<u32>().ok()?;
    Some((uid, key.as_bytes().to_vec()))
}

fn rc4_key_material(user_key: &[u8], last_hash: &[u8; 16]) -> [u8; 16] {
    let mut password = BASE64_STANDARD.encode(user_key).into_bytes();
    password.extend_from_slice(BASE64_STANDARD.encode(last_hash).as_bytes());
    let mut key = [0u8; 16];
    openssl_bytes_to_key(&password, &mut key);
    key
}

fn rnd_start_pos(rand_len: usize, rng: &mut XorShift128Plus) -> usize {
    if rand_len == 0 {
        0
    } else {
        (rng.next() % 8_589_934_609u64 % rand_len as u64) as usize
    }
}

fn rnd_data_len(
    variant: AuthChainVariant,
    buf_size: usize,
    last_hash: &[u8; 16],
    rng: &mut XorShift128Plus,
    data_size_list: &[u16],
    data_size_list2: &[u16],
) -> usize {
    if buf_size >= 1440 {
        return 0;
    }

    rng.init_from_bin_len(last_hash, buf_size as u16);

    if variant == AuthChainVariant::B {
        let target = buf_size as u16 + OVERHEAD;

        let pos = partition_point(data_size_list, target);
        if !data_size_list.is_empty() {
            let final_pos = pos + (rng.next() as usize % data_size_list.len());
            if final_pos < data_size_list.len() {
                return (data_size_list[final_pos] - target) as usize;
            }
        }

        let pos2 = partition_point(data_size_list2, target);
        if !data_size_list2.is_empty() {
            let final_pos = pos2 + (rng.next() as usize % data_size_list2.len());
            if final_pos < data_size_list2.len() {
                return (data_size_list2[final_pos] - target) as usize;
            }
            if final_pos < pos2 + data_size_list2.len().saturating_sub(1) {
                return 0;
            }
        }
    }

    if buf_size > 1300 {
        (rng.next() % 31) as usize
    } else if buf_size > 900 {
        (rng.next() % 127) as usize
    } else if buf_size > 400 {
        (rng.next() % 521) as usize
    } else {
        (rng.next() % 1021) as usize
    }
}

fn rnd_data(
    variant: AuthChainVariant,
    buf: &[u8],
    last_hash: &[u8; 16],
    rng: &mut XorShift128Plus,
    data_size_list: &[u16],
    data_size_list2: &[u16],
) -> Vec<u8> {
    let rand_len = rnd_data_len(
        variant,
        buf.len(),
        last_hash,
        rng,
        data_size_list,
        data_size_list2,
    );
    let random_pad = random_bytes(rand_len);

    if buf.is_empty() {
        return random_pad;
    }

    if rand_len == 0 {
        return buf.to_vec();
    }

    let start = rnd_start_pos(rand_len, rng);
    let mut out = Vec::with_capacity(rand_len + buf.len());
    out.extend_from_slice(&random_pad[..start]);
    out.extend_from_slice(buf);
    out.extend_from_slice(&random_pad[start..]);
    out
}

fn init_data_size(key: &[u8]) -> (Vec<u16>, Vec<u16>) {
    let mut random = XorShift128Plus::new();
    random.init_from_bin(key);

    let mut list1 = Vec::new();
    for _ in 0..(random.next() % 8 + 4) {
        list1.push((random.next() % 2340 % 2040 % 1440) as u16);
    }
    list1.sort_unstable();

    let mut list2 = Vec::new();
    for _ in 0..(random.next() % 16 + 8) {
        list2.push((random.next() % 2340 % 2040 % 1440) as u16);
    }
    list2.sort_unstable();

    (list1, list2)
}

pub struct AuthChainA {
    variant: AuthChainVariant,
    session_key: Vec<u8>,
    cipher_iv: Vec<u8>,
    configured_user: Option<(u32, Vec<u8>)>,
    is_server: bool,
    has_sent_header: bool,
    has_recv_header: bool,
    recv_buf: Vec<u8>,
    local_client_id: Option<[u8; 4]>,
    connection_id: u32,
    user_key: Vec<u8>,
    pack_id: u32,
    recv_id: u32,
    client_overhead: u16,
    last_client_hash: [u8; 16],
    last_server_hash: [u8; 16],
    random_client: XorShift128Plus,
    random_server: XorShift128Plus,
    tx_rc4: Option<Rc4>,
    rx_rc4: Option<Rc4>,
    unit_len: usize,
    data_size_list: Vec<u16>,
    data_size_list2: Vec<u16>,
}

impl AuthChainA {
    pub fn new(
        session_key: Vec<u8>,
        protocol_param: &str,
        variant: AuthChainVariant,
        is_server: bool,
    ) -> Self {
        let configured_user = parse_protocol_param(protocol_param);
        let user_key = configured_user
            .as_ref()
            .map_or_else(|| session_key.clone(), |(_, key)| key.clone());
        let (data_size_list, data_size_list2) = if variant == AuthChainVariant::B {
            init_data_size(&session_key)
        } else {
            (Vec::new(), Vec::new())
        };

        Self {
            variant,
            session_key,
            cipher_iv: Vec::new(),
            configured_user,
            is_server,
            has_sent_header: false,
            has_recv_header: false,
            recv_buf: Vec::new(),
            local_client_id: None,
            connection_id: 0,
            user_key,
            pack_id: 1,
            recv_id: 1,
            client_overhead: OVERHEAD,
            last_client_hash: [0u8; 16],
            last_server_hash: [0u8; 16],
            random_client: XorShift128Plus::new(),
            random_server: XorShift128Plus::new(),
            tx_rc4: None,
            rx_rc4: None,
            unit_len: UNIT_LEN,
            data_size_list,
            data_size_list2,
        }
    }

    fn auth_data(&mut self) -> [u8; 12] {
        if self.local_client_id.is_none() || self.connection_id > 0xFF00_0000 {
            let mut client_id = [0u8; 4];
            rand::rng().fill_bytes(&mut client_id);
            self.local_client_id = Some(client_id);
            self.connection_id = random_u32() & 0x00FF_FFFF;
        }
        self.connection_id = self.connection_id.wrapping_add(1);

        let mut out = [0u8; 12];
        out[..4].copy_from_slice(&current_unix_secs().to_le_bytes());
        out[4..8].copy_from_slice(&self.local_client_id.unwrap());
        out[8..12].copy_from_slice(&self.connection_id.to_le_bytes());
        out
    }

    fn init_rc4_state(&mut self) {
        let key = rc4_key_material(&self.user_key, &self.last_client_hash);
        self.tx_rc4 = Some(Rc4::new(&key));
        self.rx_rc4 = Some(Rc4::new(&key));
    }

    fn rc4_encrypt(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        let rc4 = self.tx_rc4.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "auth_chain: RC4 encryptor missing",
            )
        })?;
        let mut out = data.to_vec();
        rc4.process(&mut out);
        Ok(out)
    }

    fn rc4_decrypt(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        let rc4 = self.rx_rc4.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "auth_chain: RC4 decryptor missing",
            )
        })?;
        let mut out = data.to_vec();
        rc4.process(&mut out);
        Ok(out)
    }

    fn pack_client_data(&mut self, buf: &[u8]) -> io::Result<Vec<u8>> {
        let encrypted = self.rc4_encrypt(buf)?;
        let payload = rnd_data(
            self.variant,
            &encrypted,
            &self.last_client_hash,
            &mut self.random_client,
            &self.data_size_list,
            &self.data_size_list2,
        );

        let mut frame = Vec::with_capacity(payload.len() + 4);
        let length = (encrypted.len() as u16)
            ^ u16::from_le_bytes(self.last_client_hash[14..16].try_into().unwrap());
        frame.extend_from_slice(&length.to_le_bytes());
        frame.extend_from_slice(&payload);

        let mut mac_key = self.user_key.clone();
        mac_key.extend_from_slice(&self.pack_id.to_le_bytes());
        self.last_client_hash = hmac_md5(&mac_key, &frame);
        frame.extend_from_slice(&self.last_client_hash[..2]);
        self.pack_id = self.pack_id.wrapping_add(1);
        Ok(frame)
    }

    fn pack_server_data(&mut self, buf: &[u8]) -> io::Result<Vec<u8>> {
        let encrypted = self.rc4_encrypt(buf)?;
        let payload = rnd_data(
            self.variant,
            &encrypted,
            &self.last_server_hash,
            &mut self.random_server,
            &self.data_size_list,
            &self.data_size_list2,
        );

        let mut frame = Vec::with_capacity(payload.len() + 4);
        let length = (encrypted.len() as u16)
            ^ u16::from_le_bytes(self.last_server_hash[14..16].try_into().unwrap());
        frame.extend_from_slice(&length.to_le_bytes());
        frame.extend_from_slice(&payload);

        let mut mac_key = self.user_key.clone();
        mac_key.extend_from_slice(&self.pack_id.to_le_bytes());
        self.last_server_hash = hmac_md5(&mac_key, &frame);
        frame.extend_from_slice(&self.last_server_hash[..2]);
        self.pack_id = self.pack_id.wrapping_add(1);
        Ok(frame)
    }

    fn pack_auth_data(&mut self, buf: &[u8]) -> io::Result<Vec<u8>> {
        let mut auth = [0u8; 16];
        auth[..12].copy_from_slice(&self.auth_data());
        auth[12..14].copy_from_slice(&OVERHEAD.to_le_bytes());

        let mut mac_key = self.cipher_iv.clone();
        mac_key.extend_from_slice(&self.session_key);

        let check_head = random_bytes(4);
        self.last_client_hash = hmac_md5(&mac_key, &check_head);

        let uid = self
            .configured_user
            .as_ref()
            .map_or_else(random_u32, |(uid, _)| *uid);
        self.user_key = self
            .configured_user
            .as_ref()
            .map_or_else(|| self.session_key.clone(), |(_, key)| key.clone());

        let auth_key = aes128_cbc_key(&self.user_key, self.variant.salt());
        let uid_xored = uid ^ u32::from_le_bytes(self.last_client_hash[8..12].try_into().unwrap());
        let ciphertext = aes128_cbc_encrypt_no_padding(&auth_key, &auth);

        let mut data = Vec::with_capacity(24);
        data.extend_from_slice(&uid_xored.to_le_bytes());
        data.extend_from_slice(&ciphertext);

        self.last_server_hash = hmac_md5(&self.user_key, &data);

        let mut out = Vec::with_capacity(36 + buf.len() + 1024);
        out.extend_from_slice(&check_head);
        out.extend_from_slice(&self.last_client_hash[..8]);
        out.extend_from_slice(&data);
        out.extend_from_slice(&self.last_server_hash[..4]);

        self.init_rc4_state();
        out.extend_from_slice(&self.pack_client_data(buf)?);
        Ok(out)
    }

    fn decode_frames(
        &mut self,
        receive_from_client: bool,
        recv_mss_prefix: bool,
    ) -> io::Result<Option<Vec<u8>>> {
        let mut out = Vec::new();

        while self.recv_buf.len() > 4 {
            let last_hash = if receive_from_client {
                self.last_client_hash
            } else {
                self.last_server_hash
            };

            let data_len = u16::from_le_bytes(self.recv_buf[..2].try_into().unwrap())
                ^ u16::from_le_bytes(last_hash[14..16].try_into().unwrap());
            let rand_len = rnd_data_len(
                self.variant,
                data_len as usize,
                &last_hash,
                if receive_from_client {
                    &mut self.random_client
                } else {
                    &mut self.random_server
                },
                &self.data_size_list,
                &self.data_size_list2,
            );
            let body_len = data_len as usize + rand_len;
            if body_len >= 4096 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_chain: frame length out of range",
                ));
            }
            if self.recv_buf.len() < body_len + 4 {
                break;
            }

            let mut mac_key = self.user_key.clone();
            mac_key.extend_from_slice(&self.recv_id.to_le_bytes());
            let expected = hmac_md5(&mac_key, &self.recv_buf[..body_len + 2]);
            if expected[..2] != self.recv_buf[body_len + 2..body_len + 4] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_chain: frame checksum mismatch",
                ));
            }

            let mut payload_offset = 2usize;
            if data_len > 0 && rand_len > 0 {
                payload_offset += rnd_start_pos(
                    rand_len,
                    if receive_from_client {
                        &mut self.random_client
                    } else {
                        &mut self.random_server
                    },
                );
            }

            let encrypted =
                self.recv_buf[payload_offset..payload_offset + data_len as usize].to_vec();
            let mut decrypted = self.rc4_decrypt(&encrypted)?;
            if recv_mss_prefix && self.recv_id == 1 {
                if decrypted.len() < 2 {
                    return Ok(None);
                }
                decrypted.drain(..2);
            }
            out.extend_from_slice(&decrypted);

            if receive_from_client {
                self.last_client_hash = expected;
            } else {
                self.last_server_hash = expected;
            }

            self.recv_buf.drain(..body_len + 4);
            self.recv_id = self.recv_id.wrapping_add(1);
        }

        if out.is_empty() {
            Ok(None)
        } else {
            Ok(Some(out))
        }
    }

    fn server_decode_auth_header(&mut self) -> io::Result<Option<()>> {
        if self.recv_buf.len() < 36 {
            return Ok(None);
        }

        let mut mac_key = self.cipher_iv.clone();
        mac_key.extend_from_slice(&self.session_key);
        let check_hash = hmac_md5(&mac_key, &self.recv_buf[..4]);
        if check_hash[..8] != self.recv_buf[4..12] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "auth_chain: auth check-head mismatch",
            ));
        }
        self.last_client_hash = check_hash;

        let decoded_uid = u32::from_le_bytes(self.recv_buf[12..16].try_into().unwrap())
            ^ u32::from_le_bytes(check_hash[8..12].try_into().unwrap());
        if let Some((expected_uid, key)) = &self.configured_user {
            if decoded_uid != *expected_uid {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "auth_chain: unexpected user id",
                ));
            }
            self.user_key = key.clone();
        } else {
            self.user_key = self.session_key.clone();
        }

        let auth_hash = hmac_md5(&self.user_key, &self.recv_buf[12..32]);
        if auth_hash[..4] != self.recv_buf[32..36] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "auth_chain: auth header checksum mismatch",
            ));
        }
        self.last_server_hash = auth_hash;

        let auth_key = aes128_cbc_key(&self.user_key, self.variant.salt());
        let ciphertext: [u8; 16] = self.recv_buf[16..32].try_into().unwrap();
        let header = aes128_cbc_decrypt_no_padding(&auth_key, &ciphertext)?;

        let timestamp = u32::from_le_bytes(header[..4].try_into().unwrap()) as i64;
        let now = current_unix_secs() as i64;
        if (timestamp - now).abs() > MAX_TIME_DIFF_SECS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "auth_chain: timestamp out of range",
            ));
        }

        self.client_overhead = u16::from_le_bytes(header[12..14].try_into().unwrap());
        self.init_rc4_state();
        self.recv_buf.drain(..36);
        self.has_recv_header = true;
        Ok(Some(()))
    }
}

impl ProtocolPlugin for AuthChainA {
    fn set_iv(&mut self, iv: &[u8], _session_key: &[u8]) {
        self.cipher_iv = iv.to_vec();
        self.has_sent_header = false;
        self.has_recv_header = false;
        self.recv_buf.clear();
        self.local_client_id = None;
        self.connection_id = 0;
        self.pack_id = 1;
        self.recv_id = 1;
        self.client_overhead = OVERHEAD;
        self.last_client_hash = [0u8; 16];
        self.last_server_hash = [0u8; 16];
        self.random_client = XorShift128Plus::new();
        self.random_server = XorShift128Plus::new();
        self.tx_rc4 = None;
        self.rx_rc4 = None;
        self.unit_len = UNIT_LEN;
        self.user_key = self
            .configured_user
            .as_ref()
            .map_or_else(|| self.session_key.clone(), |(_, key)| key.clone());
    }

    fn encode(&mut self, data: &[u8], _is_first: bool) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut rest = data;

        if !self.has_sent_header {
            let head_size = get_head_size(rest, 30);
            let first_len = rest.len().min((random_u8() as usize % 32) + head_size);
            out.extend_from_slice(&self.pack_auth_data(&rest[..first_len])?);
            rest = &rest[first_len..];
            self.has_sent_header = true;
        }

        if self.is_server && self.pack_id == 1 {
            let mut first_payload = Vec::with_capacity(rest.len() + 2);
            first_payload.extend_from_slice(&DEFAULT_TCP_MSS.to_le_bytes());
            first_payload.extend_from_slice(rest);
            rest = &[];

            self.unit_len =
                DEFAULT_TCP_MSS.saturating_sub(self.client_overhead.max(OVERHEAD)) as usize;
            out.extend_from_slice(&self.pack_server_data(&first_payload)?);
        }

        while rest.len() > self.unit_len {
            let chunk = &rest[..self.unit_len];
            if self.is_server {
                out.extend_from_slice(&self.pack_server_data(chunk)?);
            } else {
                out.extend_from_slice(&self.pack_client_data(chunk)?);
            }
            rest = &rest[self.unit_len..];
        }

        if self.is_server {
            out.extend_from_slice(&self.pack_server_data(rest)?);
        } else {
            out.extend_from_slice(&self.pack_client_data(rest)?);
        }

        Ok(out)
    }

    fn decode(&mut self, data: &[u8]) -> io::Result<Option<Vec<u8>>> {
        self.recv_buf.extend_from_slice(data);

        if self.is_server && !self.has_recv_header && self.server_decode_auth_header()?.is_none() {
            return Ok(None);
        }

        let receive_from_client = self.is_server;
        let recv_mss_prefix = !self.is_server;
        let decoded = self.decode_frames(receive_from_client, recv_mss_prefix)?;
        Ok(decoded)
    }
}
