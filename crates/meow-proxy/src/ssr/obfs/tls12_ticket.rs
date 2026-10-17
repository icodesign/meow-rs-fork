//! `tls1.2_ticket_auth` obfuscation plugin compatible with the Python
//! ShadowsocksR implementation.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;

use super::ObfsPlugin;

const TLS_VERSION: [u8; 2] = [0x03, 0x03];
const CLIENT_CIPHER_SUITES_AND_COMPRESS: &[u8] = &[
    0x00, 0x1c, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13, 0xc0, 0x0a,
    0xc0, 0x14, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0x0a, 0x01, 0x00,
];
const SERVER_HELLO_SUFFIX: &[u8] = &[0xc0, 0x2f, 0x00, 0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00];
const EXT_RENEGOTIATION_INFO: &[u8] = &[0xff, 0x01, 0x00, 0x01, 0x00];
const EXT_EXTENDED_MASTER_SECRET: &[u8] = &[0x00, 0x17, 0x00, 0x00];
const EXT_SIGNATURE_ALGORITHMS: &[u8] = &[
    0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x01, 0x06, 0x03, 0x05, 0x01, 0x05, 0x03, 0x04, 0x01,
    0x04, 0x03, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01, 0x02, 0x03,
];
const EXT_STATUS_REQUEST: &[u8] = &[0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00];
const EXT_SIGNED_CERT_TIMESTAMP: &[u8] = &[0x00, 0x12, 0x00, 0x00];
const EXT_CHANNEL_ID: &[u8] = &[0x75, 0x50, 0x00, 0x00];
const EXT_EC_POINT_FORMATS: &[u8] = &[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00];
const EXT_SUPPORTED_GROUPS: &[u8] = &[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18];
const MAX_TIME_DIFF_SECS: i64 = 60 * 60 * 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeState {
    Initial,
    PeerHelloReceived,
    Established,
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac = <Hmac<Sha1>>::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rand::rng().fill_bytes(&mut out);
    out
}

fn random_u16() -> u16 {
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

fn push_tls_record(out: &mut Vec<u8>, record_type: u8, version: [u8; 2], body: &[u8]) {
    out.push(record_type);
    out.extend_from_slice(&version);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

fn push_handshake(out: &mut Vec<u8>, handshake_type: u8, body: &[u8]) {
    out.push(handshake_type);
    out.push(((body.len() >> 16) & 0xff) as u8);
    out.push(((body.len() >> 8) & 0xff) as u8);
    out.push((body.len() & 0xff) as u8);
    out.extend_from_slice(body);
}

fn chunk_app_data(buf: &[u8]) -> Vec<u8> {
    let mut rest = buf;
    let mut out = Vec::with_capacity(buf.len() + (buf.len() / 2048 + 1) * 5);

    while rest.len() > 2048 {
        let size = ((random_u16() % 4096) + 100) as usize;
        let take = size.min(rest.len());
        push_tls_record(&mut out, 0x17, TLS_VERSION, &rest[..take]);
        rest = &rest[take..];
    }

    if !rest.is_empty() {
        push_tls_record(&mut out, 0x17, TLS_VERSION, rest);
    }

    out
}

fn pick_host(param: &str) -> String {
    let candidate = param.trim();
    if candidate.is_empty() || candidate.as_bytes().last().is_some_and(u8::is_ascii_digit) {
        return String::new();
    }

    let hosts: Vec<&str> = candidate
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .collect();
    if hosts.is_empty() {
        return String::new();
    }

    let idx = (random_u16() as usize) % hosts.len();
    hosts[idx].to_owned()
}

fn sni_extension(host: &str) -> Vec<u8> {
    let host = host.as_bytes();
    let mut server_name = Vec::with_capacity(host.len() + 9);
    server_name.extend_from_slice(&[0x00, 0x00]);
    let server_name_len = (host.len() + 3) as u16;
    server_name.extend_from_slice(&server_name_len.to_be_bytes());
    let list_len = (host.len() + 3) as u16;
    server_name.extend_from_slice(&list_len.to_be_bytes());
    server_name.push(0x00);
    server_name.extend_from_slice(&(host.len() as u16).to_be_bytes());
    server_name.extend_from_slice(host);
    server_name
}

pub struct Tls12TicketAuth {
    is_server: bool,
    key: Vec<u8>,
    obfs_param: String,
    handshake_state: HandshakeState,
    recv_buffer: Vec<u8>,
    client_id: [u8; 32],
    startup_time: u32,
    server_response_sent: bool,
}

impl Tls12TicketAuth {
    pub fn new(param: String, is_server: bool) -> Self {
        let mut client_id = [0u8; 32];
        rand::rng().fill_bytes(&mut client_id);

        Self {
            is_server,
            key: Vec::new(),
            obfs_param: param,
            handshake_state: HandshakeState::Initial,
            recv_buffer: Vec::new(),
            client_id,
            startup_time: current_unix_secs().saturating_sub(60 * 30),
            server_response_sent: false,
        }
    }

    fn pack_auth_data(&self, client_id: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..4].copy_from_slice(&current_unix_secs().to_be_bytes());
        out[4..22].copy_from_slice(&random_bytes(18));
        let verify = hmac_sha1(&[self.key.as_slice(), client_id].concat(), &out[..22]);
        out[22..32].copy_from_slice(&verify[..10]);
        out
    }

    fn build_client_hello(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&TLS_VERSION);
        body.extend_from_slice(&self.pack_auth_data(&self.client_id));
        body.push(0x20);
        body.extend_from_slice(&self.client_id);
        body.extend_from_slice(CLIENT_CIPHER_SUITES_AND_COMPRESS);

        let host = pick_host(&self.obfs_param);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(EXT_RENEGOTIATION_INFO);
        extensions.extend_from_slice(&sni_extension(&host));
        extensions.extend_from_slice(EXT_EXTENDED_MASTER_SECRET);

        let ticket = random_bytes((((random_u16() % 17) + 8) * 16) as usize);
        extensions.extend_from_slice(&[0x00, 0x23]);
        extensions.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ticket);

        extensions.extend_from_slice(EXT_SIGNATURE_ALGORITHMS);
        extensions.extend_from_slice(EXT_STATUS_REQUEST);
        extensions.extend_from_slice(EXT_SIGNED_CERT_TIMESTAMP);
        extensions.extend_from_slice(EXT_CHANNEL_ID);
        extensions.extend_from_slice(EXT_EC_POINT_FORMATS);
        extensions.extend_from_slice(EXT_SUPPORTED_GROUPS);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        push_handshake(&mut handshake, 0x01, &body);

        let mut out = Vec::new();
        push_tls_record(&mut out, 0x16, [0x03, 0x01], &handshake);
        out
    }

    fn build_client_finished(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0x14, TLS_VERSION[0], TLS_VERSION[1], 0x00, 0x01, 0x01]);

        let mut finished_record = Vec::new();
        finished_record.push(0x16);
        finished_record.extend_from_slice(&TLS_VERSION);
        finished_record.extend_from_slice(&0x0020u16.to_be_bytes());
        finished_record.extend_from_slice(&random_bytes(22));

        let mut verify_input = out.clone();
        verify_input.extend_from_slice(&finished_record);
        let verify = hmac_sha1(
            &[self.key.as_slice(), self.client_id.as_slice()].concat(),
            &verify_input,
        );
        finished_record.extend_from_slice(&verify[..10]);
        out.extend_from_slice(&finished_record);
        out
    }

    fn build_server_response(&self) -> Vec<u8> {
        let mut server_hello_body = Vec::new();
        server_hello_body.extend_from_slice(&TLS_VERSION);
        server_hello_body.extend_from_slice(&self.pack_auth_data(&self.client_id));
        server_hello_body.push(0x20);
        server_hello_body.extend_from_slice(&self.client_id);
        server_hello_body.extend_from_slice(SERVER_HELLO_SUFFIX);

        let mut handshake = Vec::new();
        push_handshake(&mut handshake, 0x02, &server_hello_body);

        let mut out = Vec::new();
        push_tls_record(&mut out, 0x16, TLS_VERSION, &handshake);

        out.extend_from_slice(&[0x14, TLS_VERSION[0], TLS_VERSION[1], 0x00, 0x01, 0x01]);

        let finished_len = if random_u32() & 1 == 0 { 32 } else { 40 };
        let mut finished_record = Vec::new();
        finished_record.push(0x16);
        finished_record.extend_from_slice(&TLS_VERSION);
        finished_record.extend_from_slice(&(finished_len as u16).to_be_bytes());
        finished_record.extend_from_slice(&random_bytes(finished_len - 10));

        let mut verify_input = out.clone();
        verify_input.extend_from_slice(&finished_record);
        let verify = hmac_sha1(
            &[self.key.as_slice(), self.client_id.as_slice()].concat(),
            &verify_input,
        );
        finished_record.extend_from_slice(&verify[..10]);
        out.extend_from_slice(&finished_record);
        out
    }

    fn parse_app_data(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut out = Vec::new();
        loop {
            if self.recv_buffer.len() < 5 {
                break;
            }
            if self.recv_buffer[0] != 0x17
                || self.recv_buffer[1] != TLS_VERSION[0]
                || self.recv_buffer[2] != TLS_VERSION[1]
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tls1.2_ticket_auth: expected TLS application data",
                ));
            }
            let len = u16::from_be_bytes([self.recv_buffer[3], self.recv_buffer[4]]) as usize;
            if self.recv_buffer.len() < len + 5 {
                break;
            }
            out.extend_from_slice(&self.recv_buffer[5..5 + len]);
            self.recv_buffer.drain(..5 + len);
        }

        if out.is_empty() {
            Ok(None)
        } else {
            Ok(Some(out))
        }
    }

    fn parse_client_hello(&mut self) -> io::Result<Option<()>> {
        if self.recv_buffer.len() < 5 {
            return Ok(None);
        }
        if self.recv_buffer[..3] != [0x16, 0x03, 0x01] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls1.2_ticket_auth: expected ClientHello",
            ));
        }

        let record_len = u16::from_be_bytes([self.recv_buffer[3], self.recv_buffer[4]]) as usize;
        if self.recv_buffer.len() < record_len + 5 {
            return Ok(None);
        }

        let record = &self.recv_buffer[5..5 + record_len];
        if record.len() < 43 || record[0] != 0x01 || record[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls1.2_ticket_auth: invalid ClientHello",
            ));
        }

        let handshake_len = u16::from_be_bytes([record[2], record[3]]) as usize;
        if handshake_len != record.len() - 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls1.2_ticket_auth: wrong ClientHello length",
            ));
        }

        if record[4..6] != TLS_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls1.2_ticket_auth: wrong TLS version",
            ));
        }

        let verify_id = &record[6..38];
        let session_id_len = record[38] as usize;
        if session_id_len < 32 || record.len() < 39 + session_id_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls1.2_ticket_auth: invalid session id",
            ));
        }
        let client_id_len = self.client_id.len();
        self.client_id
            .copy_from_slice(&record[39..39 + client_id_len]);

        let expected = hmac_sha1(
            &[self.key.as_slice(), self.client_id.as_slice()].concat(),
            &verify_id[..22],
        );
        if expected[..10] != verify_id[22..32] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls1.2_ticket_auth: verify sha1 mismatch",
            ));
        }

        let utc_time = u32::from_be_bytes(verify_id[..4].try_into().unwrap()) as i64;
        let now = current_unix_secs() as i64;
        if (now - utc_time).abs() > MAX_TIME_DIFF_SECS
            || utc_time < self.startup_time as i64 - (MAX_TIME_DIFF_SECS / 2)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls1.2_ticket_auth: timestamp out of range",
            ));
        }

        self.recv_buffer.drain(..record_len + 5);
        self.handshake_state = HandshakeState::PeerHelloReceived;
        Ok(Some(()))
    }

    fn parse_client_finished(&mut self) -> io::Result<Option<()>> {
        if self.recv_buffer.len() < 11 {
            return Ok(None);
        }
        if self.recv_buffer[..6] != [0x14, TLS_VERSION[0], TLS_VERSION[1], 0x00, 0x01, 0x01] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls1.2_ticket_auth: expected ChangeCipherSpec",
            ));
        }
        if self.recv_buffer[6] != 0x16
            || self.recv_buffer[7] != TLS_VERSION[0]
            || self.recv_buffer[8] != TLS_VERSION[1]
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls1.2_ticket_auth: expected Finished",
            ));
        }

        let finished_len = u16::from_be_bytes([self.recv_buffer[9], self.recv_buffer[10]]) as usize;
        let total_len = finished_len + 11;
        if self.recv_buffer.len() < total_len {
            return Ok(None);
        }

        let expected = hmac_sha1(
            &[self.key.as_slice(), self.client_id.as_slice()].concat(),
            &self.recv_buffer[..total_len - 10],
        );
        if expected[..10] != self.recv_buffer[total_len - 10..total_len] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls1.2_ticket_auth: finished sha1 mismatch",
            ));
        }

        self.recv_buffer.drain(..total_len);
        self.handshake_state = HandshakeState::Established;
        Ok(Some(()))
    }

    fn parse_server_response(&mut self) -> io::Result<Option<()>> {
        if self.recv_buffer.len() < 43 {
            return Ok(None);
        }
        if self.recv_buffer[0] != 0x16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls1.2_ticket_auth: expected ServerHello",
            ));
        }

        let first_len = u16::from_be_bytes([self.recv_buffer[3], self.recv_buffer[4]]) as usize;
        if self.recv_buffer.len() < first_len + 5 {
            return Ok(None);
        }

        let mut offset = first_len + 5;
        while self.recv_buffer.len() >= offset + 5 && self.recv_buffer[offset] == 0x16 {
            let record_len =
                u16::from_be_bytes([self.recv_buffer[offset + 3], self.recv_buffer[offset + 4]])
                    as usize;
            if self.recv_buffer.len() < offset + 5 + record_len {
                return Ok(None);
            }
            if offset == first_len + 5 {
                offset += 5 + record_len;
                continue;
            }
            break;
        }

        if self.recv_buffer.len() < offset + 6 {
            return Ok(None);
        }
        if self.recv_buffer[offset..offset + 6]
            != [0x14, TLS_VERSION[0], TLS_VERSION[1], 0x00, 0x01, 0x01]
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls1.2_ticket_auth: expected server ChangeCipherSpec",
            ));
        }
        offset += 6;

        if self.recv_buffer.len() < offset + 5 {
            return Ok(None);
        }
        if self.recv_buffer[offset] != 0x16
            || self.recv_buffer[offset + 1] != TLS_VERSION[0]
            || self.recv_buffer[offset + 2] != TLS_VERSION[1]
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls1.2_ticket_auth: expected server Finished",
            ));
        }
        let finished_len =
            u16::from_be_bytes([self.recv_buffer[offset + 3], self.recv_buffer[offset + 4]])
                as usize;
        let response_len = offset + 5 + finished_len;
        if self.recv_buffer.len() < response_len {
            return Ok(None);
        }

        let verify = &self.recv_buffer[11..43];
        let verify_expected = hmac_sha1(
            &[self.key.as_slice(), self.client_id.as_slice()].concat(),
            &verify[..22],
        );
        if verify_expected[..10] != verify[22..32] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls1.2_ticket_auth: server verify sha1 mismatch",
            ));
        }

        let expected = hmac_sha1(
            &[self.key.as_slice(), self.client_id.as_slice()].concat(),
            &self.recv_buffer[..response_len - 10],
        );
        if expected[..10] != self.recv_buffer[response_len - 10..response_len] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls1.2_ticket_auth: server response sha1 mismatch",
            ));
        }

        self.recv_buffer.drain(..response_len);
        self.handshake_state = HandshakeState::Established;
        Ok(Some(()))
    }
}

impl ObfsPlugin for Tls12TicketAuth {
    fn set_iv(&mut self, _iv: &[u8], key: &[u8]) {
        self.key = key.to_vec();
    }

    fn encode(&mut self, data: &[u8], is_first: bool) -> Vec<u8> {
        if is_first {
            if self.is_server {
                let mut out = Vec::new();
                if !self.server_response_sent {
                    out.extend_from_slice(&self.build_server_response());
                    self.server_response_sent = true;
                }
                out.extend_from_slice(&chunk_app_data(data));
                out
            } else {
                let mut out = self.build_client_hello();
                out.extend_from_slice(&self.build_client_finished());
                out.extend_from_slice(&chunk_app_data(data));
                self.handshake_state = HandshakeState::PeerHelloReceived;
                out
            }
        } else {
            chunk_app_data(data)
        }
    }

    fn decode(&mut self, buf: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
        self.recv_buffer.extend_from_slice(buf);
        buf.clear();

        if self.handshake_state != HandshakeState::Established {
            if self.is_server {
                if self.handshake_state == HandshakeState::Initial
                    && self.parse_client_hello()?.is_none()
                {
                    return Ok(None);
                }
                if self.handshake_state == HandshakeState::PeerHelloReceived
                    && self.parse_client_finished()?.is_none()
                {
                    return Ok(None);
                }
            } else if self.parse_server_response()?.is_none() {
                return Ok(None);
            }
        }

        self.parse_app_data()
    }
}
