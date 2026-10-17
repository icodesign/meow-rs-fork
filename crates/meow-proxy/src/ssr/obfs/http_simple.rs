//! `http_simple` obfuscation plugin.
//!
//! Wraps the first outbound packet inside a fake HTTP GET (or POST) request,
//! expects the server to reply with a fake HTTP 200 response, then sends raw
//! bytes for the rest of the connection.
//!
//! # First outbound packet wire format
//!
//! ```text
//! GET /[random_path] HTTP/1.1\r\n
//! Host: [host]\r\n
//! User-Agent: curl/7.[N].[M]\r\n
//! Accept: */*\r\n
//! Connection: keep-alive\r\n
//! \r\n
//! [cipher_iv + encrypted_data]
//! ```
//!
//! # First server response
//!
//! ```text
//! HTTP/1.1 200 OK\r\n
//! … headers …\r\n
//! \r\n
//! [cipher_iv + encrypted_data]
//! ```
//!
//! After the initial HTTP exchange both sides send raw bytes with no framing.

use std::fmt::Write as _;
use std::io;

use super::ObfsPlugin;

// ── HttpSimple ────────────────────────────────────────────────────────────────

pub struct HttpSimple {
    is_server: bool,
    /// Hostname to place in the `Host:` header (from obfs_param, or empty).
    host: String,
    /// Use POST instead of GET.
    use_post: bool,
    /// True once the HTTP response header has been consumed from the read buffer.
    response_done: bool,
    /// Partial header accumulation buffer (read side).
    header_buf: Vec<u8>,
    iv_len: usize,
}

impl HttpSimple {
    pub fn new(param: String, use_post: bool, is_server: bool) -> Self {
        Self {
            is_server,
            host: param,
            use_post,
            response_done: false,
            header_buf: Vec::new(),
            iv_len: 0,
        }
    }

    /// Generate a random User-Agent: `curl/7.N.M`.
    fn random_user_agent() -> String {
        format!(
            "curl/7.{}.{}",
            rand::random::<u8>() % 70,
            rand::random::<u8>() % 10
        )
    }

    fn random_prefix_len(&self, data_len: usize) -> usize {
        let head_size = self.iv_len + 30;
        if data_len > head_size + 64 {
            (head_size + (usize::from(rand::random::<u8>()) % 65)).min(data_len)
        } else {
            data_len
        }
    }

    fn encode_head(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len() * 3);
        for byte in data {
            let _ = write!(&mut out, "%{byte:02x}");
        }
        out
    }

    fn parse_request_head(buf: &[u8]) -> io::Result<Vec<u8>> {
        let first_line = buf.split(|&b| b == b'\n').next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "http_simple: empty request")
        })?;
        let first_line = first_line.strip_suffix(b"\r").unwrap_or(first_line);
        let mut parts = first_line.split(|&b| b == b' ');
        let _method = parts.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "http_simple: missing request method",
            )
        })?;
        let path = parts.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "http_simple: missing request path",
            )
        })?;
        let path = path.strip_prefix(b"/").unwrap_or(path);
        let mut out = Vec::new();
        let mut idx = 0usize;
        while idx + 3 <= path.len() {
            if path[idx] != b'%' {
                break;
            }
            let hex = std::str::from_utf8(&path[idx + 1..idx + 3]).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "http_simple: invalid hex path")
            })?;
            let byte = u8::from_str_radix(hex, 16).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "http_simple: invalid hex byte")
            })?;
            out.push(byte);
            idx += 3;
        }
        Ok(out)
    }
}

impl ObfsPlugin for HttpSimple {
    fn set_iv(&mut self, iv: &[u8], _key: &[u8]) {
        self.iv_len = iv.len();
    }

    fn encode(&mut self, data: &[u8], is_first: bool) -> Vec<u8> {
        if !is_first {
            return data.to_vec();
        }

        if self.is_server {
            let header = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Connection: keep-alive\r\n",
                "Content-Encoding: gzip\r\n",
                "Content-Type: text/html\r\n",
                "Server: nginx\r\n",
                "Vary: Accept-Encoding\r\n\r\n"
            );
            let mut out = Vec::with_capacity(header.len() + data.len());
            out.extend_from_slice(header.as_bytes());
            out.extend_from_slice(data);
            return out;
        }

        let method = if self.use_post { "POST" } else { "GET" };
        let split_at = self.random_prefix_len(data.len());
        let (head, body) = data.split_at(split_at);
        let path = format!("/{}", Self::encode_head(head));
        let host = if self.host.is_empty() {
            "www.bing.com".to_string()
        } else {
            // Use only the first host if a comma-separated list is provided.
            self.host
                .split(',')
                .next()
                .unwrap_or("www.bing.com")
                .trim()
                .to_string()
        };
        let ua = Self::random_user_agent();

        let mut out = Vec::new();
        let header = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"
        );
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(body);
        out
    }

    fn decode(&mut self, buf: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
        if self.response_done {
            // Steady-state: raw bytes.
            if buf.is_empty() {
                return Ok(None);
            }
            return Ok(Some(std::mem::take(buf)));
        }

        // Accumulate into header_buf until we see \r\n\r\n.
        self.header_buf.extend_from_slice(buf);
        buf.clear();

        // Search for end-of-headers marker.
        const DELIM: &[u8] = b"\r\n\r\n";
        if let Some(pos) = find_subsequence(&self.header_buf, DELIM) {
            let header = self.header_buf[..pos].to_vec();
            let body_start = pos + DELIM.len();
            let body = self.header_buf.split_off(body_start);
            self.header_buf.clear();
            self.response_done = true;

            if self.is_server {
                let mut decoded = Self::parse_request_head(&header)?;
                decoded.extend_from_slice(&body);
                if decoded.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(decoded))
                }
            } else if body.is_empty() {
                Ok(None)
            } else {
                Ok(Some(body))
            }
        } else {
            // Still waiting for the full header.
            Ok(None)
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Return the byte offset of the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
