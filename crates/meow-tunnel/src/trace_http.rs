use serde::{Deserialize, Serialize};

const SAMPLE_LIMIT: usize = 4096;

/// A bounded plaintext sample; never an HTTPS decryption or a complete request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequestSample {
    pub text: String,
    pub captured_bytes: usize,
    pub truncated: bool,
}

#[derive(Default)]
pub(super) struct HttpSampleBuffer {
    bytes: Vec<u8>,
    rejected: bool,
    truncated: bool,
}

impl HttpSampleBuffer {
    pub(super) fn observe(&mut self, bytes: &[u8]) {
        if self.rejected || self.bytes.len() == SAMPLE_LIMIT {
            return;
        }
        let count = bytes.len().min(SAMPLE_LIMIT - self.bytes.len());
        self.bytes.extend_from_slice(&bytes[..count]);
        self.truncated |= count < bytes.len() || self.bytes.len() == SAMPLE_LIMIT;
        const METHODS: &[&[u8]] = &[
            b"GET ",
            b"POST ",
            b"PUT ",
            b"PATCH ",
            b"DELETE ",
            b"HEAD ",
            b"OPTIONS ",
            b"CONNECT ",
            b"TRACE ",
        ];
        if !METHODS
            .iter()
            .any(|method| method.starts_with(&self.bytes) || self.bytes.starts_with(method))
        {
            self.rejected = true;
            self.bytes.clear();
        }
    }

    pub(super) fn finish(&mut self) -> Option<HttpRequestSample> {
        if self.rejected || self.bytes.is_empty() {
            return None;
        }
        let bytes = std::mem::take(&mut self.bytes);
        let text = String::from_utf8_lossy(&bytes);
        if !text
            .lines()
            .next()
            .is_some_and(|line| line.contains(" HTTP/1."))
        {
            return None;
        }
        Some(HttpRequestSample {
            text: redact_headers(&text),
            captured_bytes: bytes.len(),
            // A preview ending mid-header or mid-body cannot claim completeness.
            truncated: self.truncated || !text.ends_with("\r\n\r\n"),
        })
    }
}

fn redact_headers(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut headers = true;
    let mut sensitive = false;
    for (index, line) in text.split("\r\n").enumerate() {
        if index > 0 {
            result.push_str("\r\n");
        }
        if index == 0 {
            // Keep endpoint paths, but query values can contain arbitrary tokens.
            if let Some((prefix, rest)) = line.split_once('?') {
                result.push_str(prefix);
                result.push('?');
                if let Some((query, version)) = rest.rsplit_once(' ') {
                    for (i, part) in query.split('&').enumerate() {
                        if i > 0 {
                            result.push('&');
                        }
                        result.push_str(part.split('=').next().unwrap_or_default());
                        result.push_str("=<redacted>");
                    }
                    result.push(' ');
                    result.push_str(version);
                }
            } else {
                result.push_str(line);
            }
        } else if headers && line.is_empty() {
            headers = false;
        } else if headers {
            if line.starts_with([' ', '\t']) && sensitive {
                result.push_str(" <redacted>");
                continue;
            }
            sensitive = line.split_once(':').is_some_and(|(name, _)| {
                [
                    "authorization",
                    "proxy-authorization",
                    "cookie",
                    "set-cookie",
                    "x-api-key",
                    "api-key",
                ]
                .iter()
                .any(|key| name.eq_ignore_ascii_case(key))
            });
            if sensitive {
                result.push_str(line.split(':').next().unwrap_or_default());
                result.push_str(": <redacted>");
            } else {
                result.push_str(line);
            }
        } else {
            result.push_str(line);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_request_redacts_authentication_and_query_values() {
        let mut sample = HttpSampleBuffer::default();
        sample.observe(b"GE");
        sample.observe(b"T /app?token=secret&range=1 HTTP/1.1\r\nAuthorization: Bear");
        sample.observe(b"er secret\r\nCookie: private\r\nRange: bytes=0-10\r\n\r\n");
        let request = sample.finish().expect("HTTP sample");
        assert!(!request.text.contains("secret") && !request.text.contains("private"));
        assert!(request.text.contains("Range: bytes=0-10"));
    }

    #[test]
    fn encrypted_stream_is_not_saved() {
        let mut sample = HttpSampleBuffer::default();
        sample.observe(&[0x16, 0x03, 0x01, 0x02]);
        assert!(sample.finish().is_none());
    }

    #[test]
    fn payload_sample_is_bounded() {
        let mut sample = HttpSampleBuffer::default();
        sample.observe(b"POST / HTTP/1.1\r\n\r\n");
        sample.observe(&vec![b'x'; 20_000]);
        let request = sample.finish().expect("HTTP sample");
        assert_eq!(request.captured_bytes, SAMPLE_LIMIT);
        assert!(request.truncated);
    }
}
