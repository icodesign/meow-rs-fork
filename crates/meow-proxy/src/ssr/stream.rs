//! `SsrStream<S>` — async read/write wrapper implementing the full SSR stack.
//!
//! Applies the three SSR layers in the correct order:
//!
//! ```text
//! Write: data → protocol.encode → cipher.encrypt → [IV prepend on first] → obfs.encode → inner
//! Read:  inner → obfs.decode → [IV extract on first] → cipher.decrypt → protocol.decode → data
//! ```
//!
//! The cipher IV is embedded in the first obfs-encoded frame (not sent separately).
//! For `plain` obfs the IV appears as raw leading bytes.  For `http_simple` the IV
//! is the HTTP request/response body.  For `tls1.2_ticket_auth` the IV is carried
//! in the TLS session-ticket extension / Finished body.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use blowfish::Blowfish;
use cfb_mode::cipher::generic_array::GenericArray;
use cfb_mode::cipher::{KeyIvInit, StreamCipher as _};
use cfb_mode::{BufDecryptor, BufEncryptor};
use chacha20::ChaCha20Legacy;
use pin_project_lite::pin_project;
use rand::RngCore;
use salsa20::Salsa20;
use shadowsocks_crypto::v1::{openssl_bytes_to_key, Cipher as CompatCipher};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::config::{CipherKind, SsrConfig};
use super::obfs::{make_obfs, ObfsKind, ObfsPlugin};
use super::protocol::{make_protocol, ProtocolKind, ProtocolPlugin};

enum SsrWriteCipher {
    Compat(Box<CompatCipher>),
    BlowfishCfb(Box<BufEncryptor<Blowfish>>),
    Chacha20Legacy(ChaCha20Legacy),
    Salsa20(Salsa20),
}

impl SsrWriteCipher {
    fn apply(&mut self, buf: &mut [u8]) {
        match self {
            Self::Compat(cipher) => cipher.encrypt_packet(buf),
            Self::BlowfishCfb(cipher) => cipher.encrypt(buf),
            Self::Chacha20Legacy(cipher) => cipher.apply_keystream(buf),
            Self::Salsa20(cipher) => cipher.apply_keystream(buf),
        }
    }
}

enum SsrReadCipher {
    Compat(Box<CompatCipher>),
    BlowfishCfb(Box<BufDecryptor<Blowfish>>),
    Chacha20Legacy(ChaCha20Legacy),
    Salsa20(Salsa20),
}

impl SsrReadCipher {
    fn apply(&mut self, buf: &mut [u8]) {
        match self {
            Self::Compat(cipher) => {
                let _ = cipher.decrypt_packet(buf);
            }
            Self::BlowfishCfb(cipher) => cipher.decrypt(buf),
            Self::Chacha20Legacy(cipher) => cipher.apply_keystream(buf),
            Self::Salsa20(cipher) => cipher.apply_keystream(buf),
        }
    }
}

fn make_write_cipher(kind: CipherKind, session_key: &[u8], iv: &[u8]) -> SsrWriteCipher {
    match kind.compat_kind() {
        Some(kind) => SsrWriteCipher::Compat(Box::new(CompatCipher::new(kind, session_key, iv))),
        None => match kind {
            CipherKind::BF_CFB => SsrWriteCipher::BlowfishCfb(Box::new(
                BufEncryptor::<Blowfish>::new_from_slices(session_key, iv)
                    .expect("bf-cfb key and iv lengths are validated by LegacyCipherKind"),
            )),
            CipherKind::CHACHA20_LEGACY => SsrWriteCipher::Chacha20Legacy(ChaCha20Legacy::new(
                GenericArray::from_slice(session_key),
                GenericArray::from_slice(iv),
            )),
            CipherKind::SALSA20 => SsrWriteCipher::Salsa20(Salsa20::new(
                GenericArray::from_slice(session_key),
                GenericArray::from_slice(iv),
            )),
            _ => unreachable!(),
        },
    }
}

fn make_read_cipher(kind: CipherKind, session_key: &[u8], iv: &[u8]) -> SsrReadCipher {
    match kind.compat_kind() {
        Some(kind) => SsrReadCipher::Compat(Box::new(CompatCipher::new(kind, session_key, iv))),
        None => match kind {
            CipherKind::BF_CFB => SsrReadCipher::BlowfishCfb(Box::new(
                BufDecryptor::<Blowfish>::new_from_slices(session_key, iv)
                    .expect("bf-cfb key and iv lengths are validated by LegacyCipherKind"),
            )),
            CipherKind::CHACHA20_LEGACY => SsrReadCipher::Chacha20Legacy(ChaCha20Legacy::new(
                GenericArray::from_slice(session_key),
                GenericArray::from_slice(iv),
            )),
            CipherKind::SALSA20 => SsrReadCipher::Salsa20(Salsa20::new(
                GenericArray::from_slice(session_key),
                GenericArray::from_slice(iv),
            )),
            _ => unreachable!(),
        },
    }
}

fn drain_pending_write<S: AsyncWrite>(
    mut inner: Pin<&mut S>,
    cx: &mut Context<'_>,
    write_buf: &mut Vec<u8>,
    write_start: &mut usize,
    context: &'static str,
) -> Poll<io::Result<()>> {
    while *write_start < write_buf.len() {
        let pending = &write_buf[*write_start..];
        match inner.as_mut().poll_write(cx, pending) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!("SSR: write zero during {context}"),
                )))
            }
            Poll::Ready(Ok(n)) => *write_start += n,
        }
    }

    write_buf.clear();
    *write_start = 0;
    Poll::Ready(Ok(()))
}

fn fill_recv_buf<S: AsyncRead>(
    mut inner: Pin<&mut S>,
    cx: &mut Context<'_>,
    recv_buf: &mut Vec<u8>,
    capacity_hint: usize,
) -> Poll<io::Result<usize>> {
    let scratch_start = recv_buf.len();
    let capacity = capacity_hint.max(4096);
    recv_buf.resize(scratch_start + capacity, 0);

    let mut rb = ReadBuf::new(&mut recv_buf[scratch_start..]);
    match inner.as_mut().poll_read(cx, &mut rb) {
        Poll::Pending => {
            recv_buf.truncate(scratch_start);
            Poll::Pending
        }
        Poll::Ready(Err(e)) => {
            recv_buf.truncate(scratch_start);
            Poll::Ready(Err(e))
        }
        Poll::Ready(Ok(())) => {
            let n = rb.filled().len();
            recv_buf.truncate(scratch_start + n);
            Poll::Ready(Ok(n))
        }
    }
}

// ── SsrStream ─────────────────────────────────────────────────────────────────

pin_project! {
    /// A full-stack SSR duplex stream.
    ///
    /// Construct via [`outbound_connect`] (client) or [`inbound_accept`] (server).
    /// After construction the stream implements [`AsyncRead`] + [`AsyncWrite`].
    pub struct SsrStream<S> {
        #[pin]
        inner: S,

        // ── cipher parameters ─────────────────────────────────────────────────
        kind:        CipherKind,
        session_key: Vec<u8>,

        // ── write side ────────────────────────────────────────────────────────
        write_cipher:    Option<SsrWriteCipher>,
        write_buf:       Vec<u8>,   // pending outbound bytes (post-obfs), to drain
        write_start:     usize,
        write_first:     bool,      // true until first poll_write completes encode
        write_encrypted: bool,      // true once write_buf has been filled for current call
        write_iv:        Vec<u8>,   // cached write IV prepended on first write

        // ── read side ─────────────────────────────────────────────────────────
        read_cipher:  Option<SsrReadCipher>,
        recv_buf:     Vec<u8>,   // raw bytes from inner, pre-obfs
        obfs_decoded_buf: Vec<u8>, // bytes already decoded by obfs, awaiting cipher/protocol
        // Remote IV extraction state (IV arrives embedded in first obfs frame).
        iv_needed:    usize,     // > 0 until remote IV is fully received
        iv_buf:       Vec<u8>,   // accumulates IV bytes from obfs output
        plain_buf:    Vec<u8>,   // decoded data ready for the caller
        plain_start:  usize,

        // ── plugins ───────────────────────────────────────────────────────────
        protocol:         Box<dyn ProtocolPlugin>,
        protocol_passthrough: bool,
        protocol_iv_set:  bool,     // true once protocol.set_iv has been called
        obfs:             Box<dyn ObfsPlugin>,
        obfs_passthrough_first: bool,
        obfs_passthrough_after_first: bool,
        obfs_first_sent:  bool,     // true once obfs.encode(is_first=true) has been called
    }
}

// ── Constructors ──────────────────────────────────────────────────────────────

fn protocol_passthrough(kind: &ProtocolKind) -> bool {
    matches!(kind, ProtocolKind::Origin)
}

fn obfs_passthrough_first(kind: &ObfsKind) -> bool {
    matches!(kind, ObfsKind::Plain)
}

fn obfs_passthrough_after_first(kind: &ObfsKind) -> bool {
    matches!(
        kind,
        ObfsKind::Plain | ObfsKind::HttpSimple | ObfsKind::HttpPost
    )
}

/// **Client-side** SSR connection.
///
/// Generates a random cipher IV.  The IV is embedded in the first write frame
/// (not sent upfront) so obfs plugins can wrap it correctly.
pub async fn outbound_connect<S>(stream: S, cfg: &SsrConfig) -> io::Result<SsrStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let kind = cfg.cipher;
    let iv_len = kind.iv_len();
    let key_len = kind.key_len();

    // Derive session key from password.
    let mut session_key = vec![0u8; key_len.max(1)];
    if key_len > 0 {
        openssl_bytes_to_key(cfg.password.as_bytes(), &mut session_key);
    }

    // Generate random write IV.
    let mut write_iv = vec![0u8; iv_len];
    if iv_len > 0 {
        rand::rng().fill_bytes(&mut write_iv);
    }

    // Initialise write cipher.
    let write_cipher = if key_len > 0 && iv_len > 0 {
        Some(make_write_cipher(kind, &session_key, &write_iv))
    } else {
        None
    };

    // Build plugins.  The protocol is told the client's own write IV (used for
    // auth header derivation on encode).
    let mut protocol = make_protocol(
        cfg.protocol,
        &cfg.protocol_param,
        session_key.clone(),
        false,
    );
    let mut obfs = make_obfs(cfg.obfs, &cfg.obfs_param, false);
    let protocol_passthrough = protocol_passthrough(&cfg.protocol);
    let obfs_passthrough_first = obfs_passthrough_first(&cfg.obfs);
    let obfs_passthrough_after_first = obfs_passthrough_after_first(&cfg.obfs);

    protocol.set_iv(&write_iv, &session_key);
    obfs.set_iv(&write_iv, &session_key);

    Ok(SsrStream {
        inner: stream,
        kind,
        session_key,
        write_cipher,
        write_buf: Vec::new(),
        write_start: 0,
        write_first: true,
        write_encrypted: false,
        write_iv,
        read_cipher: None,
        recv_buf: Vec::new(),
        obfs_decoded_buf: Vec::new(),
        iv_needed: iv_len, // extract server IV lazily from first read
        iv_buf: Vec::new(),
        plain_buf: Vec::new(),
        plain_start: 0,
        protocol,
        protocol_passthrough,
        protocol_iv_set: true, // client already has its own IV set
        obfs,
        obfs_passthrough_first,
        obfs_passthrough_after_first,
        obfs_first_sent: false,
    })
}

/// **Server-side** SSR connection.
///
/// The client's cipher IV arrives embedded in the first obfs frame and is
/// extracted lazily during the first [`AsyncRead`].
#[cfg(test)]
pub async fn inbound_accept<S>(stream: S, cfg: &SsrConfig) -> io::Result<SsrStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let kind = cfg.cipher;
    let iv_len = kind.iv_len();
    let key_len = kind.key_len();

    let mut session_key = vec![0u8; key_len.max(1)];
    if key_len > 0 {
        openssl_bytes_to_key(cfg.password.as_bytes(), &mut session_key);
    }

    // Generate server write IV.
    let mut write_iv = vec![0u8; iv_len];
    if iv_len > 0 {
        rand::rng().fill_bytes(&mut write_iv);
    }

    let write_cipher = if key_len > 0 && iv_len > 0 {
        Some(make_write_cipher(kind, &session_key, &write_iv))
    } else {
        None
    };

    // The protocol's set_iv for the server side uses the CLIENT's cipher IV,
    // which we haven't received yet — it's deferred to poll_read.
    // For NONE-cipher (iv_len == 0) there is no IV to exchange; call set_iv
    // with an empty slice now so auth protocols are at least initialised.
    let mut protocol = make_protocol(cfg.protocol, &cfg.protocol_param, session_key.clone(), true);
    let mut obfs = make_obfs(cfg.obfs, &cfg.obfs_param, true);
    let protocol_passthrough = protocol_passthrough(&cfg.protocol);
    let obfs_passthrough_first = obfs_passthrough_first(&cfg.obfs);
    let obfs_passthrough_after_first = obfs_passthrough_after_first(&cfg.obfs);

    let protocol_iv_set = if iv_len == 0 {
        protocol.set_iv(&[], &session_key);
        true
    } else {
        false
    };

    // Obfs uses the server's write IV (for building server-side responses).
    obfs.set_iv(&write_iv, &session_key);

    Ok(SsrStream {
        inner: stream,
        kind,
        session_key,
        write_cipher,
        write_buf: Vec::new(),
        write_start: 0,
        write_first: true,
        write_encrypted: false,
        write_iv,
        read_cipher: None,
        recv_buf: Vec::new(),
        obfs_decoded_buf: Vec::new(),
        iv_needed: iv_len, // extract client IV lazily from first read
        iv_buf: Vec::new(),
        plain_buf: Vec::new(),
        plain_start: 0,
        protocol,
        protocol_passthrough,
        protocol_iv_set,
        obfs,
        obfs_passthrough_first,
        obfs_passthrough_after_first,
        obfs_first_sent: false,
    })
}

// ── AsyncWrite ────────────────────────────────────────────────────────────────

impl<S: AsyncRead + AsyncWrite> AsyncWrite for SsrStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let me = self.project();
        let mut inner = me.inner;

        // Encrypt `buf` into write_buf only once per logical call.
        if !*me.write_encrypted {
            let passthrough_obfs = if *me.write_first {
                *me.obfs_passthrough_first
            } else {
                *me.obfs_passthrough_after_first
            };

            if *me.protocol_passthrough && passthrough_obfs {
                me.write_buf.clear();
                me.write_buf.reserve(me.write_iv.len() + buf.len());

                if *me.write_first {
                    me.write_buf.extend_from_slice(me.write_iv);
                }

                let payload_start = me.write_buf.len();
                me.write_buf.extend_from_slice(buf);

                if let Some(cipher) = me.write_cipher.as_mut() {
                    cipher.apply(&mut me.write_buf[payload_start..]);
                }

                *me.obfs_first_sent = true;
                *me.write_first = false;
                *me.write_encrypted = true;
            } else {
                // Protocol encode.
                let proto_data = match me.protocol.encode(buf, *me.write_first) {
                    Ok(d) => d,
                    Err(e) => return Poll::Ready(Err(e)),
                };

                // Cipher encrypt in-place.
                let mut enc = proto_data;
                if let Some(cipher) = me.write_cipher.as_mut() {
                    cipher.apply(&mut enc);
                }

                // On the first write, prepend the cipher IV so the remote end can
                // extract it from the obfs-decoded bytes.
                let wire_in = if *me.write_first {
                    let mut v = me.write_iv.clone();
                    v.extend_from_slice(&enc);
                    v
                } else {
                    enc
                };

                // Obfs encode (is_first drives e.g. HTTP GET vs raw / ClientHello).
                let wire = me.obfs.encode(&wire_in, !*me.obfs_first_sent);
                *me.obfs_first_sent = true;
                *me.write_first = false;

                *me.write_buf = wire;
                *me.write_encrypted = true;
            }
        }

        match drain_pending_write(
            inner.as_mut(),
            cx,
            me.write_buf,
            me.write_start,
            "poll_write",
        ) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }

        while me.obfs.awaiting_response() {
            match fill_recv_buf(inner.as_mut(), cx, me.recv_buf, 4096) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "SSR: EOF while waiting for obfs response",
                    )))
                }
                Poll::Ready(Ok(_)) => {}
            }

            let decoded = match me.obfs.decode(me.recv_buf) {
                Ok(Some(data)) => data,
                Ok(None) => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            };

            if !decoded.is_empty() {
                me.obfs_decoded_buf.extend_from_slice(&decoded);
            }

            if let Some(pending) = me.obfs.take_pending_output() {
                *me.write_buf = pending;
                *me.write_start = 0;
                match drain_pending_write(
                    inner.as_mut(),
                    cx,
                    me.write_buf,
                    me.write_start,
                    "obfs handshake",
                ) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {}
                }
            }
        }

        if let Some(pending) = me.obfs.take_pending_output() {
            *me.write_buf = pending;
            *me.write_start = 0;
            match drain_pending_write(
                inner.as_mut(),
                cx,
                me.write_buf,
                me.write_start,
                "obfs pending write",
            ) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
        }

        *me.write_encrypted = false;

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.project();
        let mut inner = me.inner;

        match drain_pending_write(inner.as_mut(), cx, me.write_buf, me.write_start, "flush") {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }

        inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.project();
        let mut inner = me.inner;

        match drain_pending_write(inner.as_mut(), cx, me.write_buf, me.write_start, "shutdown") {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        inner.poll_shutdown(cx)
    }
}

// ── AsyncRead ─────────────────────────────────────────────────────────────────

impl<S: AsyncRead + AsyncWrite> AsyncRead for SsrStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.project();
        let mut inner = me.inner;

        loop {
            if *me.write_start < me.write_buf.len() {
                match drain_pending_write(
                    inner.as_mut(),
                    cx,
                    me.write_buf,
                    me.write_start,
                    "poll_read",
                ) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {}
                }
            }

            if let Some(pending) = me.obfs.take_pending_output() {
                *me.write_buf = pending;
                *me.write_start = 0;
                continue;
            }

            // ── 1. Return buffered plaintext to caller ────────────────────────
            if *me.plain_start < me.plain_buf.len() {
                let available = &me.plain_buf[*me.plain_start..];
                let to_copy = available.len().min(buf.remaining());
                buf.put_slice(&available[..to_copy]);
                *me.plain_start += to_copy;
                if *me.plain_start >= me.plain_buf.len() {
                    me.plain_buf.clear();
                    *me.plain_start = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // ── 2. Read more bytes from inner into recv_buf ───────────────────
            if me.obfs_decoded_buf.is_empty() {
                match fill_recv_buf(inner.as_mut(), cx, me.recv_buf, buf.remaining()) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(0)) => {
                        if me.recv_buf.is_empty() {
                            // EOF
                            return Poll::Ready(Ok(()));
                        }
                    }
                    Poll::Ready(Ok(_)) => {}
                }
            }

            if me.recv_buf.is_empty() && me.obfs_decoded_buf.is_empty() {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            // ── 3. Obfs decode ────────────────────────────────────────────────
            let mut obfs_out = if me.obfs_decoded_buf.is_empty() {
                match me.obfs.decode(me.recv_buf) {
                    Ok(Some(d)) => d,
                    Ok(None) => {
                        // Obfs needs more data.
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                }
            } else {
                std::mem::take(me.obfs_decoded_buf)
            };

            if let Some(pending) = me.obfs.take_pending_output() {
                *me.write_buf = pending;
                *me.write_start = 0;
                if obfs_out.is_empty() {
                    continue;
                }
            }

            // ── 4. Extract remote IV from the front of the first obfs frame ───
            let to_decrypt = if *me.iv_needed > 0 {
                let take = obfs_out.len().min(*me.iv_needed);
                me.iv_buf.extend_from_slice(&obfs_out[..take]);
                *me.iv_needed -= take;

                if *me.iv_needed > 0 {
                    // Still need more IV bytes; loop to read more from inner.
                    continue;
                }

                // Full remote IV received.
                let iv = std::mem::take(me.iv_buf);
                if me.kind.key_len() > 0 {
                    *me.read_cipher = Some(make_read_cipher(*me.kind, me.session_key, &iv));
                }

                // On server side, initialise the protocol with the client's IV
                // (needed for auth header verification in auth_sha1_v4, auth_aes128,
                // auth_chain_a).
                if !*me.protocol_iv_set {
                    me.protocol.set_iv(&iv, me.session_key);
                    *me.protocol_iv_set = true;
                }

                let remaining = obfs_out.split_off(take);
                if remaining.is_empty() {
                    // Got IV but no payload yet; read more.
                    continue;
                }
                remaining
            } else {
                obfs_out
            };

            // ── 5. Cipher decrypt ─────────────────────────────────────────────
            let mut dec = to_decrypt;
            if let Some(cipher) = me.read_cipher.as_mut() {
                cipher.apply(&mut dec);
            }

            // ── 6. Protocol decode ────────────────────────────────────────────
            if *me.protocol_passthrough {
                if dec.is_empty() {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                let to_copy = dec.len().min(buf.remaining());
                buf.put_slice(&dec[..to_copy]);

                if to_copy < dec.len() {
                    *me.plain_buf = dec;
                    *me.plain_start = to_copy;
                }

                return Poll::Ready(Ok(()));
            } else {
                match me.protocol.decode(&dec) {
                    Ok(Some(plain)) => {
                        *me.plain_buf = plain;
                        *me.plain_start = 0;
                        // Loop to return data to caller.
                    }
                    Ok(None) => {
                        // Protocol needs more data.
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::config::SsrConfig;
    use super::super::obfs::ObfsKind;
    use super::super::protocol::ProtocolKind;
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    async fn make_pair(
        cipher: CipherKind,
        protocol: ProtocolKind,
        obfs: ObfsKind,
    ) -> (
        SsrStream<impl AsyncRead + AsyncWrite + Unpin>,
        SsrStream<impl AsyncRead + AsyncWrite + Unpin>,
    ) {
        let cfg = SsrConfig {
            password: "test-password".into(),
            cipher,
            protocol,
            protocol_param: String::new(),
            obfs,
            obfs_param: String::new(),
        };
        let (client_raw, server_raw) = duplex(256 * 1024);
        let (client, server) = tokio::join!(
            outbound_connect(client_raw, &cfg),
            inbound_accept(server_raw, &cfg),
        );
        (client.unwrap(), server.unwrap())
    }

    #[tokio::test]
    async fn origin_plain_roundtrip() {
        let (mut client, mut server) = make_pair(
            CipherKind::AES_128_CFB128,
            ProtocolKind::Origin,
            ObfsKind::Plain,
        )
        .await;

        let msg = b"hello, SSR!";
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();

        let mut got = vec![0u8; msg.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, msg);
    }

    #[tokio::test]
    async fn origin_plain_none_cipher_roundtrip() {
        let (mut client, mut server) =
            make_pair(CipherKind::NONE, ProtocolKind::Origin, ObfsKind::Plain).await;

        let msg = b"no encryption";
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();

        let mut got = vec![0u8; msg.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, msg);
    }

    #[tokio::test]
    async fn bidirectional_origin_plain() {
        let (mut client, mut server) = make_pair(
            CipherKind::AES_128_CFB128,
            ProtocolKind::Origin,
            ObfsKind::Plain,
        )
        .await;

        // Client → Server
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut got = [0u8; 4];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");

        // Server → Client
        server.write_all(b"pong").await.unwrap();
        server.flush().await.unwrap();
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
    }

    #[tokio::test]
    async fn auth_sha1_v4_plain_roundtrip() {
        let (mut client, mut server) = make_pair(
            CipherKind::AES_128_CFB128,
            ProtocolKind::AuthSha1V4,
            ObfsKind::Plain,
        )
        .await;

        let msg = b"auth_sha1_v4 test message";
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();

        let mut got = vec![0u8; msg.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, msg);
    }

    #[tokio::test]
    async fn auth_sha1_v4_plain_roundtrip_ctr() {
        let (mut client, mut server) = make_pair(
            CipherKind::AES_128_CTR,
            ProtocolKind::AuthSha1V4,
            ObfsKind::Plain,
        )
        .await;

        let msg = b"auth_sha1_v4 ctr test message";
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();

        let mut got = vec![0u8; msg.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, msg);
    }

    #[tokio::test]
    async fn auth_aes128_sha1_plain_roundtrip() {
        let (mut client, mut server) = make_pair(
            CipherKind::AES_128_CFB128,
            ProtocolKind::AuthAes128Sha1,
            ObfsKind::Plain,
        )
        .await;

        let msg = b"auth_aes128_sha1 test message";
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();

        let mut got = vec![0u8; msg.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, msg);
    }

    #[tokio::test]
    async fn auth_aes128_md5_plain_roundtrip() {
        let (mut client, mut server) = make_pair(
            CipherKind::AES_256_CFB128,
            ProtocolKind::AuthAes128Md5,
            ObfsKind::Plain,
        )
        .await;

        let msg = b"auth_aes128_md5 roundtrip";
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();

        let mut got = vec![0u8; msg.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, msg);
    }

    #[tokio::test]
    async fn auth_chain_a_plain_roundtrip() {
        let (mut client, mut server) = make_pair(
            CipherKind::AES_128_CFB128,
            ProtocolKind::AuthChainA,
            ObfsKind::Plain,
        )
        .await;

        let msg = b"auth_chain_a test message";
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();

        let mut got = vec![0u8; msg.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, msg);
    }

    #[tokio::test]
    async fn auth_chain_b_plain_roundtrip() {
        let (mut client, mut server) = make_pair(
            CipherKind::AES_128_CFB128,
            ProtocolKind::AuthChainB,
            ObfsKind::Plain,
        )
        .await;

        let msg = b"auth_chain_b test message";
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();

        let mut got = vec![0u8; msg.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, msg);
    }

    #[tokio::test]
    async fn origin_plain_bf_cfb_roundtrip() {
        let (mut client, mut server) =
            make_pair(CipherKind::BF_CFB, ProtocolKind::Origin, ObfsKind::Plain).await;

        let msg = b"bf-cfb ssr";
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();

        let mut got = vec![0u8; msg.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, msg);
    }

    #[tokio::test]
    async fn origin_plain_chacha20_legacy_roundtrip() {
        let (mut client, mut server) = make_pair(
            CipherKind::CHACHA20_LEGACY,
            ProtocolKind::Origin,
            ObfsKind::Plain,
        )
        .await;

        let msg = b"chacha20 ssr";
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();

        let mut got = vec![0u8; msg.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, msg);
    }

    #[tokio::test]
    async fn origin_plain_salsa20_roundtrip() {
        let (mut client, mut server) =
            make_pair(CipherKind::SALSA20, ProtocolKind::Origin, ObfsKind::Plain).await;

        let msg = b"salsa20 ssr";
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();

        let mut got = vec![0u8; msg.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, msg);
    }

    #[tokio::test]
    async fn origin_http_simple_roundtrip() {
        let (mut client, mut server) = make_pair(
            CipherKind::AES_128_CFB128,
            ProtocolKind::Origin,
            ObfsKind::HttpSimple,
        )
        .await;

        let msg = b"http_simple obfs test";
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();

        let mut got = vec![0u8; msg.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, msg);
    }

    #[tokio::test]
    async fn origin_random_head_roundtrip() {
        let (mut client, mut server) = make_pair(
            CipherKind::AES_128_CFB128,
            ProtocolKind::Origin,
            ObfsKind::RandomHead,
        )
        .await;

        let msg = b"random_head obfs test";
        let (_, read_res) = tokio::join!(
            async {
                client.write_all(msg).await.unwrap();
                client.flush().await.unwrap();
            },
            async {
                let mut got = vec![0u8; msg.len()];
                server.read_exact(&mut got).await.unwrap();
                got
            }
        );

        assert_eq!(read_res, msg);
    }

    #[tokio::test]
    async fn origin_tls12_ticket_roundtrip() {
        let (mut client, mut server) = make_pair(
            CipherKind::AES_128_CFB128,
            ProtocolKind::Origin,
            ObfsKind::Tls12TicketAuth,
        )
        .await;

        let msg = b"tls12_ticket obfs test";
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();

        let mut got = vec![0u8; msg.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, msg);
    }

    #[tokio::test]
    async fn large_message_auth_aes128_sha1() {
        let (mut client, mut server) = make_pair(
            CipherKind::AES_128_CFB128,
            ProtocolKind::AuthAes128Sha1,
            ObfsKind::Plain,
        )
        .await;

        let msg: Vec<u8> = (0u8..=255).cycle().take(32 * 1024).collect();
        let (_, read_res) = tokio::join!(
            async {
                client.write_all(&msg).await.unwrap();
                client.flush().await.unwrap();
            },
            async {
                let mut got = vec![0u8; msg.len()];
                server.read_exact(&mut got).await.unwrap();
                got
            }
        );
        assert_eq!(read_res, msg);
    }
}
