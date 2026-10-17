use crate::ssr::{outbound_connect, CipherKind, ObfsKind, ProtocolKind, SsrConfig, SsrStream};
use crate::ShadowsocksAdapter;
use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use parking_lot::Mutex;
use smol_str::SmolStr;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

/// ShadowsocksR outbound adapter.
///
/// TCP is handled by meow's native SSR codec. UDP follows the SSR legacy
/// behavior: Shadowsocks UDP encryption without protocol/obfs framing.
/// Both legs go through the pluggable [`TcpDialer`](crate::dialer::TcpDialer),
/// so `dialer-proxy` chains apply.
pub struct ShadowsocksRAdapter {
    name: SmolStr,
    server: SmolStr,
    port: u16,
    addr_str: SmolStr,
    config: SsrConfig,
    udp_adapter: Option<ShadowsocksAdapter>,
    health: ProxyHealth,
    dialer: Arc<dyn crate::dialer::TcpDialer>,
}

impl ShadowsocksRAdapter {
    #[allow(
        clippy::too_many_arguments,
        reason = "mirrors the flat SSR config block: protocol/obfs + params"
    )]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "dialer is stored; Arc moved in like the other adapters"
    )]
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        cipher: &str,
        udp: bool,
        protocol: &str,
        protocol_param: Option<&str>,
        obfs: &str,
        obfs_param: Option<&str>,
        dialer: Arc<dyn crate::dialer::TcpDialer>,
    ) -> Result<Self> {
        let cipher_kind = parse_cipher(cipher)?;
        let config = SsrConfig {
            password: password.to_string(),
            cipher: cipher_kind,
            protocol: parse_protocol(protocol)?,
            protocol_param: protocol_param.unwrap_or_default().to_string(),
            obfs: parse_obfs(obfs)?,
            obfs_param: obfs_param.unwrap_or_default().to_string(),
        };
        let udp_adapter = if udp {
            Some(ShadowsocksAdapter::new(
                name,
                server,
                port,
                password,
                cipher,
                true,
                None,
                None,
                None,
                Arc::clone(&dialer),
            )?)
        } else {
            None
        };

        Ok(Self {
            name: SmolStr::from(name),
            server: SmolStr::from(server),
            port,
            addr_str: SmolStr::from(format!("{server}:{port}")),
            config,
            udp_adapter,
            health: ProxyHealth::new(),
            dialer,
        })
    }
}

fn parse_cipher(cipher: &str) -> Result<CipherKind> {
    cipher
        .parse::<CipherKind>()
        .map_err(|_| MeowError::Config(format!("unknown ssr cipher: {cipher}")))
}

fn parse_protocol(protocol: &str) -> Result<ProtocolKind> {
    ProtocolKind::from_str(protocol)
        .ok_or_else(|| MeowError::Config(format!("unknown ssr protocol: {protocol}")))
}

fn parse_obfs(obfs: &str) -> Result<ObfsKind> {
    ObfsKind::from_str(obfs).ok_or_else(|| MeowError::Config(format!("unknown ssr obfs: {obfs}")))
}

fn target_addr_bytes(metadata: &Metadata) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + 1 + metadata.host.len() + 2);
    if metadata.host.is_empty() {
        match metadata.dst_ip.ok_or_else(|| {
            MeowError::Config("ssr target requires destination IP or host".to_string())
        })? {
            IpAddr::V4(ip) => {
                out.push(0x01);
                out.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.push(0x04);
                out.extend_from_slice(&ip.octets());
            }
        }
    } else {
        let host = metadata.host.as_bytes();
        let len = u8::try_from(host.len()).map_err(|_| {
            MeowError::Config(format!("ssr target host is too long: {}", metadata.host))
        })?;
        out.push(0x03);
        out.push(len);
        out.extend_from_slice(host);
    }
    out.extend_from_slice(&metadata.dst_port.to_be_bytes());
    Ok(out)
}

async fn write_target_addr<S>(stream: &mut S, metadata: &Metadata) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let target = target_addr_bytes(metadata)?;
    stream
        .write_all(&target)
        .await
        .map_err(|e| MeowError::Proxy(format!("ssr write target addr: {e}")))?;
    Ok(())
}

struct SsrConn<S> {
    inner: Mutex<SsrStream<S>>,
}

impl<S> SsrConn<S> {
    fn new(inner: SsrStream<S>) -> Self {
        Self {
            inner: Mutex::new(inner),
        }
    }
}

impl<S> AsyncRead for SsrConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut inner = self.inner.lock();
        Pin::new(&mut *inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for SsrConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut inner = self.inner.lock();
        Pin::new(&mut *inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut inner = self.inner.lock();
        Pin::new(&mut *inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut inner = self.inner.lock();
        Pin::new(&mut *inner).poll_shutdown(cx)
    }
}

impl<S> ProxyConn for SsrConn<S> where S: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

#[async_trait]
impl ProxyAdapter for ShadowsocksRAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::ShadowsocksR
    }

    fn addr(&self) -> &str {
        &self.addr_str
    }

    fn support_udp(&self) -> bool {
        self.udp_adapter.is_some()
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let tcp = self
            .dialer
            .dial(&self.server, self.port, metadata.is_internal())
            .await
            .map_err(|e| MeowError::Proxy(format!("ssr tcp connect: {e}")))?;
        let mut stream = outbound_connect(tcp, &self.config)
            .await
            .map_err(|e| MeowError::Proxy(format!("ssr handshake: {e}")))?;
        write_target_addr(&mut stream, metadata).await?;
        Ok(Box::new(SsrConn::new(stream)))
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        let Some(adapter) = &self.udp_adapter else {
            return Err(MeowError::UdpNotSupported);
        };
        adapter.dial_udp(metadata).await
    }

    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        let mut stream = outbound_connect(stream, &self.config)
            .await
            .map_err(|e| MeowError::Proxy(format!("ssr relay handshake: {e}")))?;
        write_target_addr(&mut stream, metadata).await?;
        Ok(Box::new(SsrConn::new(stream)))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssr::inbound_accept;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{timeout, Duration};

    const TIMEOUT: Duration = Duration::from_secs(10);

    #[test]
    fn accepts_supported_protocols_and_obfs() {
        ShadowsocksRAdapter::new(
            "ssr",
            "127.0.0.1",
            8388,
            "secret",
            "aes-256-cfb",
            true,
            "auth_sha1_v4",
            None,
            "http_simple",
            Some("cdn.example.com"),
            Arc::new(crate::dialer::DirectDialer),
        )
        .expect("native SSR combo should be accepted");
    }

    #[test]
    fn rejects_unknown_protocol_obfs_or_cipher() {
        assert!(parse_protocol("unknown_protocol").is_err());
        assert!(parse_obfs("unknown_obfs").is_err());
        assert!(parse_cipher("unknown-cipher").is_err());
    }

    #[test]
    fn encodes_socks_target_addr_for_ip_and_domain() {
        let ip_meta = Metadata {
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_port: 8080,
            ..Default::default()
        };
        assert_eq!(
            target_addr_bytes(&ip_meta).expect("ip target"),
            vec![0x01, 127, 0, 0, 1, 0x1f, 0x90]
        );

        let domain_meta = Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        assert_eq!(
            target_addr_bytes(&domain_meta).expect("domain target"),
            [
                &[0x03, 11][..],
                b"example.com".as_slice(),
                &[0x01, 0xbb][..]
            ]
            .concat()
        );
    }

    #[tokio::test]
    async fn relays_tcp_with_http_obfs() {
        assert_tcp_relay("origin", None, "http_simple", Some("cdn.example.com")).await;
    }

    async fn assert_tcp_relay(
        protocol: &str,
        protocol_param: Option<&str>,
        obfs: &str,
        obfs_param: Option<&str>,
    ) {
        let (echo_addr, _echo_task) = start_tcp_echo_server().await;
        let server_cfg = SsrConfig {
            password: "secret".to_string(),
            cipher: parse_cipher("aes-256-cfb").expect("cipher"),
            protocol: parse_protocol(protocol).expect("protocol"),
            protocol_param: protocol_param.unwrap_or_default().to_string(),
            obfs: parse_obfs(obfs).expect("obfs"),
            obfs_param: obfs_param.unwrap_or_default().to_string(),
        };
        let (server_addr, _server_task) = start_ssr_server(server_cfg).await;
        let adapter = ShadowsocksRAdapter::new(
            "ssr",
            "127.0.0.1",
            server_addr.port(),
            "secret",
            "aes-256-cfb",
            false,
            protocol,
            protocol_param,
            obfs,
            obfs_param,
            Arc::new(crate::dialer::DirectDialer),
        )
        .expect("adapter");
        let metadata = Metadata {
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_port: echo_addr.port(),
            ..Default::default()
        };

        let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata))
            .await
            .expect("dial timeout")
            .expect("dial");
        timeout(TIMEOUT, conn.write_all(b"hello ssr"))
            .await
            .expect("write timeout")
            .expect("write");
        let mut buf = [0u8; 9];
        timeout(TIMEOUT, conn.read_exact(&mut buf))
            .await
            .expect("read timeout")
            .expect("read");
        assert_eq!(&buf, b"hello ssr");
    }

    async fn start_tcp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let addr = listener.local_addr().expect("echo addr");
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        });
        (addr, handle)
    }

    async fn start_ssr_server(config: SsrConfig) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ssr");
        let addr = listener.local_addr().expect("ssr addr");
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let config = config.clone();
                tokio::spawn(async move {
                    let mut ssr = inbound_accept(stream, &config).await.expect("ssr accept");
                    let target = read_socks_addr(&mut ssr).await.expect("target addr");
                    let mut upstream = TcpStream::connect(target).await.expect("connect target");
                    let _ = tokio::io::copy_bidirectional(&mut ssr, &mut upstream).await;
                });
            }
        });
        (addr, handle)
    }

    async fn read_socks_addr<S>(stream: &mut S) -> std::io::Result<SocketAddr>
    where
        S: AsyncRead + Unpin,
    {
        let mut atyp = [0u8; 1];
        stream.read_exact(&mut atyp).await?;
        let ip = match atyp[0] {
            0x01 => {
                let mut octets = [0u8; 4];
                stream.read_exact(&mut octets).await?;
                IpAddr::V4(octets.into())
            }
            0x04 => {
                let mut octets = [0u8; 16];
                stream.read_exact(&mut octets).await?;
                IpAddr::V6(octets.into())
            }
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unsupported test atyp {other:#x}"),
                ))
            }
        };
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await?;
        Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
    }
}
