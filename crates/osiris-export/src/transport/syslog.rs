//! Syslog exporter over UDP, TCP (RFC 6587 octet counting) and TLS.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustls::pki_types::ServerName;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use super::tls::client_tls_config;
use crate::config::{Facility, SyslogConfig, SyslogFormat, SyslogTransport};
use crate::error::{ConfigError, ExportError};
use crate::exporter::{ExportOutcome, Exporter};
use crate::format::{cef, rfc5424};
use crate::record::ExportRecord;

/// Connect and write timeout for TCP/TLS (fixed; not configurable).
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum UDP payload in bytes.
const UDP_PAYLOAD_CAP: usize = 8192;

enum Conn {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl Conn {
    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Conn::Plain(s) => {
                s.write_all(buf).await?;
                s.flush().await
            }
            Conn::Tls(s) => {
                s.write_all(buf).await?;
                s.flush().await
            }
        }
    }
}

pub struct SyslogExporter {
    name: String,
    address: String,
    transport: SyslogTransport,
    format: SyslogFormat,
    facility: Facility,
    app_name: String,
    include_raw: bool,
    product_version: String,
    tls: Option<(TlsConnector, ServerName<'static>)>,
    io_timeout: Duration,
    conn: Mutex<Option<Conn>>,
}

/// Host part of `host:port` (brackets stripped from IPv6 literals).
fn host_of(address: &str) -> &str {
    let host = address.rsplit_once(':').map_or(address, |(h, _)| h);
    host.trim_start_matches('[').trim_end_matches(']')
}

/// Cut `s` to at most `cap` bytes at a UTF-8 char boundary.
fn truncate_at_boundary(s: &str, cap: usize) -> &str {
    if s.len() <= cap {
        return s;
    }
    let mut cut = cap;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    &s[..cut]
}

impl SyslogExporter {
    pub fn new(
        name: &str,
        cfg: &SyslogConfig,
        include_raw: bool,
        product_version: &str,
    ) -> Result<Self, ConfigError> {
        Self::build(name, cfg, include_raw, product_version, IO_TIMEOUT)
    }

    /// Test-only constructor with a shortened connect/write timeout.
    #[cfg(test)]
    fn new_with_timeout(
        name: &str,
        cfg: &SyslogConfig,
        include_raw: bool,
        product_version: &str,
        io_timeout: Duration,
    ) -> Result<Self, ConfigError> {
        Self::build(name, cfg, include_raw, product_version, io_timeout)
    }

    fn build(
        name: &str,
        cfg: &SyslogConfig,
        include_raw: bool,
        product_version: &str,
        io_timeout: Duration,
    ) -> Result<Self, ConfigError> {
        let tls = if cfg.transport == SyslogTransport::Tls {
            let config = client_tls_config(
                cfg.ca_file.as_deref(),
                cfg.client_cert.as_deref(),
                cfg.client_key.as_deref(),
            )
            .map_err(|e| ConfigError::new(name, e.message))?;
            let sni = cfg
                .server_name
                .clone()
                .unwrap_or_else(|| host_of(&cfg.address).to_string());
            let server_name = ServerName::try_from(sni)
                .map_err(|_| ConfigError::new(name, "invalid TLS server name"))?;
            Some((TlsConnector::from(config), server_name))
        } else {
            None
        };
        Ok(Self {
            name: name.to_string(),
            address: cfg.address.clone(),
            transport: cfg.transport,
            format: cfg.format,
            facility: cfg.facility,
            app_name: cfg.app_name.clone(),
            include_raw,
            product_version: product_version.to_string(),
            tls,
            io_timeout,
            conn: Mutex::new(None),
        })
    }

    fn render(&self, rec: &ExportRecord) -> String {
        match self.format {
            SyslogFormat::Rfc5424 => rfc5424(rec, self.facility, &self.app_name, self.include_raw),
            SyslogFormat::Cef => cef(rec, self.facility, &self.app_name, &self.product_version),
        }
    }

    fn transient(&self, what: &str, kind: impl std::fmt::Display) -> ExportError {
        ExportError::Transient(format!("syslog {what} {} failed: {kind}", self.address))
    }

    async fn export_udp(&self, msgs: &[String]) -> Result<ExportOutcome, ExportError> {
        let fail = |e: io::Error| self.transient("udp send to", e.kind());
        let addr = tokio::time::timeout(
            self.io_timeout,
            tokio::net::lookup_host(self.address.as_str()),
        )
        .await
        .map_err(|_| self.transient("udp resolve of", "timed out"))?
        .map_err(fail)?
        .next()
        .ok_or_else(|| self.transient("udp resolve of", "no address"))?;
        let bind = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind).await.map_err(fail)?;
        let mut outcome = ExportOutcome::default();
        for msg in msgs {
            let payload = truncate_at_boundary(msg, UDP_PAYLOAD_CAP);
            if payload.len() < msg.len() {
                outcome.truncated += 1;
            }
            socket
                .send_to(payload.as_bytes(), addr)
                .await
                .map_err(fail)?;
        }
        Ok(outcome)
    }

    async fn connect(&self) -> Result<Conn, ExportError> {
        let tcp = TcpStream::connect(self.address.as_str())
            .await
            .map_err(|e| self.transient("tcp connect to", e.kind()))?;
        let _ = tcp.set_nodelay(true);
        match &self.tls {
            None => Ok(Conn::Plain(tcp)),
            Some((connector, server_name)) => {
                let tls = connector
                    .connect(server_name.clone(), tcp)
                    .await
                    .map_err(|e| {
                        let reason = e
                            .get_ref()
                            .map_or_else(|| e.kind().to_string(), |inner| inner.to_string());
                        self.transient("tls handshake with", reason)
                    })?;
                Ok(Conn::Tls(Box::new(tls)))
            }
        }
    }

    async fn export_stream(&self, msgs: &[String]) -> Result<ExportOutcome, ExportError> {
        let mut payload = Vec::new();
        for m in msgs {
            payload.extend_from_slice(format!("{} ", m.len()).as_bytes());
            payload.extend_from_slice(m.as_bytes());
        }
        let mut guard = self.conn.lock().await;
        if guard.is_none() {
            let conn = tokio::time::timeout(self.io_timeout, self.connect())
                .await
                .map_err(|_| self.transient("connect to", "timed out"))??;
            *guard = Some(conn);
        }
        let conn = guard.as_mut().expect("connection just established");
        let res = tokio::time::timeout(self.io_timeout, conn.write_all(&payload)).await;
        match res {
            Ok(Ok(())) => Ok(ExportOutcome::default()),
            Ok(Err(e)) => {
                *guard = None;
                Err(self.transient("write to", e.kind()))
            }
            Err(_) => {
                *guard = None;
                Err(self.transient("write to", "timed out"))
            }
        }
    }
}

#[async_trait]
impl Exporter for SyslogExporter {
    fn name(&self) -> &str {
        &self.name
    }

    async fn export(&self, batch: &[Arc<ExportRecord>]) -> Result<ExportOutcome, ExportError> {
        let msgs: Vec<String> = batch.iter().map(|r| self.render(r)).collect();
        match self.transport {
            SyslogTransport::Udp => self.export_udp(&msgs).await,
            SyslogTransport::Tcp | SyslogTransport::Tls => self.export_stream(&msgs).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::transport::testutil::{event, event_with_exe};

    fn cfg(address: String, transport: SyslogTransport) -> SyslogConfig {
        SyslogConfig {
            address,
            transport,
            format: SyslogFormat::Rfc5424,
            facility: Facility::Local0,
            app_name: "osiris".to_string(),
            ca_file: None,
            client_cert: None,
            client_key: None,
            server_name: None,
        }
    }

    fn exporter(c: &SyslogConfig) -> SyslogExporter {
        SyslogExporter::new("syslog-test", c, false, "0.0.0-test").unwrap()
    }

    /// Parse as many `<len> <msg>` frames as `buf` holds.
    fn parse_frames(buf: &[u8]) -> (Vec<String>, usize) {
        let mut frames = Vec::new();
        let mut pos = 0;
        while let Some(sp) = buf[pos..].iter().position(|b| *b == b' ') {
            let Ok(len) = std::str::from_utf8(&buf[pos..pos + sp])
                .unwrap_or("x")
                .parse::<usize>()
            else {
                panic!("bad octet count");
            };
            let start = pos + sp + 1;
            if buf.len() < start + len {
                break;
            }
            frames.push(String::from_utf8(buf[start..start + len].to_vec()).unwrap());
            pos = start + len;
        }
        (frames, pos)
    }

    async fn read_frames<R: tokio::io::AsyncRead + Unpin>(r: &mut R, count: usize) -> Vec<String> {
        let mut buf = Vec::new();
        loop {
            let (frames, _) = parse_frames(&buf);
            if frames.len() >= count {
                return frames;
            }
            let mut chunk = [0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(5), r.read(&mut chunk))
                .await
                .expect("timed out waiting for frames")
                .unwrap();
            assert!(n > 0, "connection closed before {count} frames");
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    #[tokio::test]
    async fn udp_sends_one_datagram_per_record() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ex = exporter(&cfg(
            server.local_addr().unwrap().to_string(),
            SyslogTransport::Udp,
        ));
        let out = ex.export(&[event(1), event(2), event(3)]).await.unwrap();
        assert_eq!(out, ExportOutcome::default());
        let mut buf = vec![0u8; 65536];
        for _ in 0..3 {
            let n = server.recv(&mut buf).await.unwrap();
            let msg = std::str::from_utf8(&buf[..n]).unwrap();
            assert!(msg.starts_with("<"), "{msg}");
            assert!(msg.contains("osiris"), "{msg}");
        }
    }

    #[tokio::test]
    async fn udp_truncates_oversized_payload_at_char_boundary() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ex = exporter(&cfg(
            server.local_addr().unwrap().to_string(),
            SyslogTransport::Udp,
        ));
        let big = event_with_exe(1, &"é".repeat(9000));
        let out = ex.export(&[big, event(2)]).await.unwrap();
        assert_eq!(out.truncated, 1);
        let mut buf = vec![0u8; 65536];
        let n = server.recv(&mut buf).await.unwrap();
        assert!(n <= 8192, "{n}");
        std::str::from_utf8(&buf[..n]).expect("valid utf-8");
        let n2 = server.recv(&mut buf).await.unwrap();
        assert!(n2 < 8192);
    }

    #[tokio::test]
    async fn tcp_uses_octet_counting_framing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            read_frames(&mut s, 3).await
        });
        let ex = exporter(&cfg(addr, SyslogTransport::Tcp));
        ex.export(&[event(1), event(2)]).await.unwrap();
        ex.export(&[event(3)]).await.unwrap();
        let frames = server.await.unwrap();
        assert_eq!(frames.len(), 3);
        for f in &frames {
            assert!(f.starts_with('<') && f.contains("osiris"), "{f}");
        }
    }

    struct Pki {
        ca_pem: String,
        cert_pem: String,
        key_pem: String,
    }

    fn make_ca(cn: &str) -> (rcgen::Certificate, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, cn);
        let cert = params.self_signed(&key).unwrap();
        (cert, key)
    }

    fn make_pki(cn: &str, san: &str) -> Pki {
        let (ca, ca_key) = make_ca(cn);
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec![san.to_string()]).unwrap();
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        Pki {
            ca_pem: ca.pem(),
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }

    fn acceptor(pki: &Pki) -> TlsAcceptor {
        let certs = rustls_pemfile::certs(&mut pki.cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut pki.key_pem.as_bytes())
            .unwrap()
            .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        TlsAcceptor::from(Arc::new(config))
    }

    fn temp_file(tag: &str, contents: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "osiris-export-{tag}-{}-{}.pem",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&p, contents).unwrap();
        p
    }

    fn tls_cfg(address: String, ca: &Path) -> SyslogConfig {
        let mut c = cfg(address, SyslogTransport::Tls);
        c.ca_file = Some(ca.to_path_buf());
        c
    }

    #[tokio::test]
    async fn tls_delivers_with_a_trusted_ca() {
        let pki = make_pki("test ca", "localhost");
        let ca = temp_file("ca", &pki.ca_pem);
        let acc = acceptor(&pki);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let mut tls = acc.accept(s).await.unwrap();
            read_frames(&mut tls, 2).await
        });
        let ex = exporter(&tls_cfg(format!("localhost:{port}"), &ca));
        ex.export(&[event(1), event(2)]).await.unwrap();
        assert_eq!(server.await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn tls_with_wrong_ca_fails_with_a_reason() {
        let server_pki = make_pki("server ca", "localhost");
        let other_pki = make_pki("other ca", "localhost");
        let ca = temp_file("wrongca", &other_pki.ca_pem);
        let acc = acceptor(&server_pki);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let _ = acc.accept(s).await;
        });
        let ex = exporter(&tls_cfg(format!("localhost:{port}"), &ca));
        let err = ex.export(&[event(1)]).await.unwrap_err();
        assert!(matches!(err, ExportError::Transient(_)), "{err}");
        let msg = err.to_string();
        assert!(msg.contains("UnknownIssuer"), "{msg}");
        assert!(msg.contains(&format!("localhost:{port}")), "{msg}");
    }

    #[tokio::test]
    async fn tls_never_sends_plaintext_to_a_server_that_does_not_speak_tls() {
        // A plain TCP listener captures the raw bytes the client puts on the
        // wire; the client attempts TLS against it and must fail.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut got)).await;
            got
        });
        let pki = make_pki("test ca", "localhost");
        let ca = temp_file("plainca", &pki.ca_pem);
        let mut c = tls_cfg(format!("127.0.0.1:{port}"), &ca);
        c.server_name = Some("localhost".to_string());
        let ex = SyslogExporter::new_with_timeout(
            "syslog-test",
            &c,
            false,
            "0.0.0-test",
            Duration::from_millis(500),
        )
        .unwrap();
        let err = ex.export(&[event(1)]).await.unwrap_err();
        assert!(matches!(err, ExportError::Transient(_)), "{err}");
        let got = server.await.unwrap();
        let text = String::from_utf8_lossy(&got);
        assert!(
            !text.contains("osiris") && !text.contains("<134>1"),
            "plaintext leaked"
        );
        assert!(
            got.is_empty() || got[0] == 0x16,
            "first byte {:#x} is not a TLS handshake record",
            got[0]
        );
    }

    #[tokio::test]
    async fn tls_server_name_override_allows_ip_address() {
        let pki = make_pki("test ca", "syslog.test");
        let ca = temp_file("snca", &pki.ca_pem);
        let acc = acceptor(&pki);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let mut tls = acc.accept(s).await.unwrap();
            read_frames(&mut tls, 1).await
        });
        let mut c = tls_cfg(format!("127.0.0.1:{port}"), &ca);
        c.server_name = Some("syslog.test".to_string());
        exporter(&c).export(&[event(1)]).await.unwrap();
        assert_eq!(server.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn tcp_reconnects_after_the_listener_restarts() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ex = exporter(&cfg(addr.to_string(), SyslogTransport::Tcp));

        let (mut s, _) = {
            let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
            ex.export(&[event(1)]).await.unwrap();
            accept.await.unwrap()
        };
        assert_eq!(read_frames(&mut s, 1).await.len(), 1);
        // The destination goes down: connection and listener are gone.
        drop(s);

        // Sends into the dead connection must eventually fail (and drop it).
        let mut failed = false;
        for i in 0..50u8 {
            if ex.export(&[event(10 + i)]).await.is_err() {
                failed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(failed, "writes to a closed peer never errored");

        // The destination comes back on the same address.
        let listener = TcpListener::bind(addr).await.unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            read_frames(&mut s, 1).await
        });
        ex.export(&[event(99)]).await.unwrap();
        assert_eq!(server.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn tcp_write_to_a_reader_that_never_reads_times_out_as_transient() {
        // A listener with a tiny receive buffer that accepts and never reads.
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(1024).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = socket.local_addr().unwrap().to_string();
        let listener = socket.listen(1).unwrap();
        let _holder = tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        let ex = SyslogExporter::new_with_timeout(
            "syslog-test",
            &cfg(addr, SyslogTransport::Tcp),
            false,
            "0.0.0-test",
            Duration::from_secs(1),
        )
        .unwrap();
        let rec = event_with_exe(1, &"x".repeat(100_000));
        let batch: Vec<_> = (0..40).map(|_| rec.clone()).collect();
        // Some platforms (Windows loopback) absorb several MB before pushing
        // back, so keep sending until a write blocks.
        let started = std::time::Instant::now();
        let mut result = None;
        for _ in 0..200 {
            if let Err(e) = ex.export(&batch).await {
                result = Some(e);
                break;
            }
        }
        let err = result.expect("writes to a non-reading peer never blocked");
        assert!(matches!(err, ExportError::Transient(_)), "{err}");
        assert!(err.to_string().contains("timed out"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(60));
        // The stuck connection was dropped.
        assert!(ex.conn.lock().await.is_none());
    }
}
