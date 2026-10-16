//! Live TLS 1.3 decoy (§10.2 anti-probing).
//!
//! A prober that scans the host's TCP port completes a genuine TLS handshake
//! against a genuine certificate and is served a genuine web page, while the
//! PQANON service lives on the UDP port, where every datagram is random bytes
//! to anyone without the server's keys and anything the server can't open gets
//! no answer at all (`obf.rs`, PQANON-OBF/2). Canned answers on the UDP port
//! would be worse than silence: no real HTTPS server replies to stray UDP with
//! a TLS record, so the reply itself would mark the host.
//!
//! No crypto is hand-rolled: rustls (ring provider) does the TLS, rcgen mints a
//! self-signed certificate on first run, and rustls-pemfile loads a real
//! certificate (Let's Encrypt, etc.) when one is provided.

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// The page served at `/` when no custom one is configured — an ordinary,
/// unremarkable "it works" page, the kind a default web server ships.
pub const DEFAULT_INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>It works!</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 48rem; margin: 4rem auto; padding: 0 1rem; color: #222; }
    h1 { font-weight: 500; }
    code { background: #f4f4f4; padding: 0.1rem 0.3rem; border-radius: 3px; }
  </style>
</head>
<body>
  <h1>It works!</h1>
  <p>This server is running normally.</p>
  <p><code>GET /</code> returned this page over TLS.</p>
</body>
</html>
"#;

/// Decoy configuration.
///
/// There is no option to log visitors. Anyone may connect to the decoy, a
/// customer whose network blocks UDP included, so it never records who
/// connected, the name or path they asked for, or when; a completed handshake
/// only advances the `pqanon_server_decoy_probes_total` counter.
pub struct DecoyConfig {
    pub listen: std::net::SocketAddr,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub index_html: String,
    pub handshake_timeout: Duration,
}

impl Default for DecoyConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:443".parse().unwrap(),
            cert_path: PathBuf::from("/etc/pqanon/decoy/cert.pem"),
            key_path: PathBuf::from("/etc/pqanon/decoy/key.pem"),
            index_html: DEFAULT_INDEX_HTML.to_string(),
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

/// A running (or runnable) TLS decoy server.
pub struct TlsDecoy {
    acceptor: TlsAcceptor,
    config: DecoyConfig,
    cert_fingerprint: String,
}

impl TlsDecoy {
    /// Build a decoy. If the cert/key files are absent, a self-signed
    /// certificate is generated and persisted so it is stable across restarts.
    pub fn new(config: DecoyConfig) -> Result<Self> {
        let (cert_der, key_der) = load_or_generate(&config.cert_path, &config.key_path)?;

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .context("build rustls server config")?;

        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(cert_der.as_ref());
        let fp = hex::encode(&h.finalize()[..16]);

        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(server_config)),
            config,
            cert_fingerprint: fp,
        })
    }

    pub fn cert_fingerprint(&self) -> &str {
        &self.cert_fingerprint
    }

    pub fn local_config(&self) -> &DecoyConfig {
        &self.config
    }

    /// Serve until the listener fails or the task is cancelled.
    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(self.config.listen)
            .await
            .with_context(|| format!("bind decoy on {}", self.config.listen))?;
        tracing::info!(addr = %self.config.listen, cert_fp = %self.cert_fingerprint, "TLS decoy listening");

        let me = Arc::new(self);
        loop {
            // The peer's address is not kept: not logged, not stored.
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(err = %e, "decoy accept failed");
                    continue;
                }
            };
            let me = me.clone();
            tokio::spawn(async move {
                let _ = me.handle_one(stream).await;
            });
        }
    }

    async fn handle_one(&self, stream: tokio::net::TcpStream) -> Result<()> {
        let mut tls = tokio::time::timeout(self.config.handshake_timeout, self.acceptor.accept(stream))
            .await
            .map_err(|_| anyhow!("handshake timeout"))?
            .context("tls accept")?;
        crate::metrics::DECOY_PROBES.inc();

        // Read the request line (bounded).
        let mut req_buf = vec![0u8; 8192];
        let n = match tokio::time::timeout(Duration::from_secs(3), tls.read(&mut req_buf)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };
        let request_line = if n > 0 {
            let slice = &req_buf[..n];
            let end = slice.iter().position(|&b| b == b'\n').unwrap_or(slice.len().min(120));
            String::from_utf8_lossy(&slice[..end]).trim().to_string()
        } else {
            String::new()
        };
        // Respond like an ordinary static server.
        let path = parse_path(&request_line);
        let (status, content_type, body): (&str, &str, Vec<u8>) = match path.as_str() {
            "/" | "/index.html" => ("200 OK", "text/html; charset=utf-8", self.config.index_html.as_bytes().to_vec()),
            "/robots.txt" => ("200 OK", "text/plain; charset=utf-8", b"User-agent: *\nDisallow: /\n".to_vec()),
            "/favicon.ico" => ("204 No Content", "image/x-icon", Vec::new()),
            _ => ("404 Not Found", "text/html; charset=utf-8", b"<!doctype html><title>404</title><h1>Not Found</h1>".to_vec()),
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nServer: nginx\r\n\r\n",
            body.len()
        );
        tls.write_all(response.as_bytes()).await?;
        if !body.is_empty() {
            tls.write_all(&body).await?;
        }
        let _ = tls.flush().await;
        let _ = tls.shutdown().await;
        Ok(())
    }
}

fn parse_path(request_line: &str) -> String {
    let mut parts = request_line.split_whitespace();
    let _method = parts.next();
    parts.next().unwrap_or("/").to_string()
}

fn load_or_generate(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read(cert_path).with_context(|| format!("read {}", cert_path.display()))?;
        let key_pem = std::fs::read(key_path).with_context(|| format!("read {}", key_path.display()))?;
        let certs = parse_certs(&cert_pem)?;
        let key = parse_key(&key_pem)?;
        tracing::info!(cert = %cert_path.display(), chains = certs.len(), "loaded decoy certificate");
        return Ok((
            certs.into_iter().next().ok_or_else(|| anyhow!("no certs in file"))?,
            key,
        ));
    }

    tracing::info!("generating self-signed decoy certificate");
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("rcgen self-signed")?;
    let cert_der = ck.cert.der().clone();
    let key_der = ck.key_pair.serialize_der();

    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(cert_path, pem_encode("CERTIFICATE", cert_der.as_ref()))
        .with_context(|| format!("write {}", cert_path.display()))?;
    std::fs::write(key_path, pem_encode("PRIVATE KEY", &key_der))
        .with_context(|| format!("write {}", key_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
    }
    tracing::info!(cert = %cert_path.display(), key = %key_path.display(), "wrote self-signed decoy certificate");

    let pk = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    Ok((cert_der, pk))
}

fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut cursor = std::io::Cursor::new(pem);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse cert PEM")?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found"));
    }
    Ok(certs)
}

fn parse_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut cursor = std::io::Cursor::new(pem);
    rustls_pemfile::private_key(&mut cursor)
        .context("parse key PEM")?
        .ok_or_else(|| anyhow!("no private key found"))
}

fn pem_encode(label: &str, der: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::new();
    out.push_str(&format!("-----BEGIN {label}-----\n"));
    for (i, c) in b64.chars().enumerate() {
        if i > 0 && i % 64 == 0 {
            out.push('\n');
        }
        out.push(c);
    }
    out.push_str(&format!("\n-----END {label}-----\n"));
    out.into_bytes()
}
