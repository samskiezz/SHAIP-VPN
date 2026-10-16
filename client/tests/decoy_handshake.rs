//! Integration test: stand up the decoy, connect with a real rustls client that
//! trusts the decoy's generated certificate, and verify a genuine TLS 1.3
//! handshake completes and the HTTP response comes back. This proves the decoy
//! is a real TLS server, not a canned blob.

use anyhow::Result;
use pqanon::decoy::{DecoyConfig, TlsDecoy, DEFAULT_INDEX_HTML};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;

fn temp_dir() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("pqanon-decoy-test-{}", std::process::id()));
    std::fs::create_dir_all(&p).ok();
    p
}

async fn free_addr() -> std::net::SocketAddr {
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    addr
}

fn trusting_connector(cert_path: &std::path::Path) -> Result<TlsConnector> {
    let cert_pem = std::fs::read(cert_path)?;
    let mut cursor = std::io::Cursor::new(&cert_pem);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cursor).collect::<std::result::Result<Vec<_>, _>>()?;
    assert!(!certs.is_empty(), "expected a generated certificate");
    let mut roots = rustls::RootCertStore::empty();
    for c in certs {
        roots.add(c)?;
    }
    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(client_cfg)))
}

#[tokio::test]
async fn decoy_completes_handshake_and_serves_html() -> Result<()> {
    let dir = temp_dir();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    let addr = free_addr().await;
    let cfg = DecoyConfig {
        listen: addr,
        cert_path: cert_path.clone(),
        key_path: key_path.clone(),
        index_html: DEFAULT_INDEX_HTML.to_string(),
        log_probes: false,
        handshake_timeout: Duration::from_secs(5),
    };
    let decoy = TlsDecoy::new(cfg)?;
    let cert_fp = decoy.cert_fingerprint().to_string();
    assert!(!cert_fp.is_empty());

    let server = tokio::spawn(async move { decoy.run().await });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let connector = trusting_connector(&cert_path)?;
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let domain = ServerName::try_from("localhost")?.to_owned();
    let mut tls = connector.connect(domain, tcp).await?;

    // Confirm the negotiated version is TLS 1.3.
    {
        let (_, session) = tls.get_ref();
        assert_eq!(
            session.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3),
            "decoy must negotiate TLS 1.3"
        );
    }

    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await?;
    tls.flush().await?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await?;
    let resp = String::from_utf8_lossy(&buf);

    assert!(resp.starts_with("HTTP/1.1 200 OK"), "response: {resp}");
    assert!(resp.contains("It works!"), "body missing: {resp}");
    assert!(resp.contains("Content-Type: text/html"));

    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::test]
async fn decoy_returns_404_for_unknown_path() -> Result<()> {
    let dir = temp_dir();
    let cert_path = dir.join("cert2.pem");
    let key_path = dir.join("key2.pem");
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    let addr = free_addr().await;
    let cfg = DecoyConfig {
        listen: addr,
        cert_path: cert_path.clone(),
        key_path: key_path.clone(),
        index_html: DEFAULT_INDEX_HTML.to_string(),
        log_probes: false,
        handshake_timeout: Duration::from_secs(5),
    };
    let decoy = TlsDecoy::new(cfg)?;
    let server = tokio::spawn(async move { decoy.run().await });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let connector = trusting_connector(&cert_path)?;
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let domain = ServerName::try_from("localhost")?.to_owned();
    let mut tls = connector.connect(domain, tcp).await?;
    tls.write_all(b"GET /nope HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await?;
    tls.flush().await?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await?;
    let resp = String::from_utf8_lossy(&buf);
    assert!(resp.starts_with("HTTP/1.1 404"), "response: {resp}");

    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
