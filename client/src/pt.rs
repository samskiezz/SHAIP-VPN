//! SHAIP-PT/1 — pluggable transport: carry the tunnel inside a TLS byte stream.
//!
//! SHAIP's data plane is UDP. On a network that blocks or throttles UDP, or that
//! fingerprints VPN traffic, a pluggable transport reshapes the tunnel so a
//! censor's deep-packet inspection sees something ordinary. This transport wraps
//! the tunnel's datagrams in a TLS connection to port 443: to an observer it is
//! an HTTPS-looking TCP+TLS flow, not a UDP VPN. (The datagrams inside are
//! already SHAIP-sealed and OBF/2-shaped, so the TLS layer only changes what the
//! flow *looks* like, not what it protects.)
//!
//! The wire inside TLS is a simple length-delimited datagram stream: a 2-byte
//! big-endian length, then that many bytes, one frame per tunnel datagram. The
//! client [`connect`]s and the bridge [`accept`]s; both then move datagrams with
//! [`write_datagram`] / [`read_datagram`]. This module is the self-contained,
//! tested carrier (framing + TLS setup + a full loopback round trip); the bridge
//! daemon that relays between this carrier and a local `shaipd`, and the client
//! option that dials it instead of raw UDP, are layered on top.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// Largest datagram the 2-byte length frame can carry.
pub const MAX_DATAGRAM: usize = u16::MAX as usize;

/// Write one datagram as a length-delimited frame.
pub async fn write_datagram<W: AsyncWrite + Unpin>(w: &mut W, datagram: &[u8]) -> io::Result<()> {
    if datagram.len() > MAX_DATAGRAM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "datagram exceeds the 65535-byte frame limit",
        ));
    }
    w.write_all(&(datagram.len() as u16).to_be_bytes()).await?;
    w.write_all(datagram).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-delimited datagram frame. Returns `UnexpectedEof` cleanly when
/// the peer closes the stream between frames.
pub async fn read_datagram<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len).await?;
    let n = u16::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Build a client TLS config that trusts exactly the given root certificates
/// (e.g. the bridge's own certificate, or a public CA chain). No client auth.
pub fn client_config(roots: Vec<CertificateDer<'static>>) -> anyhow::Result<Arc<ClientConfig>> {
    let mut store = RootCertStore::empty();
    for cert in roots {
        store
            .add(cert)
            .map_err(|e| anyhow::anyhow!("add root certificate: {e}"))?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Build a bridge (server) TLS config from a certificate chain and private key.
pub fn server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<Arc<ServerConfig>> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| anyhow::anyhow!("build server TLS config: {e}"))?;
    Ok(Arc::new(config))
}

/// Dial the bridge: open TCP, complete the TLS handshake, and return the stream
/// the tunnel's datagrams ride over. `server_name` is the SNI/hostname presented
/// (choose one that blends in with ordinary HTTPS to that host).
pub async fn connect(
    addr: std::net::SocketAddr,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|e| anyhow::anyhow!("invalid server name {server_name:?}: {e}"))?;
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true).ok();
    let tls = TlsConnector::from(config).connect(name, tcp).await?;
    Ok(tls)
}

/// Accept one inbound bridge connection and complete its TLS handshake.
pub async fn accept(
    acceptor: &TlsAcceptor,
    tcp: TcpStream,
) -> anyhow::Result<tokio_rustls::server::TlsStream<TcpStream>> {
    tcp.set_nodelay(true).ok();
    let tls = acceptor.accept(tcp).await?;
    Ok(tls)
}

/// The RFC 6455 WebSocket GUID, used to derive `Sec-WebSocket-Accept`.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn ws_accept(key: &str) -> String {
    use base64::Engine;
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

/// Read HTTP headers (up to the blank line) from a stream, bounded.
async fn read_http_head<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<String> {
    let mut buf = Vec::new();
    let mut one = [0u8; 1];
    loop {
        let n = s.read(&mut one).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in HTTP head"));
        }
        buf.push(one[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP head too large"));
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Client side of the WebSocket (RFC 6455) HTTP/1.1 Upgrade: makes the flow look
/// like a genuine WebSocket connection to deep-packet inspection, then hands back
/// the raw stream for the datagram framing. `host`/`path` shape the request line.
pub async fn client_http_upgrade<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    host: &str,
    path: &str,
) -> anyhow::Result<()> {
    use base64::Engine;
    let mut key_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key_bytes);
    let key = base64::engine::general_purpose::STANDARD.encode(key_bytes);
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await?;
    s.flush().await?;
    let head = read_http_head(s).await?;
    let first = head.lines().next().unwrap_or("");
    if !first.starts_with("HTTP/1.1 101") {
        anyhow::bail!("bridge did not accept the WebSocket upgrade: {first:?}");
    }
    // Verify the server proved it spoke WebSocket (defeats a naive echo).
    let want = ws_accept(&key);
    let ok = head.lines().any(|l| {
        let l = l.trim();
        l.len() > 22
            && l[..22].eq_ignore_ascii_case("sec-websocket-accept: ")
            && l[22..].trim() == want
    });
    if !ok {
        anyhow::bail!("bridge returned a bad Sec-WebSocket-Accept");
    }
    Ok(())
}

/// Bridge side of the WebSocket Upgrade: read the client's request, answer
/// `101 Switching Protocols` with the correct `Sec-WebSocket-Accept`, then hand
/// back the raw stream for datagram framing.
pub async fn server_http_upgrade<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> anyhow::Result<()> {
    let head = read_http_head(s).await?;
    let key = head
        .lines()
        .find_map(|l| {
            let l = l.trim();
            (l.len() > 19 && l[..19].eq_ignore_ascii_case("sec-websocket-key: "))
                .then(|| l[19..].trim().to_string())
        })
        .ok_or_else(|| anyhow::anyhow!("no Sec-WebSocket-Key in upgrade request"))?;
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        ws_accept(&key)
    );
    s.write_all(resp.as_bytes()).await?;
    s.flush().await?;
    Ok(())
}

fn unspecified_for(addr: SocketAddr) -> SocketAddr {
    if addr.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    }
}

/// Bridge side: relay one accepted TLS connection to/from an upstream `shaipd`
/// UDP address. Framed datagrams read from the client over TLS are sent as UDP
/// datagrams to `upstream`; UDP replies are framed back over TLS. Returns when
/// either direction closes. One upstream UDP socket per connection, so `shaipd`
/// distinguishes clients by source port exactly as with direct UDP.
pub async fn bridge_connection(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    upstream: SocketAddr,
) -> anyhow::Result<()> {
    let mut tls = tls;
    // Complete the WebSocket upgrade so the flow looks like real HTTPS+WS.
    server_http_upgrade(&mut tls).await?;
    let udp = UdpSocket::bind(unspecified_for(upstream)).await?;
    udp.connect(upstream).await?;
    let udp = Arc::new(udp);
    let (mut rd, mut wr) = tokio::io::split(tls);

    // client (TLS) -> upstream (UDP)
    let mut up = {
        let udp = udp.clone();
        tokio::spawn(async move {
            while let Ok(d) = read_datagram(&mut rd).await {
                if udp.send(&d).await.is_err() {
                    break;
                }
            }
        })
    };
    // upstream (UDP) -> client (TLS)
    let mut down = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            match udp.recv(&mut buf).await {
                Ok(n) => {
                    if write_datagram(&mut wr, &buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    tokio::select! {
        _ = &mut up => down.abort(),
        _ = &mut down => up.abort(),
    }
    Ok(())
}

/// Client side: a local pluggable-transport proxy. The SHAIP client is pointed at
/// `local` (an ordinary local UDP socket) as if it were the server; this relays
/// its datagrams over a TLS connection to the bridge and back, so to the network
/// the client's traffic is an HTTPS-looking TLS flow. One SHAIP client per proxy
/// instance (it learns that client's address from its first datagram).
pub async fn pt_client(
    local: Arc<UdpSocket>,
    bridge: SocketAddr,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> anyhow::Result<()> {
    let mut tls = connect(bridge, server_name, config).await?;
    // Present a WebSocket upgrade so the carrier looks like ordinary HTTPS+WS.
    client_http_upgrade(&mut tls, server_name, "/").await?;
    let (mut rd, mut wr) = tokio::io::split(tls);
    let peer: Arc<tokio::sync::Mutex<Option<SocketAddr>>> = Arc::new(tokio::sync::Mutex::new(None));

    // local client (UDP) -> bridge (TLS)
    let mut up = {
        let local = local.clone();
        let peer = peer.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                match local.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        *peer.lock().await = Some(from);
                        if write_datagram(&mut wr, &buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        })
    };
    // bridge (TLS) -> local client (UDP)
    let mut down = tokio::spawn(async move {
        while let Ok(d) = read_datagram(&mut rd).await {
            let to = *peer.lock().await;
            if let Some(to) = to {
                if local.send_to(&d, to).await.is_err() {
                    break;
                }
            }
        }
    });

    tokio::select! {
        _ = &mut up => down.abort(),
        _ = &mut down => up.abort(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn websocket_upgrade_handshake_completes() {
        let (mut client, mut server) = tokio::io::duplex(1 << 14);
        let srv = tokio::spawn(async move { server_http_upgrade(&mut server).await });
        client_http_upgrade(&mut client, "bridge.local", "/").await.unwrap();
        srv.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn framing_roundtrips_many_sizes() {
        // Frame and de-frame a run of datagrams over an in-memory duplex.
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let sizes = [0usize, 1, 20, 1370, 65535];
        let writer = tokio::spawn(async move {
            for &n in &sizes {
                let d: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
                write_datagram(&mut a, &d).await.unwrap();
            }
        });
        for &n in &sizes {
            let got = read_datagram(&mut b).await.unwrap();
            assert_eq!(got.len(), n);
            assert!(got.iter().enumerate().all(|(i, &v)| v == (i % 251) as u8));
        }
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn datagrams_survive_a_real_tls_carrier() {
        // A self-signed bridge certificate for "bridge.local".
        let ck = rcgen::generate_simple_self_signed(vec!["bridge.local".to_string()]).unwrap();
        let cert_der = CertificateDer::from(ck.cert.der().to_vec());
        let key_der =
            PrivateKeyDer::try_from(ck.key_pair.serialize_der()).expect("pkcs8 private key");

        let server_cfg = server_config(vec![cert_der.clone()], key_der).unwrap();
        let client_cfg = client_config(vec![cert_der]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(server_cfg);

        // Bridge: accept one connection and echo every datagram back.
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = accept(&acceptor, tcp).await.unwrap();
            let (mut rd, mut wr) = tokio::io::split(tls);
            loop {
                match read_datagram(&mut rd).await {
                    Ok(d) => write_datagram(&mut wr, &d).await.unwrap(),
                    Err(_) => break, // client closed
                }
            }
        });

        // Client: dial over TLS and round-trip some datagrams.
        let tls = connect(addr, "bridge.local", client_cfg).await.unwrap();
        let (mut rd, mut wr) = tokio::io::split(tls);
        for i in 0..8u8 {
            let d: Vec<u8> = (0..(40 + i as usize * 160)).map(|b| (b as u8) ^ i).collect();
            write_datagram(&mut wr, &d).await.unwrap();
            let back = read_datagram(&mut rd).await.unwrap();
            assert_eq!(back, d, "datagram {i} must survive the TLS carrier byte-identical");
        }
        drop(wr);
        drop(rd);
        let _ = server.await;
    }
}
