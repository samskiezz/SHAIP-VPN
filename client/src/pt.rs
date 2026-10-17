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
    let tls = connect(bridge, server_name, config).await?;
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
