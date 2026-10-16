//! DNS forwarder on the server's tunnel address (TUN mode).
//!
//! Clients are told to use the server's tunnel address as their resolver, so
//! every lookup travels inside the tunnel and leaves from the server, never
//! from the client's own network. This relays queries (UDP and TCP, port 53)
//! to the server's upstream resolver unchanged. It listens only on the tunnel
//! address, so it is not an open resolver.

use anyhow::{bail, Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_IN_FLIGHT: usize = 512;

/// The first nameserver in a resolv.conf.
pub fn upstream_from_resolv_conf(text: &str) -> Option<SocketAddr> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|v| v.trim().parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .next()
}

/// Bind the UDP and TCP listeners on `listen:53` (fails if the port is taken,
/// so a server never silently runs without the resolver it advertises).
pub async fn bind(listen: Ipv4Addr) -> Result<(UdpSocket, TcpListener)> {
    let addr = SocketAddr::new(IpAddr::V4(listen), 53);
    let udp = UdpSocket::bind(addr)
        .await
        .with_context(|| format!("DNS forwarder: binding UDP {addr} (use --no-dns to run without it)"))?;
    let tcp = TcpListener::bind(addr)
        .await
        .with_context(|| format!("DNS forwarder: binding TCP {addr}"))?;
    Ok((udp, tcp))
}

/// Relay queries to `upstream` until the task is dropped.
pub async fn serve(udp: UdpSocket, tcp: TcpListener, upstream: SocketAddr) -> Result<()> {
    if upstream.ip().is_unspecified() {
        bail!("DNS upstream {upstream} is not an address");
    }
    let udp = Arc::new(udp);
    let limit = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    tracing::info!(listen = %udp.local_addr()?, %upstream, "DNS forwarder up");
    let tcp_task = tokio::spawn(serve_tcp(tcp, upstream, limit.clone()));
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, client) = udp.recv_from(&mut buf).await?;
        if n < 12 {
            continue; // shorter than a DNS header
        }
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue; // overloaded: the client will retry
        };
        let query = buf[..n].to_vec();
        let udp = udp.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Ok(answer) = relay_udp(&query, upstream).await {
                let _ = udp.send_to(&answer, client).await;
            }
        });
        if tcp_task.is_finished() {
            bail!("DNS forwarder TCP listener stopped");
        }
    }
}

async fn relay_udp(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    let bind: SocketAddr = if upstream.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse()?;
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(upstream).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; 65_535];
    loop {
        let n = tokio::time::timeout(QUERY_TIMEOUT, sock.recv(&mut buf)).await??;
        // Only the answer to this query (same transaction id).
        if n >= 12 && buf[..2] == query[..2] {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

async fn serve_tcp(listener: TcpListener, upstream: SocketAddr, limit: Arc<Semaphore>) -> Result<()> {
    loop {
        let (mut client, _) = listener.accept().await?;
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            let relay = async {
                let mut up = tokio::time::timeout(QUERY_TIMEOUT, TcpStream::connect(upstream)).await??;
                tokio::io::copy_bidirectional(&mut client, &mut up).await?;
                Ok::<_, anyhow::Error>(())
            };
            let _ = tokio::time::timeout(TCP_TIMEOUT, relay).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_is_the_first_nameserver() {
        let rc = "# comment\nsearch example\nnameserver 192.0.2.53\nnameserver 192.0.2.54\n";
        assert_eq!(upstream_from_resolv_conf(rc), Some("192.0.2.53:53".parse().unwrap()));
        assert_eq!(upstream_from_resolv_conf("nameserver ::1\n"), Some("[::1]:53".parse().unwrap()));
        assert_eq!(upstream_from_resolv_conf("search x\n"), None);
    }

    #[tokio::test]
    async fn relays_a_query_and_its_answer() {
        // A stand-in upstream that answers every query with its own bytes
        // plus a marker.
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let up_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 512];
            loop {
                let (n, from) = upstream.recv_from(&mut b).await.unwrap();
                let mut answer = b[..n].to_vec();
                answer.extend_from_slice(b"answer");
                upstream.send_to(&answer, from).await.unwrap();
            }
        });
        let query = [0xAB, 0xCD, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        let answer = relay_udp(&query, up_addr).await.unwrap();
        assert_eq!(&answer[..12], &query);
        assert!(answer.ends_with(b"answer"));
    }
}
