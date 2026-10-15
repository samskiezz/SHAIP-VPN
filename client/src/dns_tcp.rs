//! DNS-over-TCP fallback for truncated responses (RFC 1035 §4.2.2): the
//! message is length-prefixed with a 2-byte big-endian length.

use anyhow::Result;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn query_via_tcp(server: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let mut s = TcpStream::connect(server).await?;
    s.write_all(&(query.len() as u16).to_be_bytes()).await?;
    s.write_all(query).await?;
    s.flush().await?;

    let mut len_buf = [0u8; 2];
    s.read_exact(&mut len_buf).await?;
    let n = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; n];
    s.read_exact(&mut resp).await?;
    Ok(resp)
}
