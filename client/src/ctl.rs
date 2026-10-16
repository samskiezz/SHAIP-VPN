//! In-session control messages, sealed and morphed exactly like DATA, so on
//! the wire they are indistinguishable from any other small packet.
//!
//! - **Keepalive.** A `Cover` envelope whose payload is a PING asks the far
//!   side for a PONG echoing the same nonce. The client pings on a timer: the
//!   PONG proves the session is alive end to end (not merely that packets
//!   leave), keeps NAT bindings open, and gives a real round-trip time. A
//!   `Cover` payload that is neither PING nor PONG is ordinary cover traffic
//!   and is ignored.
//! - **Close.** A `Close` envelope (empty payload) ends the session. The client
//!   sends it on disconnect so the server frees the session at once; the
//!   server sends it when it shuts down so clients reconnect immediately
//!   instead of waiting out the dead-peer timer.

const KA_MAGIC: &[u8; 8] = b"PQANKA01";
const KIND_PING: u8 = 1;
const KIND_PONG: u8 = 2;
const KA_LEN: usize = KA_MAGIC.len() + 1 + 8;

/// A parsed keepalive payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keepalive {
    Ping(u64),
    Pong(u64),
}

/// The payload of a PING carrying `nonce` (send it as `MsgType::Cover`).
pub fn ping(nonce: u64) -> Vec<u8> {
    encode(KIND_PING, nonce)
}

/// The payload of the PONG answering a PING with `nonce`.
pub fn pong(nonce: u64) -> Vec<u8> {
    encode(KIND_PONG, nonce)
}

/// Parse a `Cover` payload. `None` means plain cover traffic.
pub fn parse(payload: &[u8]) -> Option<Keepalive> {
    if payload.len() != KA_LEN || &payload[..8] != KA_MAGIC {
        return None;
    }
    let nonce = u64::from_be_bytes(payload[9..17].try_into().ok()?);
    match payload[8] {
        KIND_PING => Some(Keepalive::Ping(nonce)),
        KIND_PONG => Some(Keepalive::Pong(nonce)),
        _ => None,
    }
}

fn encode(kind: u8, nonce: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(KA_LEN);
    b.extend_from_slice(KA_MAGIC);
    b.push(kind);
    b.extend_from_slice(&nonce.to_be_bytes());
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_round_trips() {
        assert_eq!(parse(&ping(7)), Some(Keepalive::Ping(7)));
        assert_eq!(parse(&pong(u64::MAX)), Some(Keepalive::Pong(u64::MAX)));
    }

    #[test]
    fn other_payloads_are_plain_cover() {
        assert_eq!(parse(b""), None);
        assert_eq!(parse(&[0u8; 17]), None);
        let mut bad_kind = ping(1);
        bad_kind[8] = 9;
        assert_eq!(parse(&bad_kind), None);
        let mut long = ping(1);
        long.push(0);
        assert_eq!(parse(&long), None);
    }
}
