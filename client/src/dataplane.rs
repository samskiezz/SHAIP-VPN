//! The per-session data-plane pipeline (§19).
//!
//! This is the pure, platform-independent core that the TUN read/write loops
//! drive: a raw IP packet goes in, a sealed + obfuscated wire datagram comes
//! out, and the exact inverse happens on the far side. No sockets, no TUN, no
//! unsafe — just the transform — so it is fully unit-testable with real IP
//! packets, and the daemons are a thin I/O shell around it.

use crate::obf::Obfuscator;
use crate::transport::Session;
use crate::wire::MsgType;

/// Couples a directional [`Session`] (keys, sequence, replay window) with its
/// per-epoch [`Obfuscator`] to form one end of a tunnel.
pub struct DataPlane {
    session: Session,
    obf: Obfuscator,
}

impl DataPlane {
    pub fn new(session: Session, obf: Obfuscator) -> Self {
        Self { session, obf }
    }

    /// IP packet read from TUN → sealed + morphed wire datagram to send.
    pub fn outbound(&mut self, ip_packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.seal(MsgType::Data, ip_packet.to_vec())
    }

    /// Wire datagram received → IP packet to write to TUN. Returns `None` for a
    /// cover or control packet (nothing to deliver), and errors on a replayed or
    /// malformed datagram.
    pub fn inbound(&mut self, wire: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let env = self.open(wire)?;
        match env.msg_type {
            MsgType::Data => Ok(Some(env.payload)),
            _ => Ok(None), // cover / control: not delivered to the TUN device
        }
    }

    /// Seal + morph a message of any type (control messages such as the
    /// session ACK travel exactly like DATA).
    pub fn seal(&mut self, msg_type: MsgType, payload: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let sealed = self.session.seal_data(msg_type, payload)?;
        Ok(self.obf.morph(&sealed))
    }

    /// Demorph + open a datagram of any type.
    pub fn open(&mut self, wire: &[u8]) -> anyhow::Result<crate::wire::Envelope> {
        let sealed = self.obf.demorph(wire)?;
        self.session.open_data(&sealed)
    }

    /// The peer's current UDP address (where outbound datagrams go).
    pub fn peer_addr(&self) -> std::net::SocketAddr {
        self.session.peer_addr
    }

    /// The last sequence number this side sealed (how much of the key's
    /// nonce space is used).
    pub fn tx_seq(&self) -> u32 {
        self.session.next_seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{ClientHandshake, Identity, ServerHandshake};

    /// Run a full handshake and return a wired client/server DataPlane pair.
    fn established_pair() -> (DataPlane, DataPlane) {
        let server_id = Identity::generate();
        let client_id = Identity::generate();
        let server_pub = server_id.public();
        let authorized = vec![client_id.identity_id()];
        let conn: u64 = 0x1234_5678;

        let mut c = ClientHandshake::new(client_id, server_pub, conn);
        let mut s = ServerHandshake::new(server_id, authorized, conn);
        let hello = c.client_hello([0u8; 32]).unwrap();
        s.recv_client_hello(&hello, false).unwrap();
        let sh = s.server_hello().unwrap();
        c.recv_server_hello(&sh).unwrap();
        let (fin, ce) = c.client_finish().unwrap();
        let se = s.recv_client_finish(&fin).unwrap();

        let addr = "127.0.0.1:0".parse().unwrap();
        let cs = Session::new(ce.conn_id, ce.k_c2s, ce.k_s2c, addr, true, 1400);
        let ss = Session::new(se.conn_id, se.k_c2s, se.k_s2c, addr, false, 1400);
        (
            DataPlane::new(cs, Obfuscator::new(&ce.ss_mix, 1)),
            DataPlane::new(ss, Obfuscator::new(&se.ss_mix, 1)),
        )
    }

    fn ipv4(dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20 + payload.len()];
        p[0] = 0x45; // IPv4, IHL 5
        p[16..20].copy_from_slice(&dst);
        p[20..].copy_from_slice(payload);
        p
    }

    #[test]
    fn real_ip_packet_roundtrips_both_ways() {
        let (mut client, mut server) = established_pair();

        // Client → server.
        let up = ipv4([10, 77, 0, 1], b"GET / HTTP/1.1");
        let wire = client.outbound(&up).unwrap();
        assert!(
            !wire.windows(4).any(|w| w == [0x50, 0x51, 0x41, 0x4e]),
            "PQAN magic must not leak onto the wire"
        );
        let delivered = server.inbound(&wire).unwrap().expect("DATA delivered");
        assert_eq!(delivered, up, "IP packet must arrive byte-identical");

        // Server → client (reply).
        let down = ipv4([10, 77, 0, 2], b"HTTP/1.1 200 OK");
        let wire2 = server.outbound(&down).unwrap();
        let delivered2 = client.inbound(&wire2).unwrap().expect("reply delivered");
        assert_eq!(delivered2, down);
    }

    #[test]
    fn replayed_datagram_is_rejected() {
        let (mut client, mut server) = established_pair();
        let wire = client.outbound(&ipv4([10, 77, 0, 1], b"x")).unwrap();
        assert!(server.inbound(&wire).unwrap().is_some());
        // The same datagram a second time is a replay.
        assert!(server.inbound(&wire).is_err());
    }
}
