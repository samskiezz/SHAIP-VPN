//! VPN test battery: fuzz/brute robustness, authenticity, stress, and isolation.
//!
//! A VPN parses hostile bytes on every packet, so the first safety property is
//! that no parser panics on *any* input, and the second is that no single-bit
//! mutation of an authenticated datagram is ever accepted. These tests brute
//! the real parsing surfaces through the public API.

use pqanon::dataplane::DataPlane;
use pqanon::handshake::{ClientHandshake, Identity, ServerHandshake};
use pqanon::obf::Obfuscator;
use pqanon::transport::{RecvWindow, Session};
use pqanon::wire::{Envelope, MsgType};
use std::collections::HashSet;

// --- deterministic, reproducible PRNG (SplitMix64) ---
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
    fn len_to(&mut self, max: usize) -> usize {
        (self.next() as usize) % (max + 1)
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.len_to(max);
        (0..n).map(|_| self.byte()).collect()
    }
}

/// Run `body` on `input`; fail with the offending input if it panics.
macro_rules! no_panic {
    ($label:expr, $input:expr, $body:expr) => {{
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body));
        if r.is_err() {
            let inp: &[u8] = $input;
            panic!(
                "PANIC in {} on {}-byte input {:02x?}",
                $label,
                inp.len(),
                &inp[..inp.len().min(48)]
            );
        }
    }};
}

const FUZZ_ITERS: usize = 60_000;

#[test]
fn fuzz_wire_open_never_panics() {
    let key = [0x42u8; 32];
    let mut rng = Rng::new(0xDEAD_BEEF);
    for _ in 0..FUZZ_ITERS {
        let input = rng.bytes(96);
        no_panic!("Envelope::open", &input, {
            let _ = Envelope::open(&input, &key);
        });
    }
    // Every exact length around the header/tag boundaries, all-0x00 and all-0xff.
    for len in 0..80usize {
        for fill in [0x00u8, 0xff] {
            let input = vec![fill; len];
            no_panic!("Envelope::open boundary", &input, {
                let _ = Envelope::open(&input, &key);
            });
        }
    }
}

#[test]
fn fuzz_from_plain_never_panics() {
    let mut rng = Rng::new(0x1234_5678);
    for _ in 0..FUZZ_ITERS {
        let input = rng.bytes(96);
        no_panic!("Envelope::from_plain", &input, {
            let _ = Envelope::from_plain(&input);
        });
    }
}

#[test]
fn fuzz_demorph_never_panics() {
    let obf = Obfuscator::new(&[7u8; 32], 1);
    let mut rng = Rng::new(0xABCD_1234);
    for _ in 0..FUZZ_ITERS {
        let input = rng.bytes(256);
        no_panic!("Obfuscator::demorph", &input, {
            let _ = obf.demorph(&input);
        });
    }
}

#[test]
fn fuzz_ipparse_never_panics() {
    let mut rng = Rng::new(0x9999_0001);
    for _ in 0..FUZZ_ITERS {
        let input = rng.bytes(64);
        no_panic!("ipparse", &input, {
            let _ = pqanon::ipparse::destination_ip(&input);
            let _ = pqanon::ipparse::source_ip(&input);
        });
    }
}

// --- authenticity: no mutation of a sealed datagram is accepted ---

#[test]
fn every_bit_flip_of_a_sealed_packet_fails_to_open() {
    let key = [0x11u8; 32];
    let env = Envelope {
        msg_type: MsgType::Data,
        epoch: 3,
        conn_id: 0xABCD_1234_5678_9009,
        seq: 7,
        payload: b"top secret payload bytes".to_vec(),
    };
    let sealed = env.seal(&key).unwrap();
    assert!(Envelope::open(&sealed, &key).is_ok(), "clean packet must open");

    // Brute every single-bit flip across the whole datagram (header AAD, ct, tag).
    for i in 0..sealed.len() {
        for bit in 0..8 {
            let mut m = sealed.clone();
            m[i] ^= 1 << bit;
            assert!(
                Envelope::open(&m, &key).is_err(),
                "AEAD accepted a flip at byte {i} bit {bit}"
            );
        }
    }
    // Every truncation fails.
    for cut in 0..sealed.len() {
        assert!(Envelope::open(&sealed[..cut], &key).is_err());
    }
    // A different key fails.
    assert!(Envelope::open(&sealed, &[0x22u8; 32]).is_err());
}

fn established_pair() -> (DataPlane, DataPlane) {
    let server_id = Identity::generate();
    let client_id = Identity::generate();
    let server_pub = server_id.public();
    let authorized = vec![client_id.identity_id()];
    let conn: u64 = 0xFEED_FACE;
    let mut c = ClientHandshake::new(client_id, server_pub, conn);
    let mut s = ServerHandshake::new(server_id, authorized, conn);
    let hello = c.client_hello([0u8; 32]).unwrap();
    s.recv_client_hello(&hello, false).unwrap();
    let sh = s.server_hello().unwrap();
    c.recv_server_hello(&sh).unwrap();
    let (fin, ce) = c.client_finish().unwrap();
    let se = s.recv_client_finish(&fin).unwrap();
    let addr = "127.0.0.1:0".parse().unwrap();
    (
        DataPlane::new(
            Session::new(ce.conn_id, ce.k_c2s, ce.k_s2c, addr, true, 1400),
            Obfuscator::new(&ce.ss_mix, 1),
        ),
        DataPlane::new(
            Session::new(se.conn_id, se.k_c2s, se.k_s2c, addr, false, 1400),
            Obfuscator::new(&se.ss_mix, 1),
        ),
    )
}

fn make_ip() -> Vec<u8> {
    let mut ip = vec![0u8; 60];
    ip[0] = 0x45;
    ip[16..20].copy_from_slice(&[10, 77, 0, 1]);
    for (i, b) in ip[20..].iter_mut().enumerate() {
        *b = i as u8;
    }
    ip
}

#[test]
fn mutations_never_forge_a_different_packet() {
    // Positive baseline: a clean datagram delivers the exact IP packet.
    {
        let (mut client, mut server) = established_pair();
        let ip = make_ip();
        let wire = client.outbound(&ip).unwrap();
        assert_eq!(server.inbound(&wire).unwrap(), Some(ip));
    }

    // Integrity: the obfuscation layer is deliberately malleable (a flip in its
    // random padding still yields the original authenticated packet), but the
    // inner AEAD guarantees no mutation ever delivers *different*, attacker-
    // chosen content — the only security-relevant property.
    let (mut client, mut server) = established_pair();
    let ip = make_ip();
    let wire = client.outbound(&ip).unwrap();
    for i in 0..wire.len() {
        let mut m = wire.clone();
        m[i] ^= 0xff;
        if let Ok(Some(p)) = server.inbound(&m) {
            assert_eq!(p, ip, "mutation at byte {i} delivered forged content");
        }
    }
}

// --- stress / load ---

#[test]
fn stress_fifty_thousand_packets_roundtrip() {
    let (mut client, mut server) = established_pair();
    let n = 50_000u32;
    let start = std::time::Instant::now();
    for i in 0..n {
        let mut ip = vec![0u8; 40];
        ip[0] = 0x45;
        ip[16..20].copy_from_slice(&[10, 77, 0, 1]);
        ip[20..24].copy_from_slice(&i.to_be_bytes());
        let wire = client.outbound(&ip).unwrap();
        let got = server.inbound(&wire).unwrap().expect("every packet delivers");
        assert_eq!(got, ip);
    }
    let secs = start.elapsed().as_secs_f64();
    eprintln!(
        "stress: {n} packets round-tripped in {secs:.2}s ({:.0} pkt/s)",
        n as f64 / secs
    );
}

// --- replay window brute ---

#[test]
fn replay_window_never_accepts_a_duplicate() {
    let mut rng = Rng::new(0x7777_7777);
    let mut w = RecvWindow::new();
    let mut accepted: HashSet<u32> = HashSet::new();
    // Adversarial sequence stream in a small range to force heavy collisions,
    // duplicates, reordering, and far jumps.
    for _ in 0..500_000 {
        let seq = (rng.next() & 0x1fff) as u32; // 0..8191
        let input = seq.to_be_bytes();
        let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| w.accept(seq)))
            .unwrap_or_else(|_| panic!("RecvWindow::accept panicked on {seq}"));
        if ok {
            assert!(
                accepted.insert(seq),
                "replay window accepted seq {seq} twice"
            );
        }
        let _ = input;
    }
}

// --- key isolation ---

#[test]
fn independent_sessions_derive_independent_keys() {
    let (c1, _s1) = session_keys();
    let (c2, _s2) = session_keys();
    assert_ne!(c1.0, c2.0, "two handshakes must not share k_c2s");
    assert_ne!(c1.1, c2.1, "two handshakes must not share k_s2c");
    assert_ne!(c1.2, c2.2, "two handshakes must not share ss_mix");

    // A packet sealed under session 1's key does not open under session 2's.
    let env = Envelope {
        msg_type: MsgType::Data,
        epoch: 1,
        conn_id: 1,
        seq: 1,
        payload: b"cross-session".to_vec(),
    };
    let sealed = env.seal(&c1.0).unwrap();
    assert!(Envelope::open(&sealed, &c1.0).is_ok());
    assert!(
        Envelope::open(&sealed, &c2.0).is_err(),
        "a datagram opened under a different session's key"
    );
}

#[allow(clippy::type_complexity)]
fn session_keys() -> (([u8; 32], [u8; 32], [u8; 32]), ([u8; 32], [u8; 32], [u8; 32])) {
    let server_id = Identity::generate();
    let client_id = Identity::generate();
    let server_pub = server_id.public();
    let authorized = vec![client_id.identity_id()];
    let conn: u64 = 42;
    let mut c = ClientHandshake::new(client_id, server_pub, conn);
    let mut s = ServerHandshake::new(server_id, authorized, conn);
    let hello = c.client_hello([0u8; 32]).unwrap();
    s.recv_client_hello(&hello, false).unwrap();
    let sh = s.server_hello().unwrap();
    c.recv_server_hello(&sh).unwrap();
    let (fin, ce) = c.client_finish().unwrap();
    let se = s.recv_client_finish(&fin).unwrap();
    (
        (ce.k_c2s, ce.k_s2c, ce.ss_mix),
        (se.k_c2s, se.k_s2c, se.ss_mix),
    )
}

// --- obfuscation roundtrip property ---

#[test]
fn obfuscation_roundtrips_for_realistic_datagram_sizes() {
    let obf = Obfuscator::new(&[0x5Au8; 32], 9);
    let mut session = pqanon::transport::Session::new(7, [3u8; 32], [4u8; 32], "127.0.0.1:9".parse().unwrap(), true, 1400);
    let mut rng = Rng::new(0x2024_1015);
    for _ in 0..20_000 {
        // Real sealed datagrams (HEADER(22) + payload + TAG(16)) across the
        // payload band a tunnel carries.
        let len = rng.len_to(1370);
        let payload: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let datagram = session.seal_data(MsgType::Data, payload).unwrap();
        let wire = obf.morph(&datagram).unwrap();
        let back = obf
            .demorph(&wire)
            .expect("demorph of our own morph must succeed");
        assert_eq!(back, datagram, "obfuscation roundtrip lost data at payload {len}");
    }
}

#[test]
fn fuzz_boot_layer_never_panics() {
    use pqanon::obf::{BootKey, Reassembly, BOOT_DATAGRAM};
    let boot = BootKey::for_server(&pqanon::handshake::Identity::generate().public());
    let mut rng = Rng::new(0x0B0F_2026);
    let mut r = Reassembly::new();
    for i in 0..FUZZ_ITERS {
        let input = rng.bytes(if i % 2 == 0 { BOOT_DATAGRAM } else { 1400 });
        no_panic!("BootKey::open", &input, {
            if let Some(f) = boot.open(&input) {
                let _ = r.push(f);
            }
        });
    }
}
