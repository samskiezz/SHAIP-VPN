//! Validating stub resolver (§12.4): the piece that puts DNSSEC *in the
//! resolver*.
//!
//! The [`dnssec`](crate::dnssec) module verifies the cryptographic primitives —
//! RRSIGs, DS digests, the trust-anchor chain. This module is what actually
//! *uses* them: it sends queries with the DNSSEC-OK bit set, parses the wire
//! response, extracts the answer RRset together with its `RRSIG` and the signing
//! `DNSKEY` RRset, and runs validation against configured trust anchors before
//! handing an address back. An answer that carries signatures but fails to
//! validate is **dropped** (`Bogus`), never returned — that is the whole point
//! of validation, and the reason it has to live on the resolution path rather
//! than in a library corner.
//!
//! Scope: `A`/`AAAA` validation, which is what a VPN client's resolver needs to
//! turn a hostname into a tunnelled address. Those RDATA types contain no
//! embedded domain names, so the on-wire RDATA is already canonical (RFC 4034
//! §6.2) and verification is byte-exact. Query minimization, the TTL cache and
//! negative caching from the sibling `dns_*` modules compose in front of it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::dns_cache::DnsCache;
use crate::dnssec::{
    validate_answer, Dnskey, ResourceRecord, Rrsig, SecurityStatus,
};

/// DNS record type numbers used here.
pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_RRSIG: u16 = 46;
pub const TYPE_DNSKEY: u16 = 48;

/// The DNSSEC-OK bit in the EDNS0 OPT record's TTL field (RFC 3225).
const EDNS_DO_BIT: u32 = 0x0000_8000;

/// Errors from resolution or parsing. Validation *failure* is not an error — it
/// is a [`SecurityStatus::Bogus`] result — but a malformed packet is.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("short or malformed DNS message")]
    Malformed,
    #[error("server returned rcode {0}")]
    Rcode(u8),
    #[error("no answer of the requested type")]
    NoAnswer,
    #[error("transport error: {0}")]
    Transport(String),
}

/// A parsed resource record with its owner name lowercased to canonical form.
#[derive(Clone, Debug)]
pub struct WireRecord {
    pub name: String,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Wire parsing
// ---------------------------------------------------------------------------

/// Read a (possibly compressed) domain name starting at `off`, returning the
/// lowercased dotted name and the offset just past the name *in the record
/// stream* (following the first pointer, per RFC 1035 §4.1.4).
fn read_name(buf: &[u8], off: usize) -> Result<(String, usize), ResolveError> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = off;
    let mut advanced = off;
    let mut jumped = false;
    let mut guard = 0;
    loop {
        if pos >= buf.len() {
            return Err(ResolveError::Malformed);
        }
        let len = buf[pos] as usize;
        if len == 0 {
            if !jumped {
                advanced = pos + 1;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                return Err(ResolveError::Malformed);
            }
            if !jumped {
                advanced = pos + 2;
            }
            let ptr = ((len & 0x3F) << 8) | buf[pos + 1] as usize;
            pos = ptr;
            jumped = true;
            guard += 1;
            if guard > 128 {
                return Err(ResolveError::Malformed); // pointer loop
            }
            continue;
        }
        pos += 1;
        if pos + len > buf.len() {
            return Err(ResolveError::Malformed);
        }
        let label: String = buf[pos..pos + len]
            .iter()
            .map(|b| b.to_ascii_lowercase() as char)
            .collect();
        labels.push(label);
        pos += len;
    }
    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        format!("{}.", labels.join("."))
    };
    Ok((name, advanced))
}

/// A parsed DNS message: just the pieces validation needs.
pub struct DnsMessage {
    pub rcode: u8,
    pub answers: Vec<WireRecord>,
    pub authority: Vec<WireRecord>,
}

impl DnsMessage {
    pub fn parse(buf: &[u8]) -> Result<DnsMessage, ResolveError> {
        if buf.len() < 12 {
            return Err(ResolveError::Malformed);
        }
        let rcode = buf[3] & 0x0F;
        let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
        let ns = u16::from_be_bytes([buf[8], buf[9]]) as usize;
        let mut off = 12;
        // Questions: name + qtype(2) + qclass(2).
        for _ in 0..qd {
            let (_, next) = read_name(buf, off)?;
            off = next + 4;
        }
        let answers = Self::read_rrs(buf, &mut off, an)?;
        let authority = Self::read_rrs(buf, &mut off, ns)?;
        Ok(DnsMessage {
            rcode,
            answers,
            authority,
        })
    }

    fn read_rrs(
        buf: &[u8],
        off: &mut usize,
        count: usize,
    ) -> Result<Vec<WireRecord>, ResolveError> {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let (name, next) = read_name(buf, *off)?;
            *off = next;
            if *off + 10 > buf.len() {
                return Err(ResolveError::Malformed);
            }
            let rr_type = u16::from_be_bytes([buf[*off], buf[*off + 1]]);
            let class = u16::from_be_bytes([buf[*off + 2], buf[*off + 3]]);
            let ttl = u32::from_be_bytes([buf[*off + 4], buf[*off + 5], buf[*off + 6], buf[*off + 7]]);
            let rdlen = u16::from_be_bytes([buf[*off + 8], buf[*off + 9]]) as usize;
            *off += 10;
            if *off + rdlen > buf.len() {
                return Err(ResolveError::Malformed);
            }
            let rdata = buf[*off..*off + rdlen].to_vec();
            *off += rdlen;
            out.push(WireRecord {
                name,
                rr_type,
                class,
                ttl,
                rdata,
            });
        }
        Ok(out)
    }
}

/// Parse RRSIG RDATA (RFC 4034 §3.1). The signer name inside RRSIG RDATA is not
/// compressed, so it is read directly from the RDATA slice.
pub fn parse_rrsig(rdata: &[u8]) -> Result<Rrsig, ResolveError> {
    if rdata.len() < 18 {
        return Err(ResolveError::Malformed);
    }
    let type_covered = u16::from_be_bytes([rdata[0], rdata[1]]);
    let algorithm = rdata[2];
    let labels = rdata[3];
    let original_ttl = u32::from_be_bytes([rdata[4], rdata[5], rdata[6], rdata[7]]);
    let sig_expiration = u32::from_be_bytes([rdata[8], rdata[9], rdata[10], rdata[11]]);
    let sig_inception = u32::from_be_bytes([rdata[12], rdata[13], rdata[14], rdata[15]]);
    let key_tag = u16::from_be_bytes([rdata[16], rdata[17]]);
    // Signer name, length-labelled and uncompressed, then the signature.
    let (signer_name, consumed) = read_name(rdata, 18)?;
    if consumed > rdata.len() {
        return Err(ResolveError::Malformed);
    }
    Ok(Rrsig {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        sig_expiration,
        sig_inception,
        key_tag,
        signer_name,
        signature: rdata[consumed..].to_vec(),
    })
}

/// Select the RRSIG covering `rr_type` from a record list.
fn covering_rrsig(records: &[WireRecord], rr_type: u16) -> Option<Rrsig> {
    records
        .iter()
        .filter(|r| r.rr_type == TYPE_RRSIG)
        .filter_map(|r| parse_rrsig(&r.rdata).ok())
        .find(|s| s.type_covered == rr_type)
}

/// Extract the RRset of `rr_type` (as `dnssec::ResourceRecord`s ready to verify).
fn rrset_of(records: &[WireRecord], rr_type: u16) -> Vec<ResourceRecord> {
    records
        .iter()
        .filter(|r| r.rr_type == rr_type)
        .map(|r| ResourceRecord {
            name: r.name.clone(),
            rr_type: r.rr_type,
            class: r.class,
            ttl: r.ttl,
            rdata: r.rdata.clone(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Query building
// ---------------------------------------------------------------------------

/// Build a DNS query for `name`/`rr_type` with EDNS0 + the DNSSEC-OK bit set, so
/// the upstream returns RRSIGs.
pub fn build_query(id: u16, name: &str, rr_type: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // RD=1
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT (OPT)
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&rr_type.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // class IN
    // EDNS0 OPT: name root, type 41, UDP size 4096, TTL carries DO bit.
    q.push(0);
    q.extend_from_slice(&41u16.to_be_bytes());
    q.extend_from_slice(&4096u16.to_be_bytes());
    q.extend_from_slice(&EDNS_DO_BIT.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes()); // RDLEN 0
    q
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// A DNS transport: send a query, get a response. Abstracted so the validator is
/// testable offline and can run over UDP, the tunnel, or DoT.
pub trait DnsTransport {
    fn query(
        &self,
        packet: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, ResolveError>> + Send;
}

/// Live UDP transport (RFC 1035 §4.2.1) with a timeout.
pub struct UdpDnsTransport {
    pub server: SocketAddr,
    pub timeout: Duration,
}

impl UdpDnsTransport {
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            timeout: Duration::from_secs(3),
        }
    }
}

impl DnsTransport for UdpDnsTransport {
    async fn query(&self, packet: &[u8]) -> Result<Vec<u8>, ResolveError> {
        let bind: SocketAddr = if self.server.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let sock = tokio::net::UdpSocket::bind(bind)
            .await
            .map_err(|e| ResolveError::Transport(e.to_string()))?;
        sock.connect(self.server)
            .await
            .map_err(|e| ResolveError::Transport(e.to_string()))?;
        sock.send(packet)
            .await
            .map_err(|e| ResolveError::Transport(e.to_string()))?;
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(self.timeout, sock.recv(&mut buf))
            .await
            .map_err(|_| ResolveError::Transport("timeout".into()))?
            .map_err(|e| ResolveError::Transport(e.to_string()))?;
        buf.truncate(n);
        Ok(buf)
    }
}

// ---------------------------------------------------------------------------
// Validating resolver
// ---------------------------------------------------------------------------

/// A validated address answer and the security verdict that earned it.
#[derive(Debug, Clone)]
pub struct ValidatedAnswer {
    pub addrs: Vec<IpAddr>,
    pub security: SecurityStatus,
}

/// A validating stub resolver. It pins the trusted zone `DNSKEY`s (the keys an
/// operator ships with the client, or that were themselves validated up the
/// chain) and verifies every signed answer against them before returning it.
pub struct ValidatingResolver<T: DnsTransport> {
    transport: T,
    trusted_keys: Vec<Dnskey>,
    cache: DnsCache,
    next_id: u16,
    /// When true, an unsigned answer is refused rather than returned Insecure —
    /// the strict posture for a zone known to be signed.
    pub require_signed: bool,
}

impl<T: DnsTransport> ValidatingResolver<T> {
    /// Create a resolver that trusts `trusted_keys` as validation anchors.
    pub fn new(transport: T, trusted_keys: Vec<Dnskey>) -> Self {
        Self {
            transport,
            trusted_keys,
            cache: DnsCache::new(1024),
            next_id: 1,
            require_signed: false,
        }
    }

    fn gen_id(&mut self) -> u16 {
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.next_id
    }

    /// Resolve `name`'s addresses, validating DNSSEC. Returns the addresses and
    /// the [`SecurityStatus`]; a `Bogus` answer yields no addresses.
    pub async fn resolve(&mut self, name: &str, rr_type: u16) -> Result<ValidatedAnswer, ResolveError> {
        let id = self.gen_id();
        let query = build_query(id, name, rr_type);

        // TTL cache (keyed on the query minus its transaction id).
        let raw = if let Some(hit) = self.cache.get(&query) {
            hit
        } else {
            let resp = self.transport.query(&query).await?;
            let ttl = DnsCache::min_ttl_from_response(&resp);
            self.cache.put(&query, &resp, ttl);
            resp
        };

        let msg = DnsMessage::parse(&raw)?;
        if msg.rcode != 0 {
            return Err(ResolveError::Rcode(msg.rcode));
        }

        let answer = rrset_of(&msg.answers, rr_type);
        if answer.is_empty() {
            return Err(ResolveError::NoAnswer);
        }

        let security = match covering_rrsig(&msg.answers, rr_type) {
            Some(sig) => {
                let now = now_unix();
                match validate_answer(&self.trusted_keys, &answer, &sig, now) {
                    Ok(()) => SecurityStatus::Secure,
                    Err(_) => SecurityStatus::Bogus,
                }
            }
            None => {
                if self.require_signed {
                    SecurityStatus::Bogus
                } else {
                    SecurityStatus::Insecure
                }
            }
        };

        // A bogus answer is never returned to the caller.
        let addrs = if security == SecurityStatus::Bogus {
            Vec::new()
        } else {
            answer.iter().filter_map(|r| rdata_to_ip(rr_type, &r.rdata)).collect()
        };

        Ok(ValidatedAnswer { addrs, security })
    }
}

fn rdata_to_ip(rr_type: u16, rdata: &[u8]) -> Option<IpAddr> {
    match rr_type {
        TYPE_A if rdata.len() == 4 => {
            Some(IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])))
        }
        TYPE_AAAA if rdata.len() == 16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(rdata);
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => None,
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec::{signing_input, DNSKEY_FLAG_ZONE};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    // --- wire round-trips ---

    #[test]
    fn query_sets_do_bit_and_parses_back() {
        let q = build_query(0x1234, "www.example.com", TYPE_A);
        // OPT record with DO bit should be present at the tail.
        assert!(q.windows(4).any(|w| w == EDNS_DO_BIT.to_be_bytes()));
        assert_eq!(&q[0..2], &[0x12, 0x34]);
    }

    #[test]
    fn name_compression_is_followed() {
        // Build: header + a name "a.b." at offset 12, then a pointer to it.
        let mut buf = vec![0u8; 12];
        buf.extend_from_slice(&[1, b'a', 1, b'b', 0]); // offset 12
        let ptr_off = buf.len();
        buf.extend_from_slice(&[0xC0, 12]); // pointer back to offset 12
        let (name, next) = read_name(&buf, ptr_off).unwrap();
        assert_eq!(name, "a.b.");
        assert_eq!(next, ptr_off + 2);
    }

    // --- a signed A answer built on the wire, then validated ---

    /// A mock transport that always returns `resp`.
    struct Fixed(Vec<u8>);
    impl DnsTransport for Fixed {
        async fn query(&self, _p: &[u8]) -> Result<Vec<u8>, ResolveError> {
            Ok(self.0.clone())
        }
    }

    fn be16(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }

    /// Encode a domain name in wire form (uncompressed).
    fn wire_name(n: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for l in n.trim_end_matches('.').split('.') {
            if l.is_empty() {
                continue;
            }
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v
    }

    /// Build a response message with one A answer RR and its RRSIG, signed by
    /// `zsk` over `addr`.
    fn signed_a_response(zsk: &SigningKey, zsk_tag: u16, name: &str, addr: [u8; 4]) -> Vec<u8> {
        // The RRSIG the resolver will reconstruct and verify.
        let answer = vec![ResourceRecord {
            name: name.to_string(),
            rr_type: TYPE_A,
            class: 1,
            ttl: 3600,
            rdata: addr.to_vec(),
        }];
        let mut sig = Rrsig {
            type_covered: TYPE_A,
            algorithm: 15,
            labels: 3,
            original_ttl: 3600,
            sig_expiration: 2_000_000_000,
            sig_inception: 1_000_000_000,
            key_tag: zsk_tag,
            signer_name: "example.".into(),
            signature: Vec::new(),
        };
        sig.signature = zsk.sign(&signing_input(&sig, &answer)).to_bytes().to_vec();

        // RRSIG RDATA on the wire.
        let mut rrsig_rdata = Vec::new();
        rrsig_rdata.extend_from_slice(&be16(sig.type_covered));
        rrsig_rdata.push(sig.algorithm);
        rrsig_rdata.push(sig.labels);
        rrsig_rdata.extend_from_slice(&sig.original_ttl.to_be_bytes());
        rrsig_rdata.extend_from_slice(&sig.sig_expiration.to_be_bytes());
        rrsig_rdata.extend_from_slice(&sig.sig_inception.to_be_bytes());
        rrsig_rdata.extend_from_slice(&be16(sig.key_tag));
        rrsig_rdata.extend_from_slice(&wire_name(&sig.signer_name));
        rrsig_rdata.extend_from_slice(&sig.signature);

        let mut m = Vec::new();
        m.extend_from_slice(&be16(0x1234)); // id
        m.extend_from_slice(&[0x81, 0x80]); // QR, RD, RA, rcode 0
        m.extend_from_slice(&be16(1)); // QD
        m.extend_from_slice(&be16(2)); // AN: A + RRSIG
        m.extend_from_slice(&be16(0)); // NS
        m.extend_from_slice(&be16(0)); // AR
        // Question.
        m.extend_from_slice(&wire_name(name));
        m.extend_from_slice(&be16(TYPE_A));
        m.extend_from_slice(&be16(1));
        // Answer A.
        m.extend_from_slice(&wire_name(name));
        m.extend_from_slice(&be16(TYPE_A));
        m.extend_from_slice(&be16(1));
        m.extend_from_slice(&3600u32.to_be_bytes());
        m.extend_from_slice(&be16(4));
        m.extend_from_slice(&addr);
        // Answer RRSIG.
        m.extend_from_slice(&wire_name(name));
        m.extend_from_slice(&be16(TYPE_RRSIG));
        m.extend_from_slice(&be16(1));
        m.extend_from_slice(&3600u32.to_be_bytes());
        m.extend_from_slice(&be16(rrsig_rdata.len() as u16));
        m.extend_from_slice(&rrsig_rdata);
        m
    }

    #[tokio::test]
    async fn validates_a_signed_a_record() {
        let zsk = SigningKey::generate(&mut OsRng);
        let key = Dnskey {
            flags: DNSKEY_FLAG_ZONE,
            algorithm: 15,
            public_key: zsk.verifying_key().to_bytes().to_vec(),
        };
        let tag = key.key_tag();
        let resp = signed_a_response(&zsk, tag, "www.example.", [203, 0, 113, 9]);

        let mut r = ValidatingResolver::new(Fixed(resp), vec![key]);
        let ans = r.resolve("www.example.", TYPE_A).await.unwrap();
        assert_eq!(ans.security, SecurityStatus::Secure);
        assert_eq!(ans.addrs, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]);
    }

    #[tokio::test]
    async fn tampered_answer_is_bogus_and_withheld() {
        let zsk = SigningKey::generate(&mut OsRng);
        let key = Dnskey {
            flags: DNSKEY_FLAG_ZONE,
            algorithm: 15,
            public_key: zsk.verifying_key().to_bytes().to_vec(),
        };
        let tag = key.key_tag();
        let mut resp = signed_a_response(&zsk, tag, "www.example.", [203, 0, 113, 9]);
        // Flip the last address byte in the A rdata region (before the RRSIG).
        let idx = resp.iter().rposition(|&b| b == 9).unwrap();
        resp[idx] = 10;

        let mut r = ValidatingResolver::new(Fixed(resp), vec![key]);
        let ans = r.resolve("www.example.", TYPE_A).await.unwrap();
        assert_eq!(ans.security, SecurityStatus::Bogus);
        assert!(ans.addrs.is_empty(), "a bogus answer must be withheld");
    }

    #[tokio::test]
    async fn unsigned_answer_is_insecure_or_refused() {
        // A response with an A record but no RRSIG.
        let mut m = Vec::new();
        m.extend_from_slice(&be16(0x1234));
        m.extend_from_slice(&[0x81, 0x80]);
        m.extend_from_slice(&be16(1));
        m.extend_from_slice(&be16(1));
        m.extend_from_slice(&be16(0));
        m.extend_from_slice(&be16(0));
        m.extend_from_slice(&wire_name("www.example."));
        m.extend_from_slice(&be16(TYPE_A));
        m.extend_from_slice(&be16(1));
        m.extend_from_slice(&wire_name("www.example."));
        m.extend_from_slice(&be16(TYPE_A));
        m.extend_from_slice(&be16(1));
        m.extend_from_slice(&3600u32.to_be_bytes());
        m.extend_from_slice(&be16(4));
        m.extend_from_slice(&[198, 51, 100, 1]);

        let mut r = ValidatingResolver::new(Fixed(m.clone()), vec![]);
        let ans = r.resolve("www.example.", TYPE_A).await.unwrap();
        assert_eq!(ans.security, SecurityStatus::Insecure);

        // Strict posture refuses the unsigned answer.
        let mut r2 = ValidatingResolver::new(Fixed(m), vec![]);
        r2.require_signed = true;
        let ans2 = r2.resolve("www.example.", TYPE_A).await.unwrap();
        assert_eq!(ans2.security, SecurityStatus::Bogus);
        assert!(ans2.addrs.is_empty());
    }

    /// LIVE: fetch the real root-zone DNSKEY RRset from 1.1.1.1 and prove the
    /// shipped [`root_trust_anchors`](crate::dnssec::root_trust_anchors) digest
    /// is the genuine live root KSK — i.e. the anchor is real, not fabricated —
    /// and that the RSA/SHA-256 verifier validates the root's self-signature.
    /// Ignored by default because it needs outbound DNS; run with
    /// `cargo test --lib -- --ignored dns_resolver`.
    #[tokio::test]
    #[ignore]
    async fn root_anchor_matches_live_root_ksk() {
        use crate::dnssec::{root_trust_anchors, validate_dnskey_rrset, Dnskey};

        let transport = UdpDnsTransport::new("1.1.1.1:53".parse().unwrap());
        let query = build_query(0x7a7a, ".", TYPE_DNSKEY);
        let raw = transport.query(&query).await.expect("live DNS query");
        let msg = DnsMessage::parse(&raw).expect("parse root DNSKEY response");
        assert_eq!(msg.rcode, 0, "root DNSKEY query rcode");

        // Parse the DNSKEY RRset and its self-RRSIG from the answer section.
        let keys: Vec<Dnskey> = msg
            .answers
            .iter()
            .filter(|r| r.rr_type == TYPE_DNSKEY)
            .map(|r| Dnskey::from_rdata(&r.rdata).expect("DNSKEY rdata"))
            .collect();
        assert!(!keys.is_empty(), "root published no DNSKEYs");
        let self_sig = covering_rrsig(&msg.answers, TYPE_DNSKEY)
            .expect("root DNSKEY RRset carries an RRSIG");

        // The shipped anchor must match one of the live root KSKs by digest.
        let anchor = root_trust_anchors();
        let matched = keys
            .iter()
            .any(|k| anchor.iter().any(|ds| ds.matches(".", k)));
        assert!(
            matched,
            "shipped root anchor (tag 20326) does not match any live root KSK"
        );

        // And the full DNSKEY-RRset validation (DS match + RSA self-signature)
        // must succeed against the shipped anchor — proving the RSA verifier
        // handles the real root key.
        let now = now_unix();
        let validated = validate_dnskey_rrset(".", &keys, &self_sig, &anchor, now);
        assert!(
            validated.is_ok(),
            "root DNSKEY RRset failed to validate against shipped anchor: {validated:?}"
        );
    }
}
