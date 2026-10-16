//! `pqanon-server`: the pieces of the `pqanond` tunnel daemon that are worth
//! testing on their own — the session table ([`core`]), tunnel-address leases
//! ([`pool`]), egress NAT ([`nat`]) and the in-tunnel DNS forwarder
//! ([`dns_forward`]). The binary in `src/bin/pqanond.rs` wires them to a UDP
//! socket and a TUN device.

pub mod core;
pub mod dns_forward;
pub mod nat;
pub mod pool;
