//! Retransmission queue: holds unacked packets and surfaces the ones that
//! have exceeded their RTO (§8.2).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub struct Unacked {
    pub seq: u32,
    pub sent_at: Instant,
    pub bytes: Vec<u8>,
    pub retransmits: u8,
}

pub struct RetxQueue {
    queue: VecDeque<Unacked>,
    max_size: usize,
    max_retransmits: u8,
}

impl RetxQueue {
    pub fn new(max_size: usize) -> Self {
        Self { queue: VecDeque::new(), max_size, max_retransmits: 10 }
    }
    pub fn push(&mut self, seq: u32, bytes: Vec<u8>) -> bool {
        if self.queue.len() >= self.max_size {
            return false;
        }
        self.queue.push_back(Unacked { seq, sent_at: Instant::now(), bytes, retransmits: 0 });
        true
    }
    pub fn ack(&mut self, seq: u32) {
        self.queue.retain(|u| u.seq != seq);
    }
    /// Return packets past RTO (up to `max`), bumping their retransmit count.
    pub fn expired(&mut self, rto: Duration, max: usize) -> Vec<(u32, Vec<u8>)> {
        let now = Instant::now();
        let mut out = Vec::new();
        for u in self.queue.iter_mut() {
            if out.len() >= max {
                break;
            }
            if now.duration_since(u.sent_at) >= rto {
                u.retransmits += 1;
                u.sent_at = now;
                out.push((u.seq, u.bytes.clone()));
            }
        }
        self.queue.retain(|u| u.retransmits < self.max_retransmits);
        out
    }
    pub fn len(&self) -> usize { self.queue.len() }
    pub fn is_empty(&self) -> bool { self.queue.is_empty() }
}
