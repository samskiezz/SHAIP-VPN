//! Priority scheduler for stream-mode output (lower priority value = sooner).

use std::cmp::Ordering;
use std::collections::BinaryHeap;

#[derive(Eq, PartialEq)]
struct QueueItem {
    stream_id: u32,
    priority: u8,
    seq: u64,
}

impl Ord for QueueItem {
    fn cmp(&self, other: &Self) -> Ordering {
        other.priority.cmp(&self.priority).then(self.seq.cmp(&other.seq))
    }
}
impl PartialOrd for QueueItem {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

#[derive(Default)]
pub struct StreamScheduler {
    queue: BinaryHeap<QueueItem>,
    next_seq: u64,
}

impl StreamScheduler {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&mut self, stream_id: u32, priority: u8) {
        self.queue.push(QueueItem { stream_id, priority, seq: self.next_seq });
        self.next_seq += 1;
    }
    pub fn pop(&mut self) -> Option<u32> {
        self.queue.pop().map(|i| i.stream_id)
    }
    pub fn len(&self) -> usize { self.queue.len() }
    pub fn is_empty(&self) -> bool { self.queue.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn priority_order() {
        let mut s = StreamScheduler::new();
        s.push(10, 5);
        s.push(20, 1); // higher priority (lower value)
        assert_eq!(s.pop(), Some(20));
        assert_eq!(s.pop(), Some(10));
    }
}
