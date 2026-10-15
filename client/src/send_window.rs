//! Send-window validator: never allow more than cwnd packets in flight.

pub struct SendWindow {
    base: u32,
    next: u32,
    cwnd_packets: u32,
}

impl SendWindow {
    pub fn new(cwnd_packets: u32) -> Self {
        Self { base: 1, next: 1, cwnd_packets }
    }
    pub fn can_send(&self) -> bool {
        self.next.wrapping_sub(self.base) < self.cwnd_packets
    }
    pub fn alloc(&mut self) -> Option<u32> {
        if !self.can_send() {
            return None;
        }
        let n = self.next;
        self.next = self.next.wrapping_add(1);
        Some(n)
    }
    pub fn ack(&mut self, seq: u32) {
        if seq >= self.base {
            self.base = seq.wrapping_add(1);
        }
    }
    pub fn set_cwnd(&mut self, packets: u32) {
        self.cwnd_packets = packets.max(2);
    }
    pub fn in_flight(&self) -> u32 { self.next.wrapping_sub(self.base) }
    pub fn base(&self) -> u32 { self.base }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn respects_cwnd() {
        let mut w = SendWindow::new(2);
        assert_eq!(w.alloc(), Some(1));
        assert_eq!(w.alloc(), Some(2));
        assert_eq!(w.alloc(), None);
        w.ack(1);
        assert_eq!(w.alloc(), Some(3));
    }
}
