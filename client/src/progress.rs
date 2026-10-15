//! Terminal progress reporter for long client operations.

use std::io::{stderr, Write};
use std::time::Instant;

pub struct Progress {
    label: String,
    total: u64,
    current: u64,
    last_render: Instant,
}

impl Progress {
    pub fn new(label: &str, total: u64) -> Self {
        Self { label: label.into(), total, current: 0, last_render: Instant::now() }
    }
    pub fn advance(&mut self, delta: u64) {
        self.current += delta;
        if self.last_render.elapsed().as_millis() >= 100 {
            self.render();
            self.last_render = Instant::now();
        }
    }
    pub fn render(&self) {
        let pct = if self.total == 0 { 0.0 } else { self.current as f64 / self.total as f64 * 100.0 };
        eprint!("\r{}: {:.1}% ({}/{})", self.label, pct, self.current, self.total);
        let _ = stderr().flush();
    }
    pub fn finish(&self) {
        eprintln!();
    }
}
