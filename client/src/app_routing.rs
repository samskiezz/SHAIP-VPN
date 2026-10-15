//! Per-application split tunneling (bypass vs. force-through-tunnel).

use std::collections::HashSet;

#[derive(Default)]
pub struct AppRouting {
    pub bypass: HashSet<String>,
    pub force: HashSet<String>,
}

impl AppRouting {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_bypass(&mut self, name: impl Into<String>) { self.bypass.insert(name.into()); }
    pub fn add_force(&mut self, name: impl Into<String>) { self.force.insert(name.into()); }
    /// `force` wins over `bypass`.
    pub fn should_bypass(&self, process: &str) -> bool {
        !self.force.contains(process) && self.bypass.contains(process)
    }
}
