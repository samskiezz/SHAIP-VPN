//! Local reputation scoring for mix-node path selection (§10.2). Scores are
//! built from this client's own observed delivery successes/failures.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct NodeReputation {
    pub node_id: String,
    pub successes: u32,
    pub failures: u32,
    pub timeouts: u32,
    pub last_seen_unix: u64,
}

impl NodeReputation {
    pub fn score(&self) -> f64 {
        let total = (self.successes + self.failures + self.timeouts).max(1) as f64;
        let success = self.successes as f64 / total;
        let timeout_penalty = self.timeouts as f64 / total * 2.0;
        (success - timeout_penalty).clamp(0.0, 1.0)
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct ReputationStore {
    pub nodes: HashMap<String, NodeReputation>,
}

impl ReputationStore {
    fn entry(&mut self, id: &str) -> &mut NodeReputation {
        self.nodes.entry(id.into()).or_insert_with(|| NodeReputation {
            node_id: id.into(),
            ..Default::default()
        })
    }

    pub fn record_success(&mut self, id: &str) {
        let n = self.entry(id);
        n.successes += 1;
        n.last_seen_unix = now_unix();
    }

    pub fn record_failure(&mut self, id: &str) {
        self.entry(id).failures += 1;
    }

    pub fn record_timeout(&mut self, id: &str) {
        self.entry(id).timeouts += 1;
    }

    pub fn top(&self, n: usize) -> Vec<&NodeReputation> {
        let mut v: Vec<&NodeReputation> = self.nodes.values().collect();
        v.sort_by(|a, b| b.score().partial_cmp(&a.score()).unwrap_or(std::cmp::Ordering::Equal));
        v.into_iter().take(n).collect()
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

    #[test]
    fn higher_success_ranks_first() {
        let mut s = ReputationStore::default();
        for _ in 0..10 {
            s.record_success("good");
        }
        s.record_success("bad");
        s.record_timeout("bad");
        s.record_timeout("bad");
        let top = s.top(1);
        assert_eq!(top[0].node_id, "good");
    }
}
