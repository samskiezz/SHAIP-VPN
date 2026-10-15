//! Server-side identity allow-list (§7 pinned identities).

use std::collections::HashSet;

pub struct Allowlist {
    identities: HashSet<String>,
    enforce: bool,
}

impl Allowlist {
    pub fn new(identities: Vec<String>, enforce: bool) -> Self {
        Self { identities: identities.into_iter().collect(), enforce }
    }
    pub fn check(&self, identity_id: &str) -> bool {
        !self.enforce || self.identities.contains(identity_id)
    }
    pub fn len(&self) -> usize { self.identities.len() }
    pub fn is_empty(&self) -> bool { self.identities.is_empty() }
}
