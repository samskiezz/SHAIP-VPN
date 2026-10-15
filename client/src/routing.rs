//! Per-domain routing policy (§12.2 `[route]`).
//!
//! Decides whether traffic for a host takes the low-latency `Fast` path or the
//! anonymizing `Anon` (mixnet) path.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Route {
    Fast,
    Anon,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub default: Route,
    #[serde(default)]
    pub anon_domains: Vec<String>,
    #[serde(default)]
    pub fast_domains: Vec<String>,
}

impl Policy {
    /// Resolve the route for `host`. `fast_domains` win over `anon_domains`;
    /// otherwise the default applies.
    pub fn select(&self, host: &str) -> Route {
        if self.fast_domains.iter().any(|p| matches(host, p)) {
            return Route::Fast;
        }
        if self.anon_domains.iter().any(|p| matches(host, p)) {
            return Route::Anon;
        }
        self.default
    }
}

/// Glob match: `*.example.com` matches any subdomain of `example.com`
/// (and, conventionally, the apex); an exact pattern matches exactly.
fn matches(host: &str, pattern: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        host == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            default: Route::Fast,
            anon_domains: vec!["*.journalist.org".into(), "leak.net".into()],
            fast_domains: vec!["*.cdn.example.com".into()],
        }
    }

    #[test]
    fn anon_match() {
        assert_eq!(policy().select("tips.journalist.org"), Route::Anon);
        assert_eq!(policy().select("leak.net"), Route::Anon);
    }

    #[test]
    fn fast_wins_over_default() {
        assert_eq!(policy().select("img.cdn.example.com"), Route::Fast);
    }

    #[test]
    fn default_applies() {
        assert_eq!(policy().select("random.example.org"), Route::Fast);
    }

    #[test]
    fn no_partial_suffix_match() {
        // "*.journalist.org" must not match "notjournalist.org".
        assert_eq!(policy().select("notjournalist.org"), Route::Fast);
    }
}
