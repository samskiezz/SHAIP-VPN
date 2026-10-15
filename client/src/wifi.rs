//! Per-SSID auto-connect policy for the client.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct WifiRule {
    pub ssid: String,
    pub auto_connect: bool,
    pub route: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct WifiPolicy {
    pub rules: Vec<WifiRule>,
    pub default_auto_connect: bool,
}

impl WifiPolicy {
    pub fn for_ssid(&self, ssid: &str) -> WifiRule {
        self.rules.iter().find(|r| r.ssid == ssid).cloned().unwrap_or(WifiRule {
            ssid: ssid.into(),
            auto_connect: self.default_auto_connect,
            route: None,
        })
    }
    pub fn should_auto_connect(&self, ssid: &str) -> bool {
        self.for_ssid(ssid).auto_connect
    }
}
