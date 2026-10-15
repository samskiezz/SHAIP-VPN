//! IP blacklist with exact addresses and CIDR ranges.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

#[derive(Default)]
pub struct Blacklist {
    exact: HashSet<IpAddr>,
    ranges: Vec<ipnet::IpNet>,
}

impl Blacklist {
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let mut bl = Self::default();
        for line in std::fs::read_to_string(path)?.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line.contains('/') {
                if let Ok(net) = line.parse::<ipnet::IpNet>() {
                    bl.ranges.push(net);
                }
            } else if let Ok(ip) = line.parse::<IpAddr>() {
                bl.exact.insert(ip);
            }
        }
        Ok(bl)
    }
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        self.exact.contains(&ip) || self.ranges.iter().any(|n| n.contains(&ip))
    }
    pub fn add(&mut self, ip: IpAddr) { self.exact.insert(ip); }
    pub fn remove(&mut self, ip: IpAddr) { self.exact.remove(&ip); }
    pub fn len(&self) -> usize { self.exact.len() + self.ranges.len() }
    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blocks_exact_and_range() {
        let mut bl = Blacklist::default();
        bl.add("1.2.3.4".parse().unwrap());
        bl.ranges.push("10.0.0.0/8".parse().unwrap());
        assert!(bl.is_blocked("1.2.3.4".parse().unwrap()));
        assert!(bl.is_blocked("10.9.9.9".parse().unwrap()));
        assert!(!bl.is_blocked("8.8.8.8".parse().unwrap()));
    }
}
