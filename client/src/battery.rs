//! Power-source awareness: reduce cover traffic on battery.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerSource {
    Ac,
    Battery,
    Unknown,
}

#[cfg(target_os = "linux")]
pub fn power_source() -> PowerSource {
    for p in ["/sys/class/power_supply/AC/online", "/sys/class/power_supply/ACAD/online"] {
        if let Ok(s) = std::fs::read_to_string(p) {
            return if s.trim() == "1" { PowerSource::Ac } else { PowerSource::Battery };
        }
    }
    PowerSource::Unknown
}

#[cfg(not(target_os = "linux"))]
pub fn power_source() -> PowerSource {
    PowerSource::Unknown
}

pub struct BatteryPolicy {
    pub cover_multiplier_on_battery: f64,
    pub disable_bulk_on_battery: bool,
}

impl Default for BatteryPolicy {
    fn default() -> Self {
        Self { cover_multiplier_on_battery: 0.25, disable_bulk_on_battery: true }
    }
}

impl BatteryPolicy {
    pub fn adjust_cover(&self, base_pps: f64) -> f64 {
        match power_source() {
            PowerSource::Battery => base_pps * self.cover_multiplier_on_battery,
            _ => base_pps,
        }
    }
}
