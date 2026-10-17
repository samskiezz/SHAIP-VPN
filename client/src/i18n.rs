//! Minimal message catalog for the CLI (§18 localization).
//!
//! Messages live in TOML files, one per language (`en.toml`, `es.toml`, …), in
//! a directory loaded at startup. The active language comes from `SHAIP_LANG`,
//! else the language portion of `LANG`, else `en`. A missing key falls back to
//! English and then to the key itself, so the daemons never panic or print an
//! empty string for an untranslated message.

use std::collections::HashMap;
use std::sync::OnceLock;

type Catalog = HashMap<String, HashMap<String, String>>;

static MESSAGES: OnceLock<Catalog> = OnceLock::new();

/// Load catalogs from TOML files in `dir`. Idempotent: only the first call
/// (across the process) populates the table; later calls are no-ops.
pub fn init_from(dir: &str) {
    let mut all: Catalog = HashMap::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let lang = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("en")
                .to_string();
            if let Ok(text) = std::fs::read_to_string(&path) {
                if let Ok(map) = toml::from_str::<HashMap<String, String>>(&text) {
                    all.insert(lang, map);
                }
            }
        }
    }
    let _ = MESSAGES.set(all);
}

/// Load catalogs from the default `i18n/` directory.
pub fn init() {
    init_from("i18n");
}

fn selected_lang() -> String {
    if let Ok(l) = std::env::var("SHAIP_LANG") {
        if !l.is_empty() {
            return l;
        }
    }
    if let Ok(l) = std::env::var("LANG") {
        // "en_US.UTF-8" -> "en"
        if let Some(pos) = l.find(['_', '.']) {
            return l[..pos].to_string();
        }
        if !l.is_empty() {
            return l;
        }
    }
    "en".into()
}

/// Translate `key` for the active language, falling back to English and then
/// to the key itself.
pub fn t(key: &str) -> String {
    if let Some(messages) = MESSAGES.get() {
        let lang = selected_lang();
        if let Some(m) = messages.get(&lang).and_then(|m| m.get(key)) {
            return m.clone();
        }
        if let Some(m) = messages.get("en").and_then(|m| m.get(key)) {
            return m.clone();
        }
    }
    key.to_string()
}

/// Translate `key` and substitute `{name}` placeholders from `args`.
pub fn t_args(key: &str, args: &[(&str, &str)]) -> String {
    let mut s = t(key);
    for (k, v) in args {
        s = s.replace(&format!("{{{k}}}"), v);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_key_falls_back_to_itself() {
        // Fallback holds regardless of whether any catalog is loaded.
        init_from("/nonexistent-shaip-i18n");
        assert_eq!(t("__definitely_missing_key__"), "__definitely_missing_key__");
    }

    #[test]
    fn placeholders_are_substituted() {
        let s = t_args("hello {who} and {who2}", &[("who", "world"), ("who2", "mix")]);
        assert_eq!(s, "hello world and mix");
    }
}
