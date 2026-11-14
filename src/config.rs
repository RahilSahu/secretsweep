//! Optional configuration file (`.secretsweep.toml`), currently used
//! for the allowlist and an entropy threshold override.
//!
//! Example:
//!
//! ```toml
//! entropy_threshold = 4.8
//!
//! [[allowlist]]
//! rule = "SS065"
//!
//! [[allowlist]]
//! path = "tests/**"
//!
//! [[allowlist]]
//! fingerprint = "0123abcd..."
//! ```
//!
//! An allowlist entry suppresses a finding when *every* field it sets
//! matches the finding. Entries with no fields set are a config error.

use crate::finding::Finding;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Default, Deserialize)]
pub struct Config {
    pub entropy_threshold: Option<f64>,
    #[serde(default)]
    pub allowlist: Vec<AllowEntry>,
}

#[derive(Debug, Deserialize)]
pub struct AllowEntry {
    pub rule: Option<String>,
    pub path: Option<String>,
    pub paths: Option<Vec<String>>,
    pub fingerprint: Option<String>,
}

impl AllowEntry {
    fn globs(&self) -> Vec<&str> {
        let mut v = Vec::new();
        if let Some(p) = &self.path {
            v.push(p.as_str());
        }
        if let Some(ps) = &self.paths {
            v.extend(ps.iter().map(|s| s.as_str()));
        }
        v
    }

    pub fn is_empty(&self) -> bool {
        self.rule.is_none() && self.fingerprint.is_none() && self.globs().is_empty()
    }

    pub fn matches(&self, f: &Finding) -> bool {
        if let Some(rule) = &self.rule {
            if rule != &f.rule_id {
                return false;
            }
        }
        if let Some(fp) = &self.fingerprint {
            if fp != &f.fingerprint {
                return false;
            }
        }
        let globs = self.globs();
        globs.is_empty() || globs.iter().any(|g| glob_match(g, &f.file))
    }
}

impl Config {
    pub fn allows(&self, f: &Finding) -> bool {
        self.allowlist.iter().any(|e| e.matches(f))
    }
}

/// Load and validate a config file.
pub fn load_config(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
    let cfg: Config = toml::from_str(&text)
        .map_err(|e| format!("cannot parse config {}: {e}", path.display()))?;
    for entry in &cfg.allowlist {
        if entry.is_empty() {
            return Err(format!(
                "config {} has an [[allowlist]] entry with no fields; set rule, path, paths or fingerprint",
                path.display()
            ));
        }
    }
    Ok(cfg)
}

/// Minimal glob matcher supporting `**` (any characters including
/// `/`), `*` (any characters except `/`) and `?` (one character
/// except `/`). Paths are compared with forward slashes.
pub fn glob_match(pattern: &str, path: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = path.chars().collect();
    match_here(&pat, &text)
}

fn match_here(pat: &[char], text: &[char]) -> bool {
    if pat.is_empty() {
        return text.is_empty();
    }
    // "**/" matches zero or more leading path segments.
    if pat.len() >= 3 && pat[0] == '*' && pat[1] == '*' && pat[2] == '/' {
        for skip in 0..=text.len() {
            if match_here(&pat[3..], &text[skip..]) {
                return true;
            }
            if skip < text.len() && text[skip] != '/' {
                // "**/" can only stop consuming at a segment boundary;
                // keep scanning but only retry at boundaries.
                continue;
            }
        }
        return false;
    }
    // "**" matches everything including slashes.
    if pat.len() >= 2 && pat[0] == '*' && pat[1] == '*' {
        for skip in 0..=text.len() {
            if match_here(&pat[2..], &text[skip..]) {
                return true;
            }
        }
        return false;
    }
    if pat[0] == '*' {
        // Single star: consume non-slash characters.
        for skip in 0..=text.len() {
            if match_here(&pat[1..], &text[skip..]) {
                return true;
            }
            if skip < text.len() && text[skip] == '/' {
                return false;
            }
        }
        return false;
    }
    if text.is_empty() {
        return false;
    }
    if pat[0] == '?' {
        return text[0] != '/' && match_here(&pat[1..], &text[1..]);
    }
    pat[0] == text[0] && match_here(&pat[1..], &text[1..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_basics() {
        assert!(glob_match("*.py", "app.py"));
        assert!(!glob_match("*.py", "src/app.py"));
        assert!(glob_match("src/*.py", "src/app.py"));
        assert!(glob_match("src/**", "src/a/b/c.py"));
        assert!(glob_match("**/fixtures/**", "tests/fixtures/x.py"));
        assert!(glob_match("tests/**", "tests/x.py"));
        assert!(glob_match("**", "anything/at/all.txt"));
        assert!(glob_match("?.txt", "a.txt"));
        assert!(!glob_match("?.txt", "ab.txt"));
        assert!(!glob_match("src/*.py", "src/app.rs"));
    }
}
