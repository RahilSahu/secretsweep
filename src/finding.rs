//! Core types shared by the scanner, reports and baseline code.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Severity of a rule or finding, ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

/// Which detection engine produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingKind {
    /// A provider or format pattern rule matched.
    Pattern,
    /// The entropy heuristic flagged a high-entropy string.
    Entropy,
}

/// One detected secret. The secret value itself is never stored here;
/// only a redacted preview and a hash fingerprint are kept.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Path of the file, relative to the scanned root (or repo-relative
    /// in git history mode).
    pub file: String,
    /// 1-based line number.
    pub line: usize,
    /// 1-based column (byte offset within the line) of the secret value.
    pub column: usize,
    pub rule_id: String,
    pub provider: String,
    pub severity: Severity,
    pub kind: FindingKind,
    pub description: String,
    /// At most the first four characters of the secret, plus "...".
    pub preview: String,
    /// SHA-256 of rule id + secret value. Lets baselines recognise a
    /// finding without storing the secret.
    pub fingerprint: String,
    /// Commit hash, set only for git history findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Byte span of the secret within the line; used internally for
    /// overlap suppression, never serialised.
    #[serde(skip)]
    pub span: (usize, usize),
}

/// Build a redacted preview: at most the first four characters of the
/// secret are shown, fewer for short values, followed by "...".
pub fn redact(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    let shown = match chars.len() {
        0..=4 => 1.min(chars.len()),
        5..=8 => 2,
        _ => 4,
    };
    let head: String = chars.into_iter().take(shown).collect();
    format!("{head}...")
}

/// Fingerprint a finding for baseline comparison. The secret value is
/// hashed, never stored.
pub fn fingerprint(rule_id: &str, secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(secret.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Values that are clearly placeholders rather than real credentials.
/// Applied to assignment-style rules and entropy candidates so that
/// documentation and templates do not drown the report in noise.
pub fn looks_like_placeholder(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "example",
        "placeholder",
        "changeme",
        "change-me",
        "change_me",
        "your-",
        "your_",
        "insert",
        "replace",
        "todo",
        "xxxxx",
        "*****",
        "sample",
        "dummy",
        "fake",
        "demo",
        "none",
        "null",
        "undefined",
        "redacted",
        "removed",
        "not-a-real",
        "not_a_real",
        "test-key",
        "test_key",
        "localhost",
    ];
    if MARKERS.iter().any(|m| v.contains(m)) {
        return true;
    }
    // A value made of a single repeated character is not a credential.
    let mut chars = value.chars();
    if let Some(first) = chars.next() {
        if chars.all(|c| c == first) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn severity_parse_roundtrip() {
        for s in ["low", "medium", "high", "critical"] {
            assert_eq!(Severity::parse(s).unwrap().as_str(), s);
        }
        assert!(Severity::parse("urgent").is_none());
        assert_eq!(Severity::parse("HIGH"), Some(Severity::High));
    }

    #[test]
    fn redact_never_shows_more_than_four_chars() {
        assert_eq!(redact("AKIAIOSFODNN7EXAMPLE"), "AKIA...");
        assert_eq!(redact("short"), "sh...");
        assert_eq!(redact("abc"), "a...");
        assert_eq!(redact(""), "...");
    }

    #[test]
    fn fingerprint_is_deterministic_and_rule_scoped() {
        let a = fingerprint("SS001", "some-value");
        let b = fingerprint("SS001", "some-value");
        let c = fingerprint("SS002", "some-value");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn placeholders_are_detected() {
        assert!(looks_like_placeholder("your-api-key-here"));
        assert!(looks_like_placeholder("EXAMPLEKEY123"));
        assert!(looks_like_placeholder("xxxxxxxxxxxx"));
        assert!(!looks_like_placeholder("aB3dEf6hIjKlMnOp9QrStUv"));
    }
}
