//! Entropy detection: a heuristic second engine next to the pattern
//! rules. It extracts candidate strings (quoted literals and values in
//! assignments), measures their Shannon entropy, and flags the ones
//! above a charset-aware threshold.
//!
//! Entropy detection is inherently noisy: random IDs, hashes and
//! compressed data also look random. Findings from this engine are
//! labelled as heuristic in every report format so they are never
//! confused with pattern matches. The baseline and allowlist exist
//! largely to tame this engine's false positives.

use crate::finding::looks_like_placeholder;
use regex::Regex;
use std::sync::OnceLock;

/// Default threshold for base64-style alphabets. The hex threshold is
/// derived from it (hex strings carry less entropy per character).
pub const DEFAULT_THRESHOLD: f64 = 4.5;

const HEX_GAP: f64 = 0.9;
const CONTEXT_BOOST: f64 = 0.4;

#[derive(Debug, Clone)]
pub struct Candidate {
    /// Byte span of the token within the line.
    pub start: usize,
    pub end: usize,
    pub token: String,
    /// True when the value sits in an assignment whose key name looks
    /// secret-related; such candidates get a lower threshold.
    pub secret_context: bool,
}

/// Shannon entropy of a string, in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let mut total = 0usize;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    let total = total as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum()
}

fn assignment_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r##"(?i)([A-Za-z0-9_.\-]+)\s*[:=]\s*["']?([A-Za-z0-9+/=_-]{16,})["']?"##)
            .expect("assignment regex must compile")
    })
}

fn key_is_secretish(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    ["password", "passwd", "secret", "token", "api_key", "apikey", "api-key", "auth", "credential", "private"]
        .iter()
        .any(|w| k.contains(w))
}

/// Extract entropy candidates from one line: quoted literals plus
/// values in `key = value` / `key: value` assignments. Overlapping
/// candidates are merged, preferring the assignment form because it
/// carries context.
pub fn find_candidates(line: &str) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();

    // Assignment values.
    for caps in assignment_regex().captures_iter(line) {
        let key = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if let Some(val) = caps.get(2) {
            let token = val.as_str();
            if token.len() >= 16 {
                out.push(Candidate {
                    start: val.start(),
                    end: val.end(),
                    token: token.to_string(),
                    secret_context: key_is_secretish(key),
                });
            }
        }
    }

    // Quoted literals.
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' || b == b'\'' || b == b'`' {
            if let Some(rel_end) = line[i + 1..].find(b as char) {
                let content_start = i + 1;
                let content_end = i + 1 + rel_end;
                let content = &line[content_start..content_end];
                if content.len() >= 16
                    && !content.chars().any(|c| c.is_whitespace())
                    && !out
                        .iter()
                        .any(|c| content_start >= c.start && content_end <= c.end)
                {
                    out.push(Candidate {
                        start: content_start,
                        end: content_end,
                        token: content.to_string(),
                        secret_context: false,
                    });
                }
                i = content_end + 1;
                continue;
            }
        }
        i += 1;
    }

    out
}

fn is_uuid(token: &str) -> bool {
    let parts: Vec<&str> = token.split('-').collect();
    parts.len() == 5
        && parts.iter().map(|p| p.len()).collect::<Vec<_>>() == vec![8, 4, 4, 4, 12]
        && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn preceded_by_digest_name(line: &str, start: usize) -> bool {
    let before = &line[..start.min(line.len())];
    ["sha1-", "sha256-", "sha512-", "md5-", "sha224-", "sha384-"]
        .iter()
        .any(|p| before.ends_with(p))
}

/// Evaluate one candidate. Returns the measured entropy when the
/// candidate should be reported, or None when it should not.
pub fn evaluate(line: &str, cand: &Candidate, base_threshold: f64) -> Option<f64> {
    let token = cand.token.as_str();
    if looks_like_placeholder(token) || is_uuid(token) {
        return None;
    }
    if preceded_by_digest_name(line, cand.start) {
        return None;
    }
    let is_hex = token.chars().all(|c| c.is_ascii_hexdigit());
    if is_hex && token.len() < 24 {
        return None;
    }
    let entropy = shannon_entropy(token);
    let mut threshold = if is_hex {
        (base_threshold - HEX_GAP).max(2.5)
    } else {
        base_threshold
    };
    if cand.secret_context {
        threshold -= CONTEXT_BOOST;
    }
    if entropy >= threshold {
        Some(entropy)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_repeated_char_is_zero() {
        assert_eq!(shannon_entropy("aaaaaaaaaaaaaaaa"), 0.0);
    }

    #[test]
    fn entropy_of_random_base64_is_high() {
        let e = shannon_entropy("Xk9mQ2vZ8pL4nR7wT1sB5dF6gH3jK");
        assert!(e > 4.5, "expected high entropy, got {e}");
    }

    #[test]
    fn entropy_of_english_is_low() {
        let e = shannon_entropy("the quick brown fox jumps over the lazy dog");
        assert!(e < 4.5, "expected low entropy, got {e}");
    }

    #[test]
    fn candidates_include_assignments_and_quotes() {
        let line = r#"api_token = "Xk9mQ2vZ8pL4nR7wT1s" and other = 'plainvalue123456789'"#;
        let cands = find_candidates(line);
        assert!(cands.iter().any(|c| c.token == "Xk9mQ2vZ8pL4nR7wT1s" && c.secret_context));
        assert!(cands.iter().any(|c| c.token == "plainvalue123456789"));
    }

    #[test]
    fn uuid_is_never_flagged() {
        let line = r#"id = "123e4567-e89b-12d3-a456-426614174000""#;
        let cands = find_candidates(line);
        for c in &cands {
            assert!(evaluate(line, c, DEFAULT_THRESHOLD).is_none());
        }
    }

    #[test]
    fn digest_values_are_not_flagged() {
        let line = "integrity sha512-Kqh7Xk9mQ2vZ8pL4nR7wT1sB5dF6gH3jK0mN9pQ2rS5tU8vW1xY4zA7bC0dE==";
        let cand = Candidate {
            start: line.find("Kqh7").unwrap(),
            end: line.len(),
            token: line[line.find("Kqh7").unwrap()..].to_string(),
            secret_context: false,
        };
        assert!(evaluate(line, &cand, DEFAULT_THRESHOLD).is_none());
    }
}
