//! Scans a single line of text with both engines. Shared by the
//! worktree scanner and the git history scanner so a secret is judged
//! the same way wherever it is found.

use crate::entropy::{self, DEFAULT_THRESHOLD};
use crate::finding::{fingerprint, looks_like_placeholder, redact, Finding, FindingKind, Severity};
use crate::rules::{self, ENTROPY_PROVIDER, ENTROPY_RULE_ID, ENTROPY_RULE_NAME};

#[derive(Debug, Clone)]
pub struct LineScanner {
    pub entropy_enabled: bool,
    pub entropy_threshold: f64,
}

impl Default for LineScanner {
    fn default() -> Self {
        LineScanner {
            entropy_enabled: true,
            entropy_threshold: DEFAULT_THRESHOLD,
        }
    }
}

impl LineScanner {
    pub fn scan_line(
        &self,
        file: &str,
        line_no: usize,
        line: &str,
        commit: Option<&str>,
    ) -> Vec<Finding> {
        let mut pattern_findings: Vec<Finding> = Vec::new();

        for compiled in rules::compiled_rules() {
            for caps in compiled.regex.captures_iter(line) {
                let (secret, span) = rules::extract_secret(&caps);
                if compiled.rule.filter_placeholders && looks_like_placeholder(&secret) {
                    continue;
                }
                pattern_findings.push(Finding {
                    file: file.to_string(),
                    line: line_no,
                    column: span.0 + 1,
                    rule_id: compiled.rule.id.to_string(),
                    provider: compiled.rule.provider.to_string(),
                    severity: compiled.rule.severity,
                    kind: FindingKind::Pattern,
                    description: compiled.rule.description.to_string(),
                    preview: redact(&secret),
                    fingerprint: fingerprint(compiled.rule.id, &secret),
                    commit: commit.map(|c| c.to_string()),
                    span,
                });
            }
        }

        // Overlap suppression: when two rules match overlapping spans
        // on the same line, keep one. Provider-specific rules beat
        // generic assignment rules (a Heroku key is also an "api key
        // assignment", but the specific diagnosis is more useful);
        // then the longer match wins, then the more severe one.
        fn generic_rank(f: &Finding) -> u8 {
            if f.provider == "Generic" {
                1
            } else {
                0
            }
        }
        pattern_findings.sort_by(|a, b| {
            a.span
                .0
                .cmp(&b.span.0)
                .then(generic_rank(a).cmp(&generic_rank(b)))
                .then((b.span.1 - b.span.0).cmp(&(a.span.1 - a.span.0)))
                .then(b.severity.cmp(&a.severity))
        });
        let mut kept: Vec<Finding> = Vec::new();
        for f in pattern_findings {
            let overlaps = kept
                .iter()
                .any(|k| f.span.0 < k.span.1 && k.span.0 < f.span.1);
            if !overlaps {
                kept.push(f);
            }
        }

        if self.entropy_enabled {
            for cand in entropy::find_candidates(line) {
                if kept
                    .iter()
                    .any(|k| cand.start < k.span.1 && k.span.0 < cand.end)
                {
                    continue;
                }
                if let Some(value) = entropy::evaluate(line, &cand, self.entropy_threshold) {
                    let secret = cand.token.clone();
                    kept.push(Finding {
                        file: file.to_string(),
                        line: line_no,
                        column: cand.start + 1,
                        rule_id: ENTROPY_RULE_ID.to_string(),
                        provider: ENTROPY_PROVIDER.to_string(),
                        severity: if cand.secret_context {
                            Severity::High
                        } else {
                            Severity::Medium
                        },
                        kind: FindingKind::Entropy,
                        description: format!(
                            "High-entropy string (Shannon entropy {value:.2} bits per character, heuristic detection, rule {ENTROPY_RULE_NAME})"
                        ),
                        preview: redact(&secret),
                        fingerprint: fingerprint(ENTROPY_RULE_ID, &secret),
                        commit: commit.map(|c| c.to_string()),
                        span: (cand.start, cand.end),
                    });
                }
            }
        }

        kept.sort_by_key(|f| f.column);
        kept
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_aws_example_is_found() {
        let s = LineScanner::default();
        let findings = s.scan_line("config.txt", 1, "key = AKIAIOSFODNN7EXAMPLE", None);
        assert!(findings.iter().any(|f| f.rule_id == "SS001"));
    }

    #[test]
    fn full_secret_never_appears_in_preview() {
        let s = LineScanner::default();
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let findings = s.scan_line("f", 1, secret, None);
        for f in &findings {
            assert!(!f.preview.contains(secret), "preview leaked the secret");
            assert!(f.preview.len() <= 7);
        }
    }

    #[test]
    fn clean_line_has_no_findings() {
        let s = LineScanner::default();
        assert!(s
            .scan_line("f", 1, "the quick brown fox jumps over the lazy dog", None)
            .is_empty());
    }
}
