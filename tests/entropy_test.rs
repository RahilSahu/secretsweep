//! Entropy engine behaviour at the line level.

use secretsweep::finding::FindingKind;
use secretsweep::scanline::LineScanner;

fn scan(line: &str) -> Vec<secretsweep::finding::Finding> {
    LineScanner::default().scan_line("f.txt", 1, line, None)
}

fn entropy_hits(line: &str) -> usize {
    scan(line)
        .iter()
        .filter(|f| f.kind == FindingKind::Entropy)
        .count()
}

#[test]
fn random_base64_in_assignment_is_flagged_as_entropy() {
    let findings = scan("session = \"Xk9mQ2vZ8pL4nR7wT1sB5dF6gH3jK0mN\"");
    let e: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == FindingKind::Entropy)
        .collect();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].rule_id, "ENTROPY");
    assert!(
        e[0].description.contains("heuristic"),
        "entropy findings must be labelled heuristic: {}",
        e[0].description
    );
}

#[test]
fn plain_english_is_not_flagged() {
    assert_eq!(
        entropy_hits("message = \"the quick brown fox jumps over the lazy dog again\""),
        0
    );
    assert_eq!(
        entropy_hits("name = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""),
        0
    );
}

#[test]
fn uuid_is_not_flagged() {
    assert_eq!(
        entropy_hits("id = \"123e4567-e89b-12d3-a456-426614174000\""),
        0
    );
}

#[test]
fn lockfile_integrity_hash_is_not_flagged() {
    let line = "\"integrity\": \"sha512-Kqh7Xk9mQ2vZ8pL4nR7wT1sB5dF6gH3jK0mN9pQ2rS5tU8vW1xY4zA7bC0dE3fG6hI9jK2lM5nO8pQ==\"";
    assert_eq!(entropy_hits(line), 0);
}

#[test]
fn raising_the_threshold_unflags_borderline_strings() {
    let line = "value = \"Xk9mQ2vZ8pL4nR7wT1sB5dF6gH\"";
    let strict = LineScanner {
        entropy_enabled: true,
        entropy_threshold: 5.5,
    };
    assert!(strict
        .scan_line("f", 1, line, None)
        .iter()
        .all(|f| f.kind != FindingKind::Entropy));
    // And the default threshold does flag it.
    assert!(entropy_hits(line) >= 1);
}

#[test]
fn entropy_can_be_disabled() {
    let off = LineScanner {
        entropy_enabled: false,
        entropy_threshold: 4.5,
    };
    let findings = off.scan_line(
        "f",
        1,
        "session = \"Xk9mQ2vZ8pL4nR7wT1sB5dF6gH3jK0mN\"",
        None,
    );
    assert!(findings.is_empty());
}

#[test]
fn pattern_match_wins_over_entropy_for_the_same_token() {
    // The documented AWS example key: pattern SS001 must report it,
    // and entropy must not double-report the same span.
    let findings = scan("key = \"AKIAIOSFODNN7EXAMPLE\"");
    assert!(findings.iter().any(|f| f.rule_id == "SS001"));
    assert!(findings.iter().all(|f| f.kind != FindingKind::Entropy));
}

#[test]
fn secret_named_assignment_gets_context_boost() {
    // Entropy of this token sits between the boosted and the plain
    // threshold, so only the secret-named assignment is flagged.
    let token = "Xk9mQ2vZ8pL4nR7wT1sB5dF6gH";
    let neutral = format!("value = \"{token}\"");
    let secretish = format!("session_token = \"{token}\"");
    let scanner = LineScanner {
        entropy_enabled: true,
        entropy_threshold: 4.9,
    };
    let n = scanner.scan_line("f", 1, &neutral, None);
    let s = scanner.scan_line("f", 1, &secretish, None);
    assert!(
        n.iter().all(|f| f.kind != FindingKind::Entropy),
        "neutral context should not flag at threshold 4.9: {n:?}"
    );
    assert!(
        s.iter().any(|f| f.kind == FindingKind::Entropy),
        "secret context should flag with the boost: {s:?}"
    );
}
