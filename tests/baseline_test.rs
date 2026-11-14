//! Baseline round-trip and allowlist matching tests.

use secretsweep::baseline::Baseline;
use secretsweep::config::{load_config, Config};
use secretsweep::scanline::LineScanner;
use secretsweep::scanner::{scan_path, ScanOptions};
use std::fs;

fn dir_with_secret() -> (tempfile::TempDir, Vec<secretsweep::finding::Finding>) {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("app.py"),
        "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n",
    )
    .unwrap();
    let (findings, _) =
        scan_path(dir.path(), &LineScanner::default(), &ScanOptions::default()).unwrap();
    assert!(!findings.is_empty());
    (dir, findings)
}

#[test]
fn baseline_round_trip_suppresses_known_findings() {
    let (_dir, findings) = dir_with_secret();
    let baseline = Baseline::from_findings(&findings);

    // The baseline must never contain the secret itself.
    let serialised = serde_json::to_string(&baseline).unwrap();
    assert!(
        !serialised.contains("AKIAIOSFODNN7EXAMPLE"),
        "baseline leaked a secret value"
    );

    let path = _dir.path().join("baseline.json");
    baseline.save(&path).unwrap();
    let loaded = Baseline::load(&path).unwrap();
    let keys = loaded.key_set();
    for f in &findings {
        assert!(Baseline::contains_raw(&keys, f));
    }
}

#[test]
fn baseline_does_not_suppress_a_new_finding() {
    let (_dir, findings) = dir_with_secret();
    let baseline = Baseline::from_findings(&findings);
    let keys = baseline.key_set();

    // Same rule, same file, different secret value: different
    // fingerprint, must not be suppressed.
    let mut changed = findings[0].clone();
    changed.fingerprint = "0".repeat(64);
    assert!(!Baseline::contains_raw(&keys, &changed));

    // Same secret in a different file: not suppressed either.
    let mut moved = findings[0].clone();
    moved.file = "other.py".to_string();
    assert!(!Baseline::contains_raw(&keys, &moved));
}

#[test]
fn allowlist_by_rule_path_and_fingerprint() {
    let (_dir, findings) = dir_with_secret();
    let f = &findings[0];
    let toml = format!(
        "[[allowlist]]\nrule = \"SS001\"\n\n[[allowlist]]\npath = \"**/nomatch/**\"\n\n[[allowlist]]\nfingerprint = \"{}\"\n",
        "0".repeat(64)
    );
    let cfg_path = _dir.path().join("cfg.toml");
    fs::write(&cfg_path, toml).unwrap();
    let cfg = load_config(&cfg_path).unwrap();
    assert!(cfg.allows(f), "rule entry should allow SS001 anywhere");

    let toml2 = "[[allowlist]]\npaths = [\"**/app.py\"]\n";
    fs::write(&cfg_path, toml2).unwrap();
    let cfg2 = load_config(&cfg_path).unwrap();
    assert!(cfg2.allows(f), "path glob should allow this file");

    let toml3 = format!("[[allowlist]]\nfingerprint = \"{}\"\n", f.fingerprint);
    fs::write(&cfg_path, toml3).unwrap();
    let cfg3 = load_config(&cfg_path).unwrap();
    assert!(
        cfg3.allows(f),
        "fingerprint entry should allow this finding"
    );

    let toml4 = "[[allowlist]]\nrule = \"SS999\"\n";
    fs::write(&cfg_path, toml4).unwrap();
    let cfg4 = load_config(&cfg_path).unwrap();
    assert!(!cfg4.allows(f), "a different rule must not allow SS001");
}

#[test]
fn empty_allowlist_entry_is_a_config_error() {
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("cfg.toml");
    fs::write(&cfg_path, "[[allowlist]]\n").unwrap();
    assert!(load_config(&cfg_path).is_err());
}

#[test]
fn malformed_config_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("cfg.toml");
    fs::write(&cfg_path, "this is [ not toml").unwrap();
    assert!(load_config(&cfg_path).is_err());
}

#[test]
fn default_config_allows_nothing() {
    let (_dir, findings) = dir_with_secret();
    let cfg = Config::default();
    assert!(!cfg.allows(&findings[0]));
}
