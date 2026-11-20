//! Report format tests: JSON shape, SARIF structure, text layout,
//! and the guarantee that no format prints a full secret.

use secretsweep::finding::{Finding, FindingKind, Severity};
use secretsweep::report::{render_json, render_sarif, render_text, ReportData};
use secretsweep::rules;
use secretsweep::scanner::ScanStats;

const SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

fn finding(severity: Severity) -> Finding {
    Finding {
        file: "src/app.py".to_string(),
        line: 7,
        column: 12,
        rule_id: "SS001".to_string(),
        provider: "AWS".to_string(),
        severity,
        kind: FindingKind::Pattern,
        description: "AWS access key ID (long-lived IAM user key)".to_string(),
        preview: "AKIA...".to_string(),
        fingerprint: "a".repeat(64),
        commit: None,
        span: (11, 31),
    }
}

fn stats() -> ScanStats {
    ScanStats {
        files_scanned: 3,
        files_skipped_binary: 1,
        files_skipped_oversize: 0,
    }
}

#[test]
fn text_report_shows_location_and_redacted_preview_only() {
    let findings = vec![finding(Severity::High)];
    let st = stats();
    let out = render_text(&ReportData {
        findings: &findings,
        suppressed: 0,
        stats: Some(&st),
    });
    assert!(out.contains("src/app.py:7:12:"), "text: {out}");
    assert!(out.contains("[HIGH] SS001"), "text: {out}");
    assert!(out.contains("AKIA..."), "text: {out}");
    assert!(!out.contains(SECRET), "text report leaked the secret");
    assert!(out.contains("Scanned 3 files"), "text: {out}");
}

#[test]
fn json_report_shape_and_no_secret_leak() {
    let findings = vec![finding(Severity::Critical)];
    let st = stats();
    let out = render_json(&ReportData {
        findings: &findings,
        suppressed: 2,
        stats: Some(&st),
    });
    assert!(!out.contains(SECRET), "JSON report leaked the secret");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["tool"], "secretsweep");
    assert_eq!(v["stats"]["files_scanned"], 3);
    assert_eq!(v["stats"]["mode"], "worktree");
    assert_eq!(v["suppressed"], 2);
    let f = &v["findings"][0];
    assert_eq!(f["rule_id"], "SS001");
    assert_eq!(f["severity"], "critical");
    assert_eq!(f["kind"], "pattern");
    assert_eq!(f["line"], 7);
    assert_eq!(f["column"], 12);
    assert_eq!(f["preview"], "AKIA...");
    // Internal span must not be serialised.
    assert!(f.get("span").is_none());
}

#[test]
fn sarif_report_structure_and_rule_metadata() {
    let findings = vec![finding(Severity::High)];
    let out = render_sarif(&ReportData {
        findings: &findings,
        suppressed: 0,
        stats: None,
    });
    assert!(!out.contains(SECRET), "SARIF report leaked the secret");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["version"], "2.1.0");
    assert!(v["$schema"].as_str().unwrap().contains("sarif-2.1.0"));
    let run = &v["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "SecretSweep");
    let rules_meta = run["tool"]["driver"]["rules"].as_array().unwrap();
    // One metadata entry per pattern rule, plus the entropy rule,
    // the two structural archive rules and the redirector rule.
    assert_eq!(rules_meta.len(), rules::rules().len() + 4);
    assert!(rules_meta.iter().any(|r| r["id"] == "ENTROPY"));
    assert!(rules_meta.iter().any(|r| r["id"] == "ARCHIVE-EXEC"));
    assert!(rules_meta.iter().any(|r| r["id"] == "ARCHIVE-UNREADABLE"));
    assert!(rules_meta.iter().any(|r| r["id"] == "REDIRECTOR"));
    let result = &run["results"][0];
    assert_eq!(result["ruleId"], "SS001");
    assert_eq!(result["level"], "error");
    let loc = &result["locations"][0]["physicalLocation"];
    assert_eq!(loc["artifactLocation"]["uri"], "src/app.py");
    assert_eq!(loc["region"]["startLine"], 7);
    assert_eq!(loc["region"]["startColumn"], 12);
    assert_eq!(
        result["partialFingerprints"]["secretsweep/v1"],
        "a".repeat(64)
    );
}

#[test]
fn sarif_level_mapping_for_all_severities() {
    let cases = [
        (Severity::Critical, "error"),
        (Severity::High, "error"),
        (Severity::Medium, "warning"),
        (Severity::Low, "note"),
    ];
    for (sev, expected) in cases {
        let findings = vec![finding(sev)];
        let out = render_sarif(&ReportData {
            findings: &findings,
            suppressed: 0,
            stats: None,
        });
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v["runs"][0]["results"][0]["level"], expected,
            "severity {sev:?}"
        );
    }
}

#[test]
fn sarif_with_no_findings_has_empty_results() {
    let out = render_sarif(&ReportData {
        findings: &[],
        suppressed: 0,
        stats: None,
    });
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
}
