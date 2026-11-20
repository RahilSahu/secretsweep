//! Report rendering: human-readable text, JSON, and SARIF 2.1.0.
//!
//! No format ever prints a full secret: findings only carry the
//! redacted preview and the hash fingerprint.

use crate::finding::{Finding, Severity};
use crate::rules;
use crate::scanner::ScanStats;
use serde_json::{json, Value};

pub struct ReportData<'a> {
    pub findings: &'a [Finding],
    pub suppressed: usize,
    /// Worktree statistics; None in git history mode.
    pub stats: Option<&'a ScanStats>,
}

fn severity_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn security_severity(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.0",
        Severity::Low => "2.0",
    }
}

pub fn render_text(data: &ReportData) -> String {
    let mut out = String::new();
    for f in data.findings {
        out.push_str(&format!(
            "{}:{}:{}: [{}] {} ({}) {} (preview: {})",
            f.file,
            f.line,
            f.column,
            f.severity.as_str().to_uppercase(),
            f.rule_id,
            f.provider,
            f.description,
            f.preview,
        ));
        if let Some(commit) = &f.commit {
            out.push_str(&format!(" [commit {}]", &commit[..commit.len().min(10)]));
        }
        out.push('\n');
    }
    match data.stats {
        Some(stats) => {
            out.push_str(&format!(
                "Scanned {} files ({} binary skipped, {} oversize skipped): {} findings",
                stats.files_scanned,
                stats.files_skipped_binary,
                stats.files_skipped_oversize,
                data.findings.len()
            ));
        }
        None => {
            out.push_str(&format!(
                "Scanned git history: {} findings",
                data.findings.len()
            ));
        }
    }
    if data.suppressed > 0 {
        out.push_str(&format!(
            " ({} suppressed by baseline or allowlist)",
            data.suppressed
        ));
    }
    out.push('\n');
    out
}

pub fn render_json(data: &ReportData) -> String {
    let stats = match data.stats {
        Some(s) => json!({
            "files_scanned": s.files_scanned,
            "files_skipped_binary": s.files_skipped_binary,
            "files_skipped_oversize": s.files_skipped_oversize,
            "mode": "worktree",
        }),
        None => json!({ "mode": "git-history" }),
    };
    let doc = json!({
        "tool": "secretsweep",
        "version": env!("CARGO_PKG_VERSION"),
        "stats": stats,
        "suppressed": data.suppressed,
        "findings": data.findings,
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string()) + "\n"
}

fn sarif_rules() -> Vec<Value> {
    let mut out = Vec::new();
    for r in rules::rules() {
        out.push(json!({
            "id": r.id,
            "name": r.name,
            "shortDescription": { "text": r.description },
            "fullDescription": { "text": format!("{}: {}", r.provider, r.description) },
            "defaultConfiguration": { "level": severity_level(r.severity) },
            "properties": {
                "security-severity": security_severity(r.severity),
                "tags": ["security", "secrets", r.provider],
            },
        }));
    }
    out.push(json!({
        "id": rules::ENTROPY_RULE_ID,
        "name": rules::ENTROPY_RULE_NAME,
        "shortDescription": { "text": "High-entropy string (heuristic detection)" },
        "fullDescription": { "text": "A string whose Shannon entropy exceeds the configured threshold. Heuristic: may be a secret, a random identifier or a hash." },
        "defaultConfiguration": { "level": "warning" },
        "properties": {
            "security-severity": "5.0",
            "tags": ["security", "secrets", "entropy", "heuristic"],
        },
    }));
    out.push(json!({
        "id": rules::ARCHIVE_EXEC_RULE_ID,
        "name": rules::ARCHIVE_EXEC_RULE_NAME,
        "shortDescription": { "text": "Archive contains executable and launcher or script files" },
        "fullDescription": { "text": "A zip archive pairing an executable with a launcher or script file, or with a large single-line text file. Inspect before running anything from the archive." },
        "defaultConfiguration": { "level": "error" },
        "properties": {
            "security-severity": "8.0",
            "tags": ["security", "archive", "malware-indicator"],
        },
    }));
    out.push(json!({
        "id": rules::ARCHIVE_UNREADABLE_RULE_ID,
        "name": rules::ARCHIVE_UNREADABLE_RULE_NAME,
        "shortDescription": { "text": "Archive could not be inspected" },
        "fullDescription": { "text": "A zip archive that could not be opened or fully read (corrupt, encrypted or unsupported compression). Unexamined contents were not scanned." },
        "defaultConfiguration": { "level": "note" },
        "properties": {
            "security-severity": "2.0",
            "tags": ["security", "archive"],
        },
    }));
    out.push(json!({
        "id": rules::REDIRECTOR_RULE_ID,
        "name": rules::REDIRECTOR_RULE_NAME,
        "shortDescription": { "text": "Remote-config redirector pattern (fetch or XHR, atob decode, location redirect)" },
        "fullDescription": { "text": "An HTML or JavaScript file combining a fetch or XHR request, an atob() base64 decode and a location redirect assignment: the remote-config redirector pattern used by lure download portals, whose destination is fetched from a config file and can be changed without editing the page." },
        "defaultConfiguration": { "level": "error" },
        "properties": {
            "security-severity": "8.0",
            "tags": ["security", "redirector", "malware-indicator"],
        },
    }));
    out
}

pub fn render_sarif(data: &ReportData) -> String {
    let results: Vec<Value> = data
        .findings
        .iter()
        .map(|f| {
            let mut physical = json!({
                "artifactLocation": { "uri": f.file },
                "region": { "startLine": f.line, "startColumn": f.column },
            });
            if let Some(commit) = &f.commit {
                physical["artifactLocation"]["uri"] = json!(f.file);
                physical["contextRegion"] = json!({
                    "snippet": { "text": format!("commit {commit}") }
                });
            }
            json!({
                "ruleId": f.rule_id,
                "level": severity_level(f.severity),
                "message": { "text": format!("{}: {} (preview: {})", f.provider, f.description, f.preview) },
                "locations": [ { "physicalLocation": physical } ],
                "partialFingerprints": { "secretsweep/v1": f.fingerprint },
            })
        })
        .collect();

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [ {
            "tool": { "driver": {
                "name": "SecretSweep",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/RahilSahu/secretsweep",
                "rules": sarif_rules(),
            } },
            "results": results,
        } ],
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string()) + "\n"
}
