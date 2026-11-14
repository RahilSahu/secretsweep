//! Baselines: a JSON snapshot of known findings.
//!
//! A baseline entry stores the rule id, the file, and the finding's
//! fingerprint (a SHA-256 hash of rule id + secret value). The secret
//! itself is never written to the baseline, so the baseline file is
//! safe to commit.

use crate::finding::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub tool: String,
    pub entries: Vec<BaselineEntry>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct BaselineEntry {
    pub rule_id: String,
    pub file: String,
    pub fingerprint: String,
}

impl Baseline {
    pub fn from_findings(findings: &[Finding]) -> Baseline {
        let mut seen = HashSet::new();
        let mut entries = Vec::new();
        for f in findings {
            let entry = BaselineEntry {
                rule_id: f.rule_id.clone(),
                file: f.file.clone(),
                fingerprint: f.fingerprint.clone(),
            };
            if seen.insert(entry.clone()) {
                entries.push(entry);
            }
        }
        entries.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then(a.rule_id.cmp(&b.rule_id))
                .then(a.fingerprint.cmp(&b.fingerprint))
        });
        Baseline {
            version: 1,
            tool: format!("secretsweep {}", env!("CARGO_PKG_VERSION")),
            entries,
        }
    }

    pub fn key_set(&self) -> HashSet<(String, String, String)> {
        self.entries
            .iter()
            .map(|e| {
                (
                    e.rule_id.clone(),
                    e.file.clone(),
                    e.fingerprint.clone(),
                )
            })
            .collect()
    }

    pub fn contains_raw(keys: &HashSet<(String, String, String)>, f: &Finding) -> bool {
        keys.contains(&(
            f.rule_id.clone(),
            f.file.clone(),
            f.fingerprint.clone(),
        ))
    }

    pub fn load(path: &Path) -> Result<Baseline, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read baseline {}: {e}", path.display()))?;
        let baseline: Baseline = serde_json::from_str(&text)
            .map_err(|e| format!("cannot parse baseline {}: {e}", path.display()))?;
        if baseline.version != 1 {
            return Err(format!(
                "baseline {} has unsupported version {}",
                path.display(),
                baseline.version
            ));
        }
        Ok(baseline)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| format!("cannot serialise baseline: {e}"))?;
        std::fs::write(path, text + "\n")
            .map_err(|e| format!("cannot write baseline {}: {e}", path.display()))
    }
}
