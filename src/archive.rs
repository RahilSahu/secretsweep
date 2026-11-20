//! Zip archive inspection for worktree scans.
//!
//! Before v1.1, a `.zip` file was skipped as an opaque binary, which
//! is exactly where a real malware lure hid its payload during the
//! 2026-11-20 hunt: a launcher script, a bundled interpreter
//! executable, and a disguised script file, none of them ever opened.
//! Worktree scans now open zip archives (one level only) and:
//!
//! - scan text-like entries with the normal rule engine, reporting
//!   findings under `archive.zip!/entry-name` paths;
//! - raise a dedicated warning when an archive pairs an executable
//!   with a launcher or script file, or with a large single-line
//!   text file (a common disguised-script shape);
//! - report archives that cannot be opened or read (corrupt,
//!   encrypted, unsupported compression) as uninspectable instead of
//!   failing the scan.
//!
//! Safety caps keep a hostile or accidental zip bomb from exhausting
//! memory: at most [`MAX_ARCHIVE_ENTRIES`] entries are examined, at
//! most the per-file size cap is extracted per entry, and at most 16
//! times that cap across the whole archive. Entries are read in
//! memory only; nothing is ever written to disk or executed.

use crate::finding::{fingerprint, Finding, FindingKind, Severity};
use crate::redirector;
use crate::rules::{ARCHIVE_EXEC_RULE_ID, ARCHIVE_PROVIDER, ARCHIVE_UNREADABLE_RULE_ID};
use crate::scanline::LineScanner;
use std::io::{Cursor, Read};
use std::path::Path;

/// Maximum number of entries examined per archive.
pub const MAX_ARCHIVE_ENTRIES: usize = 512;

/// A text entry at least this large with at most one line counts as
/// a "large single-line text file" for the executable pairing check:
/// the shape of a script payload disguised as a data or icon file.
pub const LARGE_SINGLE_LINE_BYTES: usize = 50_000;

/// Extensions treated as executables for the pairing check.
const EXECUTABLE_EXTS: &[&str] = &["exe", "dll", "scr", "com", "msi", "sys"];

/// Extensions treated as launcher or script files for the pairing
/// check: Windows script hosts and shell launchers that can start an
/// executable or script with a double click.
const LAUNCHER_EXTS: &[&str] = &[
    "cmd", "bat", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
];

/// True when the file looks like a zip archive, by extension or by
/// the PK magic at the start of the data.
pub fn is_zip(path: &Path, data: &[u8]) -> bool {
    let by_extension = path
        .extension()
        .map(|e| e.to_string_lossy().eq_ignore_ascii_case("zip"))
        .unwrap_or(false);
    // PK\x03\x04 (local file header), PK\x05\x06 (empty archive),
    // PK\x07\x08 (spanned archive marker).
    let by_magic = data.len() >= 4
        && data[0] == b'P'
        && data[1] == b'K'
        && matches!(
            (data[2], data[3]),
            (0x03, 0x04) | (0x05, 0x06) | (0x07, 0x08)
        );
    by_extension || by_magic
}

fn extension_of(name: &str) -> String {
    name.rsplit('.')
        .next()
        .filter(|ext| !ext.is_empty() && !ext.contains('/'))
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn is_binary(data: &[u8]) -> bool {
    data.iter().take(8192).any(|&b| b == 0)
}

fn structural_finding(
    file: &str,
    rule_id: &str,
    severity: Severity,
    description: String,
    summary: &str,
) -> Finding {
    let preview: String = summary.chars().take(60).collect();
    Finding {
        file: file.to_string(),
        line: 1,
        column: 1,
        rule_id: rule_id.to_string(),
        provider: ARCHIVE_PROVIDER.to_string(),
        severity,
        kind: FindingKind::Pattern,
        description,
        preview,
        fingerprint: fingerprint(rule_id, summary),
        commit: None,
        span: (0, 0),
    }
}

fn unreadable_finding(file: &str, detail: &str) -> Finding {
    structural_finding(
        file,
        ARCHIVE_UNREADABLE_RULE_ID,
        Severity::Low,
        format!(
            "Archive could not be inspected ({detail}); any unexamined contents were not scanned"
        ),
        &format!("uninspectable: {detail}"),
    )
}

/// Finding for an archive that was skipped without inspection
/// because the file itself exceeds the scan size cap. Before
/// v1.2 this skip was silent; wave 2 of the 2026-11-20 hunt
/// missed a packed cheat bundle exactly this way.
pub fn oversize_finding(file: &str, size: u64, cap: u64) -> Finding {
    structural_finding(
        file,
        ARCHIVE_UNREADABLE_RULE_ID,
        Severity::Low,
        format!(
            "Archive was not inspected due to size: the file is {size} bytes, over the scan size cap of {cap} bytes, so its contents were not scanned"
        ),
        &format!("oversize archive: {size} bytes over cap {cap}"),
    )
}

/// Inspect one zip archive's bytes. `display` is the path shown in
/// reports for the archive itself; entry findings use
/// `display!/entry-name`. `max_bytes` is the scanner's per-file size
/// cap, reused as the per-entry extraction cap.
pub fn inspect_zip(
    display: &str,
    data: &[u8],
    scanner: &LineScanner,
    max_bytes: u64,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let cursor = Cursor::new(data);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => {
            findings.push(unreadable_finding(
                display,
                "corrupt, encrypted or not a zip archive",
            ));
            return findings;
        }
    };

    let per_entry_cap = max_bytes;
    let total_cap = max_bytes.saturating_mul(16);
    let mut total_read: u64 = 0;
    let mut any_unreadable = false;
    let mut executables: Vec<String> = Vec::new();
    let mut launchers: Vec<String> = Vec::new();
    let mut large_single_line: Vec<String> = Vec::new();

    let entry_count = archive.len().min(MAX_ARCHIVE_ENTRIES);
    for i in 0..entry_count {
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(_) => {
                any_unreadable = true;
                continue;
            }
        };
        let name = entry.name().replace('\\', "/");
        if name.ends_with('/') {
            continue; // directory entry
        }
        let ext = extension_of(&name);
        if EXECUTABLE_EXTS.contains(&ext.as_str()) {
            executables.push(name.clone());
        }
        if LAUNCHER_EXTS.contains(&ext.as_str()) {
            launchers.push(name.clone());
        }
        // Nested archives are listed for the checks above (a nested
        // zip has no executable or launcher extension) but never
        // opened: inspection is one level deep.
        if ext == "zip" {
            continue;
        }
        if entry.size() > per_entry_cap || total_read >= total_cap {
            continue; // content beyond the caps is not extracted
        }
        let budget = per_entry_cap.min(total_cap - total_read);
        let mut buf = Vec::new();
        let read = entry
            .by_ref()
            .take(budget.saturating_add(1))
            .read_to_end(&mut buf);
        match read {
            Ok(_) => {
                if buf.len() as u64 > budget {
                    continue; // declared size lied; entry exceeds the cap
                }
                total_read += buf.len() as u64;
                if is_binary(&buf) {
                    continue;
                }
                let text = String::from_utf8_lossy(&buf);
                if buf.len() >= LARGE_SINGLE_LINE_BYTES && text.lines().count() <= 1 {
                    large_single_line.push(name.clone());
                }
                let entry_display = format!("{display}!/{name}");
                for (n, line) in text.lines().enumerate() {
                    findings.extend(scanner.scan_line(&entry_display, n + 1, line, None));
                }
                // The redirector signature spans lines, so HTML
                // and JavaScript entries also get the whole-file
                // structural check.
                if redirector::is_web_file(&name) {
                    if let Some(f) = redirector::check_file(&entry_display, &text) {
                        findings.push(f);
                    }
                }
            }
            Err(_) => {
                // Encrypted entries and unsupported compression land
                // here. The rest of the archive is still scanned.
                any_unreadable = true;
            }
        }
    }

    if !executables.is_empty() && (!launchers.is_empty() || !large_single_line.is_empty()) {
        let mut partners: Vec<String> = Vec::new();
        partners.extend(launchers.iter().cloned());
        for name in &large_single_line {
            partners.push(format!("{name} (large single-line text file)"));
        }
        let description = format!(
            "Archive contains executable file(s) {} together with launcher or script file(s) {}; inspect before running anything from this archive",
            executables.join(", "),
            partners.join(", ")
        );
        let summary = format!(
            "exec:{}|partners:{}",
            executables.join(","),
            partners.join(",")
        );
        findings.push(structural_finding(
            display,
            ARCHIVE_EXEC_RULE_ID,
            Severity::High,
            description,
            &summary,
        ));
    }

    if any_unreadable {
        findings.push(unreadable_finding(
            display,
            "one or more entries are corrupt, encrypted or use unsupported compression",
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut buf);
            let opts = SimpleFileOptions::default();
            for (name, content) in entries {
                writer.start_file(*name, opts).unwrap();
                writer.write_all(content).unwrap();
            }
            writer.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn zip_detection_by_extension_and_magic() {
        let data = make_zip(&[("a.txt", b"hello")]);
        assert!(is_zip(Path::new("x.zip"), &data));
        assert!(is_zip(Path::new("renamed.bin"), &data));
        assert!(!is_zip(Path::new("plain.txt"), b"just text"));
    }

    #[test]
    fn secret_inside_text_entry_is_found_with_archive_path() {
        let data = make_zip(&[(
            "inner/config.txt",
            b"aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n",
        )]);
        let findings = inspect_zip("bundle.zip", &data, &LineScanner::default(), 1024 * 1024);
        let f = findings.iter().find(|f| f.rule_id == "SS001").unwrap();
        assert_eq!(f.file, "bundle.zip!/inner/config.txt");
    }

    #[test]
    fn executable_with_launcher_triggers_warning() {
        let data = make_zip(&[
            ("run.exe", &[0x4d, 0x5a, 0x00, 0x01][..]),
            ("start.cmd", b"start run.exe\n"),
        ]);
        let findings = inspect_zip("bundle.zip", &data, &LineScanner::default(), 1024 * 1024);
        assert!(findings.iter().any(|f| f.rule_id == ARCHIVE_EXEC_RULE_ID));
    }

    #[test]
    fn docs_only_archive_is_quiet() {
        let data = make_zip(&[
            ("README.md", b"# Notes\nNothing to run here.\n"),
            ("notes.txt", b"plain documentation\n"),
        ]);
        let findings = inspect_zip("bundle.zip", &data, &LineScanner::default(), 1024 * 1024);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn corrupt_zip_is_unreadable_not_fatal() {
        let findings = inspect_zip(
            "broken.zip",
            b"PK\x03\x04 this is not really a zip",
            &LineScanner::default(),
            1024 * 1024,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, ARCHIVE_UNREADABLE_RULE_ID);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn oversize_finding_names_the_size_reason() {
        let f = oversize_finding("big.zip", 3_000_000, 1_048_576);
        assert_eq!(f.rule_id, ARCHIVE_UNREADABLE_RULE_ID);
        assert_eq!(f.severity, Severity::Low);
        assert!(f.description.contains("not inspected due to size"));
        assert!(f.description.contains("3,000,000") || f.description.contains("3000000"));
    }
}
