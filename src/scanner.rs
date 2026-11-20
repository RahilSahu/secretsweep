//! Worktree scanning: walks a file or directory tree and scans every
//! text file line by line.
//!
//! Walking respects `.gitignore` (via the `ignore` crate) so files a
//! project already excludes from version control are not scanned.
//! A built-in skip list additionally excludes VCS internals and
//! dependency or build output directories. Lockfiles are *not*
//! skipped: they are text and have historically contained committed
//! registry tokens.
//!
//! Zip archives are not skipped as binaries: they are opened and
//! inspected by the `archive` module (one level deep, with size
//! caps), because an opaque archive is exactly where a payload can
//! hide from a line-based scanner.

use crate::archive;
use crate::finding::Finding;
use crate::redirector;
use crate::scanline::LineScanner;
use ignore::WalkBuilder;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Files larger than this many bytes are skipped (but counted).
    pub max_bytes: u64,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            max_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Default)]
pub struct ScanStats {
    pub files_scanned: usize,
    pub files_skipped_binary: usize,
    pub files_skipped_oversize: usize,
}

const SKIP_DIRS: &[&str] = &[
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "vendor",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".tox",
    ".idea",
];

fn is_binary(data: &[u8]) -> bool {
    data.iter().take(8192).any(|&b| b == 0)
}

/// Display path for a walked file: as walked, with a leading "./"
/// removed so reports stay readable.
fn display_path(path: &Path) -> String {
    let s = path.to_string_lossy().replace('\\', "/");
    s.strip_prefix("./").map(|r| r.to_string()).unwrap_or(s)
}

fn scan_file(
    path: &Path,
    scanner: &LineScanner,
    opts: &ScanOptions,
    stats: &mut ScanStats,
    findings: &mut Vec<Finding>,
) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(_) => return,
    };
    if (data.len() as u64) > opts.max_bytes {
        stats.files_skipped_oversize += 1;
        // An oversize zip used to vanish silently here, which is
        // how a packed cheat bundle escaped the archive checks in
        // the 2026-11-20 hunt. Report it as uninspectable instead:
        // the skip counter still records that it was not scanned.
        if archive::is_zip(path, &data) {
            findings.push(archive::oversize_finding(
                &display_path(path),
                data.len() as u64,
                opts.max_bytes,
            ));
        }
        return;
    }
    if archive::is_zip(path, &data) {
        stats.files_scanned += 1;
        let name = display_path(path);
        findings.extend(archive::inspect_zip(&name, &data, scanner, opts.max_bytes));
        return;
    }
    if is_binary(&data) {
        stats.files_skipped_binary += 1;
        return;
    }
    stats.files_scanned += 1;
    let name = display_path(path);
    let text = String::from_utf8_lossy(&data);
    for (i, line) in text.lines().enumerate() {
        findings.extend(scanner.scan_line(&name, i + 1, line, None));
    }
    // Whole-file structural check: the remote-config redirector
    // signature only exists across lines, so it runs on the full
    // text of HTML and JavaScript files after the line scan.
    if redirector::is_web_file(&name) {
        if let Some(f) = redirector::check_file(&name, &text) {
            findings.push(f);
        }
    }
}

/// Scan a file or directory tree. Returns findings and statistics.
pub fn scan_path(
    root: &Path,
    scanner: &LineScanner,
    opts: &ScanOptions,
) -> Result<(Vec<Finding>, ScanStats), String> {
    if !root.exists() {
        return Err(format!("path does not exist: {}", root.display()));
    }
    let mut stats = ScanStats::default();
    let mut findings = Vec::new();

    if root.is_file() {
        scan_file(root, scanner, opts, &mut stats, &mut findings);
        return Ok((findings, stats));
    }

    let walker = WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .require_git(false)
        .follow_links(false)
        .filter_entry(|entry| {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let name = entry.file_name().to_string_lossy();
                !SKIP_DIRS.contains(&name.as_ref())
            } else {
                true
            }
        })
        .build();

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            scan_file(entry.path(), scanner, opts, &mut stats, &mut findings);
        }
    }

    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
    Ok((findings, stats))
}
