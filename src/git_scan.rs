//! Git history scanning.
//!
//! Implemented by shelling out to the `git` CLI (`git log -p`) instead
//! of linking a git library: the binary stays small, and history
//! semantics (rename detection, encodings) match the tool users
//! already trust. The trade-off is documented: `git` must be
//! installed. Only *added* lines are scanned, because a secret enters
//! history on the line that adds it; merge commits carry no diff in
//! `git log -p` output and are therefore not covered.

use crate::finding::Finding;
use crate::scanline::LineScanner;
use std::path::Path;
use std::process::Command;

pub struct GitScanResult {
    pub findings: Vec<Finding>,
    /// False when the repository exists but has no commits yet.
    pub has_commits: bool,
}

fn git_available() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

fn run_git(repo: &Path, args: &[&str]) -> Result<std::process::Output, String> {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run git: {e}"))
}

/// Scan every commit reachable from any ref in the repository at
/// `repo`. Returns an error when `repo` is not a git repository.
pub fn scan_git_history(repo: &Path, scanner: &LineScanner) -> Result<GitScanResult, String> {
    if !git_available() {
        return Err(
            "git history mode needs the git CLI, but `git` was not found on PATH".to_string(),
        );
    }
    let probe = run_git(repo, &["rev-parse", "--git-dir"])?;
    if !probe.status.success() {
        return Err(format!(
            "not a git repository: {} (worktree mode works on any directory, --git needs a repository)",
            repo.display()
        ));
    }
    let head = run_git(repo, &["rev-parse", "--verify", "-q", "HEAD"])?;
    if !head.status.success() {
        // A fresh repository with no commits is not an error.
        return Ok(GitScanResult {
            findings: Vec::new(),
            has_commits: false,
        });
    }

    let output = run_git(
        repo,
        &[
            "log",
            "-p",
            "-U0",
            "--all",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--format=__SS_COMMIT__%H",
        ],
    )?;
    if !output.status.success() {
        return Err(format!(
            "git log failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut findings = Vec::new();
    let mut commit: Option<String> = None;
    let mut file: Option<String> = None;
    let mut line_no: usize = 0;

    for raw in text.lines() {
        if let Some(rest) = raw.strip_prefix("__SS_COMMIT__") {
            commit = Some(rest.trim().to_string());
            file = None;
            continue;
        }
        if raw.starts_with("diff --git ") {
            file = None;
            continue;
        }
        if let Some(rest) = raw.strip_prefix("+++ ") {
            let p = rest.trim();
            if p == "/dev/null" {
                file = None;
            } else if let Some(stripped) = p.strip_prefix("b/") {
                file = Some(stripped.to_string());
            } else {
                file = Some(p.to_string());
            }
            continue;
        }
        if raw.starts_with("@@ ") {
            // Hunk header: @@ -a,b +c,d @@ ; new-file line numbers
            // start at c.
            if let Some(plus) = raw.split_whitespace().nth(2) {
                let num: String = plus
                    .trim_start_matches('+')
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                line_no = num.parse().unwrap_or(0);
            }
            continue;
        }
        if raw.starts_with('+') && !raw.starts_with("+++") {
            if let (Some(f), Some(c)) = (&file, &commit) {
                let content = &raw[1..];
                findings.extend(scanner.scan_line(f, line_no, content, Some(c)));
            }
            line_no += 1;
        }
    }

    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
    Ok(GitScanResult {
        findings,
        has_commits: true,
    })
}
