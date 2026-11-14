//! Git history scanning integration tests. These build real git
//! repositories in temporary directories with the git CLI.

use secretsweep::git_scan::scan_git_history;
use secretsweep::scanline::LineScanner;
use secretsweep::scanner::{scan_path, ScanOptions};
use std::fs;
use std::path::Path;
use std::process::Command;

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

fn git_out(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A repo whose first commit adds the AWS documentation example key
/// and whose second commit removes it again.
fn repo_with_removed_secret() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    git(p, &["init", "-q", "-b", "main"]);
    fs::write(
        p.join("config.py"),
        "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n",
    )
    .unwrap();
    git(p, &["add", "."]);
    git(p, &["commit", "-q", "-m", "add config (with a mistake)"]);
    let first_commit = git_out(p, &["rev-parse", "HEAD"]);

    fs::write(p.join("config.py"), "aws_access_key_id = \"\"\n").unwrap();
    git(p, &["add", "."]);
    git(p, &["commit", "-q", "-m", "remove the key"]);
    (dir, first_commit)
}

#[test]
fn removed_secret_is_found_in_history_but_not_in_worktree() {
    let (dir, first_commit) = repo_with_removed_secret();

    // Worktree is clean now.
    let (wt_findings, _) =
        scan_path(dir.path(), &LineScanner::default(), &ScanOptions::default()).unwrap();
    assert!(
        wt_findings.iter().all(|f| f.rule_id != "SS001"),
        "worktree must not report the removed key: {wt_findings:?}"
    );

    // History still contains it, attributed to the first commit.
    let result = scan_git_history(dir.path(), &LineScanner::default()).unwrap();
    assert!(result.has_commits);
    let f = result
        .findings
        .iter()
        .find(|f| f.rule_id == "SS001")
        .expect("history scan must find the removed key");
    assert_eq!(f.commit.as_deref(), Some(first_commit.as_str()));
    assert_eq!(f.file, "config.py");
    assert_eq!(f.line, 1);
}

#[test]
fn empty_repository_is_graceful() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q", "-b", "main"]);
    let result = scan_git_history(dir.path(), &LineScanner::default()).unwrap();
    assert!(!result.has_commits);
    assert!(result.findings.is_empty());
}

#[test]
fn non_repository_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let result = scan_git_history(dir.path(), &LineScanner::default());
    match result {
        Ok(_) => panic!("scanning a non-repository must fail"),
        Err(e) => assert!(e.contains("not a git repository"), "error: {e}"),
    }
}
