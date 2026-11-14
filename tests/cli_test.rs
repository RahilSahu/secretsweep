//! End-to-end CLI tests against the compiled binary: exit codes,
//! formats, baseline flow and allowlist config.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_secretsweep"))
        .args(args)
        .output()
        .unwrap()
}

fn run_in(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_secretsweep"))
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn dir_with(content: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("app.py");
    fs::write(&file, content).unwrap();
    let root = dir.path().to_path_buf();
    (dir, root)
}

#[test]
fn clean_directory_exits_zero() {
    let (_d, root) = dir_with("name = \"hello\"\n");
    let out = run(&[root.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "stdout: {}", stdout(&out));
    assert!(stdout(&out).contains("0 findings"));
}

#[test]
fn high_finding_exits_one() {
    let (_d, root) = dir_with("aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n");
    let out = run(&[root.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("SS001"));
}

#[test]
fn low_finding_respects_fail_on_threshold() {
    let (_d, root) = dir_with(concat!(
        "stripe = \"sk_test_",
        "AbCdEfGhIjKlMnOpQrStUvWx",
        "\"\n"
    ));
    // Default fail-on is high: a lone low finding exits 0.
    let out = run(&[root.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "stdout: {}", stdout(&out));
    // With --fail-on low it exits 1.
    let out = run(&[root.to_str().unwrap(), "--fail-on", "low"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn nonexistent_path_exits_two() {
    let out = run(&["/definitely/not/here/secretsweep"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn git_mode_on_non_repository_exits_two() {
    let (_d, root) = dir_with("x = 1\n");
    let out = run(&[root.to_str().unwrap(), "--git"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn bad_arguments_exit_two() {
    let out = run(&["--fail-on", "urgent"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn list_rules_reports_the_true_count() {
    let out = run(&["--list-rules"]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert!(text.contains("SS001"));
    assert!(text.contains("SS094"));
    assert!(text.contains("94 pattern rules"), "list output: {text}");
}

#[test]
fn json_format_via_cli() {
    let (_d, root) = dir_with("aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n");
    let out = run(&[root.to_str().unwrap(), "--format", "json"]);
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["findings"].as_array().unwrap().len(), 1);
    assert_eq!(v["findings"][0]["rule_id"], "SS001");
}

#[test]
fn sarif_format_via_cli_parses() {
    let (_d, root) = dir_with("aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n");
    let out = run(&[root.to_str().unwrap(), "--format", "sarif"]);
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["version"], "2.1.0");
}

#[test]
fn baseline_write_then_suppress_flow() {
    let (dir, root) = dir_with("aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n");
    let baseline = dir.path().join("baseline.json");
    let b = baseline.to_str().unwrap();

    // First run creates the baseline and still reports (exit 1).
    let out = run(&[root.to_str().unwrap(), "--baseline", b]);
    assert_eq!(out.status.code(), Some(1));
    assert!(baseline.exists(), "baseline file must be created");
    let text = fs::read_to_string(&baseline).unwrap();
    assert!(!text.contains("AKIAIOSFODNN7EXAMPLE"));

    // Second run suppresses the known finding (exit 0).
    let out = run(&[root.to_str().unwrap(), "--baseline", b]);
    assert_eq!(out.status.code(), Some(0), "stdout: {}", stdout(&out));
    assert!(stdout(&out).contains("suppressed"));
}

#[test]
fn allowlist_config_suppresses_via_cli() {
    let (dir, _root) = dir_with("aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n");
    fs::write(
        dir.path().join(".secretsweep.toml"),
        "[[allowlist]]\nrule = \"SS001\"\n",
    )
    .unwrap();
    // Run from inside the directory so the config is discovered.
    let out = run_in(dir.path(), &["."]);
    assert_eq!(out.status.code(), Some(0), "stdout: {}", stdout(&out));
    assert!(stdout(&out).contains("suppressed"));
}
