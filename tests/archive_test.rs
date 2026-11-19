//! Zip archive inspection integration tests, through the full
//! worktree scanner.
//!
//! Every fixture archive is built in memory from harmless text and
//! dummy bytes: no real executable, payload or credential is used.
//! The planted key is the AWS documentation example key.

use secretsweep::finding::Finding;
use secretsweep::rules::{ARCHIVE_EXEC_RULE_ID, ARCHIVE_UNREADABLE_RULE_ID};
use secretsweep::scanline::LineScanner;
use secretsweep::scanner::{scan_path, ScanOptions, ScanStats};
use std::fs;
use std::io::Write;
use std::path::Path;
use zip::write::SimpleFileOptions;

const AWS_LINE: &str = "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"";

fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
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

fn write(root: &Path, rel: &str, content: &[u8]) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn scan(root: &Path) -> (Vec<Finding>, ScanStats) {
    scan_path(root, &LineScanner::default(), &ScanOptions::default()).unwrap()
}

fn scan_with(root: &Path, max_bytes: u64) -> (Vec<Finding>, ScanStats) {
    scan_path(root, &LineScanner::default(), &ScanOptions { max_bytes }).unwrap()
}

#[test]
fn planted_key_in_zip_text_entry_is_found_with_archive_path() {
    let dir = tempfile::tempdir().unwrap();
    let zip = zip_bytes(&[("inner/config.txt", format!("{AWS_LINE}\n").as_bytes())]);
    write(dir.path(), "bundle.zip", &zip);
    let (findings, stats) = scan(dir.path());
    assert_eq!(stats.files_scanned, 1);
    assert_eq!(stats.files_skipped_binary, 0);
    let f = findings.iter().find(|f| f.rule_id == "SS001").unwrap();
    assert!(
        f.file.ends_with("bundle.zip!/inner/config.txt"),
        "file: {}",
        f.file
    );
}

#[test]
fn zip_with_non_zip_extension_is_inspected_via_magic() {
    let dir = tempfile::tempdir().unwrap();
    let zip = zip_bytes(&[("notes.txt", format!("{AWS_LINE}\n").as_bytes())]);
    write(dir.path(), "payload.bin", &zip);
    let (findings, _) = scan(dir.path());
    assert!(
        findings.iter().any(|f| f.rule_id == "SS001"),
        "magic-detected zip must be opened: {findings:?}"
    );
}

#[test]
fn exe_and_launcher_zip_triggers_archive_warning() {
    let dir = tempfile::tempdir().unwrap();
    let zip = zip_bytes(&[
        ("tool.exe", &[0x4d, 0x5a, 0x90, 0x00][..]),
        ("Launcher.cmd", b"start tool.exe data.txt\n"),
        ("data.txt", b"harmless notes\n"),
    ]);
    write(dir.path(), "Auto_claim.zip", &zip);
    let (findings, _) = scan(dir.path());
    let f = findings
        .iter()
        .find(|f| f.rule_id == ARCHIVE_EXEC_RULE_ID)
        .expect("archive warning must fire");
    assert!(f.description.contains("tool.exe"), "{}", f.description);
    assert!(f.description.contains("Launcher.cmd"), "{}", f.description);
}

#[test]
fn docs_only_zip_produces_no_findings() {
    let dir = tempfile::tempdir().unwrap();
    let zip = zip_bytes(&[
        ("README.md", b"# User guide\nHow to read this bundle.\n"),
        ("docs/notes.txt", b"plain documentation, nothing to run\n"),
    ]);
    write(dir.path(), "guide.zip", &zip);
    let (findings, stats) = scan(dir.path());
    assert_eq!(stats.files_scanned, 1);
    assert!(findings.is_empty(), "unexpected findings: {findings:?}");
}

#[test]
fn executable_alone_does_not_trigger_warning() {
    let dir = tempfile::tempdir().unwrap();
    let zip = zip_bytes(&[
        ("tool.exe", &[0x4d, 0x5a, 0x90, 0x00][..]),
        ("readme.txt", b"a single portable tool\n"),
    ]);
    write(dir.path(), "tool.zip", &zip);
    let (findings, _) = scan(dir.path());
    assert!(
        findings.iter().all(|f| f.rule_id != ARCHIVE_EXEC_RULE_ID),
        "exe without a launcher must not warn: {findings:?}"
    );
}

#[test]
fn executable_with_large_single_line_text_triggers_warning() {
    let dir = tempfile::tempdir().unwrap();
    let blob = vec![b'a'; 60_000];
    let zip = zip_bytes(&[
        ("engine.exe", &[0x4d, 0x5a, 0x90, 0x00][..]),
        ("icon.txt", &blob),
    ]);
    write(dir.path(), "bundle.zip", &zip);
    let (findings, _) = scan(dir.path());
    assert!(
        findings.iter().any(|f| f.rule_id == ARCHIVE_EXEC_RULE_ID),
        "exe plus large single-line text must warn: {findings:?}"
    );
}

#[test]
fn corrupt_zip_is_uninspectable_and_the_scan_continues() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "broken.zip",
        b"PK\x03\x04 not really a zip archive",
    );
    write(dir.path(), "plain.txt", AWS_LINE.as_bytes());
    let (findings, _) = scan(dir.path());
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == ARCHIVE_UNREADABLE_RULE_ID),
        "corrupt zip must be reported: {findings:?}"
    );
    assert!(
        findings.iter().any(|f| f.rule_id == "SS001"),
        "other files must still be scanned: {findings:?}"
    );
}

#[test]
fn oversized_zip_is_skipped_and_counted() {
    let dir = tempfile::tempdir().unwrap();
    // Random-looking padding so the archive itself stays large even
    // after deflate compression.
    let mut padding = Vec::new();
    let mut state: u32 = 0x1234_5678;
    for _ in 0..8192 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        padding.push((state >> 24) as u8);
    }
    let zip = zip_bytes(&[("pad.bin", &padding)]);
    assert!(zip.len() > 4096);
    write(dir.path(), "big.zip", &zip);
    let (findings, stats) = scan_with(dir.path(), 1024);
    assert_eq!(stats.files_skipped_oversize, 1);
    assert!(findings.is_empty());
}

#[test]
fn nested_zip_is_not_opened() {
    let dir = tempfile::tempdir().unwrap();
    let inner = zip_bytes(&[("secret.txt", format!("{AWS_LINE}\n").as_bytes())]);
    let outer = zip_bytes(&[("inner.zip", &inner), ("readme.txt", b"outer bundle\n")]);
    write(dir.path(), "outer.zip", &outer);
    let (findings, _) = scan(dir.path());
    assert!(
        findings.iter().all(|f| f.rule_id != "SS001"),
        "nested archive contents must not be scanned: {findings:?}"
    );
}

#[test]
fn entry_beyond_the_per_entry_cap_is_not_scanned() {
    let dir = tempfile::tempdir().unwrap();
    // One repetitive (well compressing) entry larger than the 1 KiB
    // cap used below, with the planted key on its second line. The
    // archive file itself compresses under the cap, so it is opened,
    // but the oversized entry's content is never extracted.
    let mut content = vec![b'x'; 1500];
    content.push(b'\n');
    content.extend_from_slice(AWS_LINE.as_bytes());
    let zip = zip_bytes(&[("big.txt", &content)]);
    assert!(zip.len() <= 1024, "fixture zip must fit the cap");
    write(dir.path(), "capped.zip", &zip);
    let (findings, stats) = scan_with(dir.path(), 1024);
    assert_eq!(stats.files_scanned, 1);
    assert!(
        findings.iter().all(|f| f.rule_id != "SS001"),
        "oversized entry must not be scanned: {findings:?}"
    );
}
