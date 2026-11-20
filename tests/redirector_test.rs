//! End-to-end tests for the remote-config redirector check:
//! the synthetic kit fixture must be flagged by a real worktree
//! scan, partial-signal pages must not be, and the check must
//! also fire for an HTML entry inside a zip archive.
//!
//! The fixture is written for this test suite. Its config URL
//! uses the reserved example.net domain; it is not a real lure.

use secretsweep::rules::REDIRECTOR_RULE_ID;
use secretsweep::scanline::LineScanner;
use secretsweep::scanner::{scan_path, ScanOptions};
use std::fs;
use std::io::Write;
use std::path::Path;
use zip::write::SimpleFileOptions;

const KIT_PAGE: &str = r#"<!DOCTYPE html>
<html><head><title>Cloud Files</title></head><body>
<p id="loader-text">Preparing your download...</p>
<script>
  const res = await fetch('https://config.example.net/settings.json');
  const data = await res.json();
  const url = atob(data.c);
  window.location.href = url;
</script>
</body></html>
"#;

const FETCH_AND_ATOB_ONLY: &str = r#"<script>
  const res = await fetch('https://api.example.net/data.json');
  document.title = atob('aGVsbG8=');
</script>
"#;

fn write(root: &Path, rel: &str, content: &[u8]) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn scan(root: &Path) -> Vec<secretsweep::finding::Finding> {
    scan_path(root, &LineScanner::default(), &ScanOptions::default())
        .unwrap()
        .0
}

#[test]
fn kit_page_is_flagged_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "site/index.html", KIT_PAGE.as_bytes());
    let findings = scan(dir.path());
    let f = findings
        .iter()
        .find(|f| f.rule_id == REDIRECTOR_RULE_ID)
        .expect("the kit page must produce a REDIRECTOR finding");
    assert!(f.file.ends_with("site/index.html"), "file: {}", f.file);
    assert!(f.description.contains("fetch or XHR"));
    assert!(f.description.contains("atob()"));
    assert!(f.description.contains("location redirect"));
}

#[test]
fn partial_signal_page_is_not_flagged() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "page.html", FETCH_AND_ATOB_ONLY.as_bytes());
    let findings = scan(dir.path());
    assert!(
        findings.iter().all(|f| f.rule_id != REDIRECTOR_RULE_ID),
        "two of three signals must not fire: {findings:?}"
    );
}

#[test]
fn kit_markup_in_a_non_web_file_is_not_flagged() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "notes.txt", KIT_PAGE.as_bytes());
    write(dir.path(), "main.rs", KIT_PAGE.as_bytes());
    let findings = scan(dir.path());
    assert!(
        findings.iter().all(|f| f.rule_id != REDIRECTOR_RULE_ID),
        "the check applies to HTML and JavaScript files only: {findings:?}"
    );
}

#[test]
fn kit_page_inside_a_zip_is_flagged() {
    let dir = tempfile::tempdir().unwrap();
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buf);
        writer
            .start_file("portal/index.html", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(KIT_PAGE.as_bytes()).unwrap();
        writer.finish().unwrap();
    }
    write(dir.path(), "bundle.zip", &buf.into_inner());
    let findings = scan(dir.path());
    let f = findings
        .iter()
        .find(|f| f.rule_id == REDIRECTOR_RULE_ID)
        .expect("the kit page inside a zip must be flagged");
    assert!(
        f.file.ends_with("bundle.zip!/portal/index.html"),
        "file: {}",
        f.file
    );
}
