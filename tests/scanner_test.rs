//! Worktree scanner integration tests on temporary directory trees.

use secretsweep::scanline::LineScanner;
use secretsweep::scanner::{scan_path, ScanOptions};
use std::fs;
use std::path::Path;

const AWS_LINE: &str = "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"";

fn write(root: &Path, rel: &str, content: &[u8]) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn scan(
    root: &Path,
) -> (
    Vec<secretsweep::finding::Finding>,
    secretsweep::scanner::ScanStats,
) {
    scan_path(root, &LineScanner::default(), &ScanOptions::default()).unwrap()
}

#[test]
fn finds_secret_in_nested_directories_with_correct_location() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "a/b/c/config.py",
        format!("line one\nline two\n{AWS_LINE}\n").as_bytes(),
    );
    let (findings, stats) = scan(dir.path());
    assert_eq!(stats.files_scanned, 1);
    let f = findings.iter().find(|f| f.rule_id == "SS001").unwrap();
    assert!(f.file.ends_with("a/b/c/config.py"), "file: {}", f.file);
    assert_eq!(f.line, 3);
    assert_eq!(f.preview, "AKIA...");
}

#[test]
fn gitignored_files_are_not_scanned() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".gitignore", b"*.log\n");
    write(dir.path(), "debug.log", AWS_LINE.as_bytes());
    write(dir.path(), "kept.py", b"clean = True\n");
    let (findings, _) = scan(dir.path());
    assert!(
        findings.iter().all(|f| f.rule_id != "SS001"),
        "gitignored file must not be scanned: {findings:?}"
    );
}

#[test]
fn binary_files_are_skipped_and_counted() {
    let dir = tempfile::tempdir().unwrap();
    let mut blob = vec![0x7f, b'E', b'L', b'F', 0x00, 0x02];
    blob.extend_from_slice(AWS_LINE.as_bytes());
    write(dir.path(), "blob.bin", &blob);
    let (findings, stats) = scan(dir.path());
    assert_eq!(stats.files_skipped_binary, 1);
    assert!(findings.is_empty());
}

#[test]
fn oversize_files_are_skipped_and_counted() {
    let dir = tempfile::tempdir().unwrap();
    let big = format!("{}\n{}", "x".repeat(500), AWS_LINE);
    write(dir.path(), "big.txt", big.as_bytes());
    let opts = ScanOptions { max_bytes: 128 };
    let (findings, stats) = scan_path(dir.path(), &LineScanner::default(), &opts).unwrap();
    assert_eq!(stats.files_skipped_oversize, 1);
    assert!(findings.is_empty());
}

fn make_zip_bytes() -> Vec<u8> {
    use std::io::Write as _;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buf);
        writer
            .start_file("payload.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"harmless filler text\n").unwrap();
        writer.finish().unwrap();
    }
    buf.into_inner()
}

#[test]
fn oversize_zip_is_reported_uninspectable_not_silent() {
    // Wave 2 of the 2026-11-20 hunt missed a packed cheat bundle
    // because the archive was over the size cap and skipped
    // silently. It must now surface as ARCHIVE-UNREADABLE while
    // the oversize skip counter still records the skip.
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "bundle.zip", &make_zip_bytes());
    let opts = ScanOptions { max_bytes: 32 };
    let (findings, stats) = scan_path(dir.path(), &LineScanner::default(), &opts).unwrap();
    assert_eq!(stats.files_skipped_oversize, 1);
    let f = findings
        .iter()
        .find(|f| f.rule_id == "ARCHIVE-UNREADABLE")
        .expect("an oversize zip must produce an uninspectable finding");
    assert!(
        f.description.contains("not inspected due to size"),
        "description: {}",
        f.description
    );
}

#[test]
fn oversize_non_archive_stays_silent() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "blob.bin", b"0123456789abcdef");
    let opts = ScanOptions { max_bytes: 8 };
    let (findings, stats) = scan_path(dir.path(), &LineScanner::default(), &opts).unwrap();
    assert_eq!(stats.files_skipped_oversize, 1);
    assert!(findings.is_empty());
}

#[test]
fn dependency_and_vcs_directories_are_skipped() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "node_modules/pkg/index.js", AWS_LINE.as_bytes());
    write(dir.path(), "vendor/lib/code.py", AWS_LINE.as_bytes());
    write(dir.path(), ".git/config", AWS_LINE.as_bytes());
    write(dir.path(), "src/app.py", b"clean = True\n");
    let (findings, stats) = scan(dir.path());
    assert_eq!(stats.files_scanned, 1, "only src/app.py should be scanned");
    assert!(findings.is_empty());
}

#[test]
fn lockfiles_and_dotenv_files_are_scanned() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package-lock.json",
        concat!(
            "{\"dependencies\": {\"x\": {\"resolved\": \"https://registry.npmjs.org\", \"token\": \"npm_",
            "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
            "\"}}}"
        )
        .as_bytes(),
    );
    write(dir.path(), ".env", AWS_LINE.as_bytes());
    let (findings, _) = scan(dir.path());
    assert!(
        findings.iter().any(|f| f.rule_id == "SS042"),
        "lockfile token: {findings:?}"
    );
    assert!(
        findings.iter().any(|f| f.rule_id == "SS001"),
        "dotenv key: {findings:?}"
    );
}

#[test]
fn scanning_a_single_file_works() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("one.txt");
    fs::write(&file, AWS_LINE).unwrap();
    let (findings, stats) = scan(&file);
    assert_eq!(stats.files_scanned, 1);
    assert!(findings.iter().any(|f| f.rule_id == "SS001"));
}

#[test]
fn nonexistent_path_is_an_error() {
    let result = scan_path(
        Path::new("/definitely/not/here/secretsweep"),
        &LineScanner::default(),
        &ScanOptions::default(),
    );
    assert!(result.is_err());
}
