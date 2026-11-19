//! Command line interface and top-level run logic.
//!
//! Exit codes:
//! - 0: no findings at or above the `--fail-on` severity
//! - 1: findings at or above the `--fail-on` severity
//! - 2: usage or runtime error (clap also exits 2 for bad arguments)

use crate::baseline::Baseline;
use crate::config::{self, Config};
use crate::entropy::DEFAULT_THRESHOLD;
use crate::finding::Severity;
use crate::git_scan;
use crate::report::{self, ReportData};
use crate::rules;
use crate::scanline::LineScanner;
use crate::scanner::{self, ScanOptions, ScanStats};
use clap::{Parser, ValueEnum};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Parser, Debug)]
#[command(
    name = "secretsweep",
    version,
    about = "Offline secrets scanner for repositories and CI",
    long_about = "SecretSweep scans a directory tree (or a repository's git history) for leaked credentials: provider pattern rules, entropy detection, baselines, allowlists, and text, JSON or SARIF reports. Nothing it scans ever leaves your machine."
)]
struct Args {
    /// File or directory to scan (repository root in --git mode)
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Scan git history instead of the worktree (needs the git CLI)
    #[arg(long)]
    git: bool,

    /// Report format
    #[arg(long, value_enum, default_value = "text")]
    format: Format,

    /// Lowest severity that makes the exit code 1
    #[arg(long, value_parser = ["low", "medium", "high", "critical"], default_value = "high")]
    fail_on: String,

    /// Baseline file: if it exists, known findings are suppressed;
    /// if it does not, it is created from this run's findings
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Config file (default: .secretsweep.toml in the scanned root
    /// or the current directory)
    #[arg(long)]
    config: Option<PathBuf>,

    /// Entropy threshold for base64-style strings (hex strings use a
    /// lower derived threshold). Overrides the config file value.
    #[arg(long)]
    entropy_threshold: Option<f64>,

    /// Disable entropy detection (pattern rules only)
    #[arg(long)]
    no_entropy: bool,

    /// Skip files larger than this many KiB
    #[arg(long, default_value_t = 1024)]
    max_size: u64,

    /// List every pattern rule and exit
    #[arg(long)]
    list_rules: bool,
}

fn error_exit(message: &str) -> i32 {
    eprintln!("secretsweep: error: {message}");
    2
}

fn find_config_file(explicit: &Option<PathBuf>, root: &Path) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.clone());
    }
    let in_root = root.join(".secretsweep.toml");
    if in_root.exists() {
        return Some(in_root);
    }
    let in_cwd = PathBuf::from(".secretsweep.toml");
    if in_cwd.exists() {
        return Some(in_cwd);
    }
    None
}

fn print_rules() {
    println!(
        "{:<7} {:<38} {:<18} {:<9} DESCRIPTION",
        "ID", "NAME", "PROVIDER", "SEVERITY"
    );
    for r in rules::rules() {
        println!(
            "{:<7} {:<38} {:<18} {:<9} {}",
            r.id,
            r.name,
            r.provider,
            r.severity.as_str(),
            r.description
        );
    }
    println!(
        "{} pattern rules, plus the {} heuristic entropy rule (id {})",
        rules::rules().len(),
        rules::ENTROPY_RULE_NAME,
        rules::ENTROPY_RULE_ID
    );
    println!(
        "Plus structural zip archive checks: {} ({}) and {} ({})",
        rules::ARCHIVE_EXEC_RULE_NAME,
        rules::ARCHIVE_EXEC_RULE_ID,
        rules::ARCHIVE_UNREADABLE_RULE_NAME,
        rules::ARCHIVE_UNREADABLE_RULE_ID
    );
}

pub fn run() -> i32 {
    let args = Args::parse();

    if args.list_rules {
        print_rules();
        return 0;
    }

    let fail_on = Severity::parse(&args.fail_on).unwrap_or(Severity::High);

    // Config.
    let mut cfg = Config::default();
    if let Some(cfg_path) = find_config_file(&args.config, &args.path) {
        match config::load_config(&cfg_path) {
            Ok(c) => cfg = c,
            Err(e) => return error_exit(&e),
        }
    }

    let threshold = args
        .entropy_threshold
        .or(cfg.entropy_threshold)
        .unwrap_or(DEFAULT_THRESHOLD);
    let line_scanner = LineScanner {
        entropy_enabled: !args.no_entropy,
        entropy_threshold: threshold,
    };

    // Baseline: load now if present, create after scanning if absent.
    let mut baseline_keys = None;
    let mut baseline_create_path: Option<PathBuf> = None;
    if let Some(bp) = &args.baseline {
        if bp.exists() {
            match Baseline::load(bp) {
                Ok(b) => baseline_keys = Some(b.key_set()),
                Err(e) => return error_exit(&e),
            }
        } else {
            baseline_create_path = Some(bp.clone());
        }
    }

    // Scan.
    let (all_findings, stats): (Vec<_>, Option<ScanStats>) = if args.git {
        match git_scan::scan_git_history(&args.path, &line_scanner) {
            Ok(result) => {
                if !result.has_commits {
                    eprintln!(
                        "secretsweep: note: repository at {} has no commits yet, nothing to scan",
                        args.path.display()
                    );
                }
                (result.findings, None)
            }
            Err(e) => return error_exit(&e),
        }
    } else {
        let opts = ScanOptions {
            max_bytes: args.max_size * 1024,
        };
        match scanner::scan_path(&args.path, &line_scanner, &opts) {
            Ok((findings, stats)) => (findings, Some(stats)),
            Err(e) => return error_exit(&e),
        }
    };

    // Suppression: allowlist first, then baseline.
    let mut suppressed = 0usize;
    let mut reported = Vec::new();
    for f in all_findings {
        if cfg.allows(&f) {
            suppressed += 1;
            continue;
        }
        if let Some(keys) = &baseline_keys {
            if Baseline::contains_raw(keys, &f) {
                suppressed += 1;
                continue;
            }
        }
        reported.push(f);
    }

    // Create a baseline from everything that would have been reported.
    if let Some(bp) = &baseline_create_path {
        let baseline = Baseline::from_findings(&reported);
        match baseline.save(bp) {
            Ok(()) => eprintln!(
                "secretsweep: wrote baseline with {} entries to {}",
                baseline.entries.len(),
                bp.display()
            ),
            Err(e) => return error_exit(&e),
        }
    }

    let data = ReportData {
        findings: &reported,
        suppressed,
        stats: stats.as_ref(),
    };
    match args.format {
        Format::Text => print!("{}", report::render_text(&data)),
        Format::Json => print!("{}", report::render_json(&data)),
        Format::Sarif => print!("{}", report::render_sarif(&data)),
    }

    if reported.iter().any(|f| f.severity >= fail_on) {
        1
    } else {
        0
    }
}
