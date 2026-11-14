# SecretSweep

[![CI](https://github.com/RahilSahu/secretsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/RahilSahu/secretsweep/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/RahilSahu/secretsweep)](https://github.com/RahilSahu/secretsweep/releases)

SecretSweep is an offline secrets scanner for repositories and CI. It scans
a directory tree, or a repository's entire git history, for leaked
credentials: cloud keys, API tokens, private keys, database passwords and
more.

Leaked keys are one of the most common ways companies get breached. A key
committed to git stays in history even after the line is deleted, and it
only takes one public push, one shared archive or one over-permissioned
clone for it to be found. SecretSweep is built to catch the key before it
ships, and to find the ones that were committed long ago.

It never phones home and never sends scanned content anywhere. Reports
never print a full secret: findings carry at most the first four
characters of a value, plus a hash fingerprint.

## What it does

- **94 pattern rules** for known providers and formats (AWS, GitHub,
  Stripe, OpenAI, database connection strings, private key blocks, and
  many more), each with a severity and a plain-language description.
- **Entropy detection**: a second, heuristic engine that measures the
  Shannon entropy of candidate strings (quoted literals and assignment
  values) and flags likely random secrets that no pattern knows about.
- **Git history mode** (`--git`): scans every commit reachable from any
  ref, so secrets that were committed and later "removed" are still
  found, with the commit hash attached.
- **Baselines**: snapshot today's known findings into a JSON file (hashes
  only, no secret values) and suppress exactly those in later runs, so a
  team can adopt the scanner on a messy repo and only fail on new leaks.
- **Allowlist** in `.secretsweep.toml`, by rule id, path glob or
  fingerprint, for documented examples and test fixtures.
- **Reports** in text, JSON and SARIF 2.1.0 (uploads cleanly to GitHub
  code scanning). CI-friendly exit codes.

## Install

You need a recent stable Rust toolchain (via [rustup](https://rustup.rs))
and, for history mode, the `git` CLI.

Install from source:

```console
cargo install --git https://github.com/RahilSahu/secretsweep --tag v1.0.0
```

Or build a checkout:

```console
git clone https://github.com/RahilSahu/secretsweep.git
cd secretsweep
cargo build --release
# binary lands in target/release/secretsweep
```

## Usage

```console
secretsweep                     # scan the current directory
secretsweep path/to/tree        # scan one file or directory tree
secretsweep --git .             # scan the git history of a repository
secretsweep --format json .     # machine-readable report
secretsweep --format sarif . > secretsweep.sarif
secretsweep --fail-on medium .  # fail on medium and above (default: high)
secretsweep --list-rules        # print every rule in the registry
```

One path per run: to cover several trees, run it once per tree or pass
their common parent.

Example output, using the AWS documentation example key:

```text
config.py:2:22: [HIGH] SS001 (AWS) AWS access key ID (long-lived IAM user key) (preview: AKIA...)
Scanned 2 files (0 binary skipped, 0 oversize skipped): 1 findings
```

### How scanning works

Worktree mode respects `.gitignore`, skips `.git`, `node_modules`,
`vendor`, `target` and similar generated directories, skips binary files
and files over 1 MiB (configurable with `--max-size`, in KiB), and scans
everything else as text, including lockfiles and dotfiles such as `.env`.

Git history mode shells out to `git log -p` and scans the lines each
commit added. It needs `git` on the PATH. Merge commits produce no diff
in `git log -p` output and are not covered; secrets that entered through
a merge are found in the branch commits that introduced them.

### Rules

The registry holds 94 pattern rules. Run `secretsweep --list-rules` for
the full table. Summary by area:

| Area | Rules |
| --- | --- |
| Cloud providers (AWS, GCP, Azure) | 12 |
| Code hosting (GitHub, GitLab) | 9 |
| Payments (Stripe, Square) | 6 |
| AI APIs (OpenAI, Anthropic, Hugging Face, Replicate) | 8 |
| Messaging and email (Slack, Discord, Telegram, Facebook, Twilio, SendGrid, Mailgun, Mailchimp, Firebase) | 15 |
| Package registries (npm, PyPI, Docker Hub) | 4 |
| Database connection strings | 7 |
| Private key blocks | 7 |
| Tokens, headers and generic assignments | 9 |
| Other platforms (Shopify, Heroku, Cloudflare, Vault, Grafana, and more) | 17 |
| **Total** | **94** |

Rules are line-based regular expressions (the Rust `regex` engine, so no
lookahead). Each rule reports the line and column of the secret value.

### Entropy detection, honestly

Pattern rules only catch secrets that look like something known. The
entropy engine looks at quoted strings and assignment values, ignores
obvious non-secrets (UUIDs, `sha512-...` integrity hashes, placeholder
text like `your-api-key-here`), and flags strings whose Shannon entropy
is above a charset-aware threshold: 4.5 bits per character by default
for base64-style strings, 3.6 for hex, with a 0.4 allowance when the
value is assigned to a secret-sounding key (`password`, `token`,
`api_key`, and friends). Tune it with `--entropy-threshold` or turn the
engine off with `--no-entropy`.

Entropy is a heuristic, not a proof. Random identifiers, hashes and
compressed data can look exactly like secrets, and a weak password can
look like plain English. Treat entropy findings as "worth a human
look", use the baseline to record the ones you have reviewed, and do not
treat a clean entropy result as a guarantee that nothing leaked.

### Baselines

```console
secretsweep --baseline secretsweep-baseline.json .
```

If the baseline file does not exist, the run writes it from the current
findings (rule id, file, and a SHA-256 fingerprint of the secret value;
the value itself is never stored) and still reports and fails as usual.
On later runs, findings in the baseline are suppressed and only new
leaks are reported. The baseline file is safe to commit.

### Allowlist

Create `.secretsweep.toml` in the scanned root (or pass `--config`):

```toml
entropy_threshold = 4.8

[[allowlist]]
rule = "SS065"            # suppress a rule everywhere

[[allowlist]]
path = "tests/**"         # suppress findings under a path glob

[[allowlist]]
fingerprint = "0123abcd..."  # suppress one exact finding
```

An entry suppresses a finding when every field it sets matches.

## Use in CI

GitHub Actions, with results uploaded to code scanning:

```yaml
name: secrets
on: [push, pull_request]
jobs:
  secretsweep:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history if you also scan with --git
      - uses: dtolnay/rust-toolchain@stable
      - name: Install SecretSweep
        run: cargo install --git https://github.com/RahilSahu/secretsweep --tag v1.0.0
      - name: Scan worktree
        run: secretsweep --format sarif --fail-on high . > secretsweep.sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: secretsweep.sarif
```

## Pre-commit

This repository ships a hook for the
[pre-commit](https://pre-commit.com) framework (`.pre-commit-hooks.yaml`)
and a plain git hook at [examples/pre-commit](examples/pre-commit).
Framework setup:

```yaml
# .pre-commit-config.yaml in your project
- repo: https://github.com/RahilSahu/secretsweep
  rev: v1.0.0
  hooks:
    - id: secretsweep
```

The hook assumes the `secretsweep` binary is on your PATH (see Install).
The plain hook is a small shell script you copy to `.git/hooks/pre-commit`;
it scans the worktree and blocks the commit when a finding at or above
the fail-on severity exists.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No findings at or above the `--fail-on` severity |
| 1 | Findings at or above the `--fail-on` severity (default: high) |
| 2 | Usage or runtime error (bad arguments, unreadable path, not a git repository in `--git` mode, invalid config or baseline) |

## Limitations

- Line-based scanning: a secret split across two lines is not detected.
- Worktree mode skips binary files and files over the size cap; both are
  counted in the summary line.
- Git history mode does not cover merge commits (see above) and needs
  the `git` CLI installed.
- In git history mode, file paths that git quotes (paths with unusual
  characters) may be displayed with their quotes.

## Roadmap

- `--staged` mode that scans only the index, for faster pre-commit runs.
- Rules for more providers, driven by real-world reports.
- A `--redact` mode that rewrites files with findings replaced by
  placeholders, for cleaning fixtures and documentation.
- Optional parallel walking for very large trees.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New rules are welcome; every rule
needs positive and negative tests, and fixtures must use publicly
documented example credentials or synthetic strings.

## License

MIT, see [LICENSE](LICENSE).
