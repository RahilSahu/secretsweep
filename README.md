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

- **100 pattern rules** for known providers and formats (AWS, GitHub,
  Stripe, OpenAI, database connection strings, private key blocks, and
  many more), each with a severity and a plain-language description.
- **Zip archive inspection**: archives are opened, not skipped as
  opaque binaries. Text entries are scanned with the normal rules
  (findings point at `archive.zip!/entry-name`), and an archive that
  pairs an executable with a launcher or script file raises a
  dedicated warning. That pairing is how a real malware lure hid its
  payload from the v1.0 scanner.
- **Malware lure indicators**: structural checks beyond secrets. A
  REDIRECTOR warning fires when one HTML or JavaScript file combines
  a fetch or XHR request, an `atob()` decode and a location redirect;
  a rule flags instructions to disable antivirus protection; and link
  checks cover file-host and shortener download lures.
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
cargo install --git https://github.com/RahilSahu/secretsweep --tag v1.2.0
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
Zip archives are the one binary-looking exception: they are opened and
inspected as described below, because an opaque archive is exactly
where a payload can hide from a line-based scanner.

Git history mode shells out to `git log -p` and scans the lines each
commit added. It needs `git` on the PATH. Merge commits produce no diff
in `git log -p` output and are not covered; secrets that entered through
a merge are found in the branch commits that introduced them.

### Rules

The registry holds 100 pattern rules. Run `secretsweep --list-rules` for
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
| Other platforms (Shopify, Heroku, Cloudflare, Vault, Grafana, auth.gg, and more) | 18 |
| Cryptocurrency addresses (informational, Low severity) | 2 |
| Malware indicators (private-key persistence, file-host lure links, antivirus-disable instructions) | 3 |
| **Total** | **100** |

Rules are line-based regular expressions (the Rust `regex` engine, so no
lookahead). Each rule reports the line and column of the secret value.

### Archive inspection

Zip archives (detected by `.zip` extension or by their PK header) are
opened instead of skipped. This exists because a real malware lure
found in the wild hid everything that mattered inside a zip: a
launcher script, a bundled executable, and a script payload disguised
as a text file. A scanner that treats archives as opaque binaries
sees none of that.

What happens inside an archive:

- Text-like entries are scanned with the same pattern and entropy
  rules as loose files. Findings are reported with paths like
  `bundle.zip!/inner/config.txt`, so the entry can be located.
- A structural warning (rule id `ARCHIVE-EXEC`) fires when an archive
  contains an executable file (`.exe`, `.dll`, `.scr`, `.com`,
  `.msi`, `.sys`) together with a launcher or script file (`.cmd`,
  `.bat`, `.ps1`, `.vbs`, `.js` and relatives), or with a large
  single-line text file of 50 KB or more, a common disguised-script
  shape. Archives of documents or source code, with no executable
  inside, do not trigger it.
- An archive that cannot be opened, or whose entries cannot be read
  (corrupt, encrypted, or an unsupported compression method), is
  reported once as uninspectable (rule id `ARCHIVE-UNREADABLE`, Low
  severity) instead of failing the scan. An archive that is itself
  over the scan size cap gets the same finding, stating that it was
  not inspected due to size, instead of the silent skip earlier
  versions made.

Safety caps, so a hostile or accidental zip bomb cannot exhaust
memory: at most 512 entries are examined, at most the `--max-size`
cap (1 MiB by default) is extracted per entry, and at most 16 times
that across one archive. Entries are read in memory only; nothing is
written to disk and nothing is executed.

Inspection is one level deep: a zip stored inside another zip is
listed but not opened, and only the ZIP format is inspected. Other
archive formats (`.tar`, `.7z`, `.rar`, and similar) are still
skipped as binary files for now.

### Lure and redirector detection

Three checks target the delivery side of malware lure repos rather
than secrets. All three came out of a November 2026 hunt through
fake cheat and airdrop repos:

- `REDIRECTOR` (High) fires when a single HTML or JavaScript file
  combines all three signals of the remote-config redirector kit
  seen in two campaigns, one of them impersonating Adobe: a
  `fetch()` call with a literal URL (or an `XMLHttpRequest` being
  opened), an `atob()` base64 decode, and a location redirect
  assignment (`window.location`, `location.href`,
  `location.replace`). The kit fetches its real destination from a
  config file on another account, so the lure page itself contains
  no malicious URL to match. One or two signals never fire; each is
  common in legitimate pages. The check also runs on HTML and
  JavaScript entries inside zip archives.
- `SS099` (Low) flags download links on file-hosting services
  frequently abused for lures (4sync, anonfiles, bayfiles,
  sendspace, zippyshare), including direct-download paths such as
  `/file/` and `/directdownload/` and `download` query parameters
  with no archive extension, and URL shorteners (cutt.ly, bit.ly,
  tinyurl.com, rb.gy) when the same line also carries a download
  signal: the words download, installer or setup, or an archive
  extension. A bare shortener link does not fire.
- `SS100` (Medium) flags instructions to disable antivirus
  protection ("disable Defender", "turn off real-time protection",
  "switch off Windows Security", "disable your antivirus"), the
  standard coaching line in lure install guides. Mentions in a
  detection context ("detected by Windows Defender") do not fire.

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
        run: cargo install --git https://github.com/RahilSahu/secretsweep --tag v1.2.0
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
  rev: v1.2.0
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
  counted in the summary line. Zip archives are inspected instead of
  skipped, within the caps described above.
- Archive inspection covers ZIP only, one level deep. Encrypted
  archives and encrypted entries cannot be read and are reported as
  uninspectable; their contents are not scanned, and no scanner can
  judge the intent of a payload whose strings only decrypt at
  runtime.
- Git history mode does not cover merge commits (see above) and needs
  the `git` CLI installed. Archives committed to history are not
  opened in this mode; history mode scans the text lines each commit
  added.
- The redirector check reads one file at a time and never fetches
  anything: it cannot follow a redirector, download its remote
  config, or judge where the redirect leads, and a kit split across
  several files will not fire it.
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
