# Changelog

## v1.1.0

Driven by a real find: a malicious repository whose payload (a
launcher script, a bundled executable, and a disguised script file)
sat inside a zip that v1.0 skipped as an opaque binary.

- Zip archive inspection in worktree mode. Text entries are scanned
  with the normal rule engine and reported as
  `archive.zip!/entry-name`. A structural warning (ARCHIVE-EXEC)
  fires when an archive pairs an executable with a launcher or
  script file, or with a large single-line text file. Corrupt or
  encrypted archives are reported as uninspectable
  (ARCHIVE-UNREADABLE) instead of failing the scan. Caps: 512
  entries, the `--max-size` cap per entry, 16 times that per
  archive. One level deep; only ZIP is inspected.
- New pattern rules (99 total, up from 94):
  - SS095 auth.gg application secret or API key near an auth.gg
    reference.
  - SS096 Ethereum address and SS097 Bitcoin address, Low severity
    and informational, so a hardcoded payout address is classified
    instead of surfacing only as entropy noise.
  - SS098 private-key persistence: code that writes private key
    material, a seed phrase or a mnemonic to a file (same-line
    heuristic).
  - SS099 download links to archives on file-hosting services
    frequently abused for malware lures, including
    password-protected archive campaigns.
- One new dependency: the `zip` crate, with only the deflate
  feature enabled.
- 177 tests (up from 152).

What v1.1 still cannot do: judge the intent of an encrypted
payload whose strings decrypt only at runtime, inspect encrypted
archives, open archives nested inside other archives, or inspect
non-ZIP archive formats.

## v1.0.0

- Initial release: 94 pattern rules, Shannon entropy heuristic,
  worktree and git history scanning, baselines, allowlists, and
  text, JSON and SARIF reports. 152 tests.
