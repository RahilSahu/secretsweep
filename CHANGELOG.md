# Changelog

## v1.2.0

Driven by a second hunt, through fake cheat and airdrop lure repos:
nine more malicious repositories across five campaigns, including a
GitHub Pages redirector kit shared by a crypto claimer and an Adobe
impersonation. This release teaches the scanner the delivery-side
patterns that hunt exposed.

- New structural check: REDIRECTOR (High). Fires when a single HTML
  or JavaScript file combines all three signals of the
  remote-config redirector kit: a fetch() call with a literal URL
  or an XMLHttpRequest being opened, an atob() base64 decode, and a
  location redirect assignment (window.location, location.href,
  location.replace). One or two signals never fire. The check runs
  on loose files and on HTML and JavaScript entries inside zip
  archives, and is covered end to end by a synthetic kit fixture in
  the test suite.
- SS099 extended. File-host lure links now also match
  direct-download paths with no archive extension (/file/,
  /directdownload/, /download/ segments and download query
  parameters), and URL shorteners (cutt.ly, bit.ly, tinyurl.com,
  rb.gy) match when the same line also carries a download signal:
  the words download, installer or setup, or an archive extension.
  A bare shortener link still does not fire.
- Oversize archives are no longer skipped silently. A zip over the
  scan size cap now produces an ARCHIVE-UNREADABLE info finding
  stating it was not inspected due to size; the oversize skip
  counter still records the skip. Wave 2 of the hunt missed a
  packed cheat bundle exactly this way.
- New pattern rule (100 total, up from 99): SS100 (Medium)
  antivirus-disable instruction: text or markdown lines telling the
  reader to disable Defender, turn off real-time protection,
  switch off Windows Security or disable their antivirus. Mentions
  in a detection context ("detected by Windows Defender") do not
  fire.
- 197 tests (up from 177).

What v1.2 still cannot do: judge the intent of an encrypted
payload whose strings decrypt only at runtime, follow a
redirector or fetch its remote config to see where it leads,
inspect encrypted archives, open archives nested inside other
archives, or inspect non-ZIP archive formats.

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
