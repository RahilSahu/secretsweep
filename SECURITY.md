# Security policy

## Reporting a vulnerability

Please report security issues privately instead of opening a public
issue. Use GitHub's private vulnerability reporting on this repository
(the "Report a vulnerability" button under the Security tab), or email
rahilsahu.jobs@gmail.com.

Expect an acknowledgement within a few days. Fixes for confirmed issues
ship in a patch release, and the reporter is credited in the release
notes unless they prefer otherwise.

## Security model of the tool itself

SecretSweep is a defensive scanner. Keep these properties in mind when
assessing it:

- It runs fully offline and makes no network requests.
- It never prints a full secret. Reports contain a redacted preview (at
  most the first four characters) and a SHA-256 fingerprint of rule id
  plus value, so findings can be tracked and baselined without storing
  the credential.
- Baselines likewise store only fingerprints, never values, and are
  safe to commit.
- Git history mode executes the locally installed `git` binary with a
  fixed argument list (no shell), reading the repository you point it
  at.

A finding from SecretSweep means "this string looks like a credential
and is in your tree or history". Treat it as compromised if it is real:
rotate it, then remove it from history; deleting the line alone does
not remove it from git.
