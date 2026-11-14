# Contributing to SecretSweep

Thanks for your interest. Contributions of new rules, bug fixes and
documentation are welcome.

## Development setup

You need a stable Rust toolchain (via [rustup](https://rustup.rs)) and
git. Then:

```console
git clone https://github.com/RahilSahu/secretsweep.git
cd secretsweep
cargo build
cargo test
```

Before opening a pull request, all three of these must pass (CI runs
the same):

```console
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Adding a rule

1. Add an entry to the `RULES` table in `src/rules.rs`. Keep the ids
   sequential (`SS001`, `SS002`, ...). Each rule has a name, provider,
   severity, a plain-language description, and a pattern. The `regex`
   crate has no lookahead or backreferences; carry context inside the
   pattern and expose the secret value through a named capture group
   called `secret` when the pattern is not just the token itself.
2. Add a positive and a negative test for it in `tests/rules_test.rs`
   with the `rule_case!` macro.
3. Fixtures are strict: use publicly documented example credentials
   (such as the AWS documentation example key) or synthetic strings
   assembled from fragments with `concat!`. Never commit a real
   credential, and never write a complete real-looking token as a
   single literal; GitHub push protection will (rightly) block it.

Set `filter_placeholders: true` on rules whose value format is loose
(assignment-style rules), so documentation placeholders such as
`your-api-key-here` do not fire.

## Changing detection behaviour

- Pattern or entropy changes belong in `src/rules.rs`, `src/entropy.rs`
  or `src/scanline.rs`, and need tests in `tests/` that show the new
  behaviour and one case that should not fire.
- Report changes belong in `src/report.rs`. Every format must keep the
  guarantee that a full secret value never appears in output; the
  report tests assert this, keep them green.

## Commits and pull requests

- Small, focused commits with a plain summary line.
- Describe what changed and how you tested it in the pull request.
- By contributing you agree your work is licensed under the MIT license
  in [LICENSE](LICENSE).
