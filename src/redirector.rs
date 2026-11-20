//! Structural check: remote-config redirector pages.
//!
//! Wave 2 of the 2026-11-20 hunt found the same GitHub Pages kit in
//! two campaigns (a crypto claimer and an Adobe impersonation): a
//! fake "Secure download portal" that fetches a small JSON config
//! hosted on a different account, base64-decodes one field with
//! `atob()`, and redirects the visitor to whatever it says. The
//! destination can be swapped at any time without touching the
//! lure page, which is the point of the design.
//!
//! No single signal is damning: plenty of legitimate pages fetch
//! data, decode base64, or redirect. The conjunction of all three
//! in one file is the kit signature, so this check fires only when
//! a single HTML or JavaScript file contains all of:
//!
//! 1. a `fetch()` call with a literal URL, or an `XMLHttpRequest`
//!    being opened;
//! 2. an `atob()` base64 decode;
//! 3. a redirect assignment (`window.location`, `location.href`,
//!    a bare `location = ...`, `location.replace()` or
//!    `location.assign()`).
//!
//! The check is a heuristic over one file's text. It does not
//! follow the redirect, fetch the remote config, or judge where
//! the redirect leads.

use crate::finding::{fingerprint, Finding, FindingKind, Severity};
use crate::rules::{REDIRECTOR_PROVIDER, REDIRECTOR_RULE_ID};
use regex::Regex;
use std::sync::OnceLock;

/// Extensions whose files are eligible for the redirector check:
/// the kit ships as HTML pages and standalone scripts.
const WEB_EXTS: &[&str] = &["html", "htm", "js", "mjs", "cjs"];

/// True when `name` (a path or archive entry name) ends in an HTML
/// or JavaScript extension.
pub fn is_web_file(name: &str) -> bool {
    let ext = name
        .rsplit('.')
        .next()
        .filter(|e| !e.is_empty() && !e.contains('/'))
        .unwrap_or("")
        .to_ascii_lowercase();
    WEB_EXTS.contains(&ext.as_str())
}

static FETCH_LITERAL_RE: OnceLock<Regex> = OnceLock::new();
static XHR_RE: OnceLock<Regex> = OnceLock::new();
static XHR_OPEN_RE: OnceLock<Regex> = OnceLock::new();
static ATOB_RE: OnceLock<Regex> = OnceLock::new();
static REDIRECT_RE: OnceLock<Regex> = OnceLock::new();

fn fetch_literal_re() -> &'static Regex {
    FETCH_LITERAL_RE.get_or_init(|| Regex::new(r#"(?i)\bfetch\s*\(\s*['"`]"#).expect("valid regex"))
}

fn xhr_re() -> &'static Regex {
    XHR_RE.get_or_init(|| Regex::new(r"(?i)\bXMLHttpRequest\b").expect("valid regex"))
}

fn xhr_open_re() -> &'static Regex {
    XHR_OPEN_RE.get_or_init(|| Regex::new(r"(?i)\.open\s*\(").expect("valid regex"))
}

fn atob_re() -> &'static Regex {
    ATOB_RE.get_or_init(|| Regex::new(r"(?i)\batob\s*\(").expect("valid regex"))
}

fn redirect_re() -> &'static Regex {
    REDIRECT_RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:(?:window\.)?location(?:\.href)?\s*=[^=]|(?:window\.)?location\.(?:replace|assign)\s*\()",
        )
        .expect("valid regex")
    })
}

fn has_fetch(text: &str) -> bool {
    fetch_literal_re().is_match(text) || (xhr_re().is_match(text) && xhr_open_re().is_match(text))
}

/// Run the redirector check over one file's full text. Returns a
/// finding when all three signals are present, `None` otherwise.
pub fn check_file(display: &str, text: &str) -> Option<Finding> {
    if !(has_fetch(text) && atob_re().is_match(text) && redirect_re().is_match(text)) {
        return None;
    }
    let summary = "remote-config redirector: fetch or XHR, atob decode, location redirect";
    let preview: String = summary.chars().take(60).collect();
    Some(Finding {
        file: display.to_string(),
        line: 1,
        column: 1,
        rule_id: REDIRECTOR_RULE_ID.to_string(),
        provider: REDIRECTOR_PROVIDER.to_string(),
        severity: Severity::High,
        kind: FindingKind::Pattern,
        description: "File combines all three redirector signals: a fetch or XHR request, an atob() base64 decode, and a location redirect assignment. This is the remote-config redirector pattern used by lure download portals, whose real destination is fetched from a config file and can be changed without editing this page. Verify where the redirect leads before trusting or hosting this file".to_string(),
        preview,
        fingerprint: fingerprint(REDIRECTOR_RULE_ID, summary),
        commit: None,
        span: (0, 0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic replica of the kit's three signals, written for
    /// this test suite. The config URL uses the reserved example
    /// domain; nothing here is a real lure.
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

    #[test]
    fn kit_shape_fires() {
        let f = check_file("index.html", KIT_PAGE).expect("kit shape must fire");
        assert_eq!(f.rule_id, REDIRECTOR_RULE_ID);
        assert_eq!(f.severity, Severity::High);
        assert!(f.description.contains("atob()"));
    }

    #[test]
    fn fetch_and_atob_without_redirect_is_quiet() {
        let page = r#"<script>
          const res = await fetch('https://api.example.net/data.json');
          const text = atob('aGVsbG8=');
          document.title = text;
        </script>"#;
        assert!(check_file("page.html", page).is_none());
    }

    #[test]
    fn atob_and_redirect_without_fetch_is_quiet() {
        let page = r#"<script>
          const url = atob('aHR0cHM6Ly9leGFtcGxlLm5ldA==');
          location.replace(url);
        </script>"#;
        assert!(check_file("page.js", page).is_none());
    }

    #[test]
    fn fetch_and_redirect_without_atob_is_quiet() {
        let page = r#"<script>
          const res = await fetch('https://api.example.net/next');
          const target = await res.text();
          window.location = target;
        </script>"#;
        assert!(check_file("page.html", page).is_none());
    }

    #[test]
    fn xhr_variant_of_the_kit_fires() {
        let page = r#"<script>
          var xhr = new XMLHttpRequest();
          xhr.open('GET', 'https://config.example.net/c.json', true);
          xhr.onload = function () {
            window.location.href = atob(JSON.parse(xhr.responseText).c);
          };
          xhr.send();
        </script>"#;
        assert!(check_file("portal.html", page).is_some());
    }

    #[test]
    fn ordinary_page_is_quiet() {
        let page = r#"<!DOCTYPE html>
<html><body>
<h1>Release notes</h1>
<a href="https://example.net/download">Download the manual</a>
<script>console.log('ready');</script>
</body></html>
"#;
        assert!(check_file("notes.html", page).is_none());
    }

    #[test]
    fn web_file_extensions() {
        assert!(is_web_file("index.html"));
        assert!(is_web_file("dir/app.JS"));
        assert!(is_web_file("portal.htm"));
        assert!(!is_web_file("main.rs"));
        assert!(!is_web_file("README.md"));
        assert!(!is_web_file("noextension"));
    }
}
