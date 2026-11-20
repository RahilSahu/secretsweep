//! The pattern rule registry.
//!
//! Each rule pairs a provider or format with a regular expression. The
//! Rust `regex` crate has no lookahead or backreferences, so rules that
//! need context carry the context inside the pattern (for example an
//! assignment like `aws_secret_access_key = ...`) and expose the secret
//! itself through a named capture group called `secret`. Rules without
//! a `secret` group report capture group 1, or the whole match.
//!
//! The number of rules is whatever this registry actually contains;
//! `rules().len()` is the single source of truth used by the CLI, the
//! reports and the README.

use crate::finding::Severity;
use regex::{Captures, Regex};
use std::sync::OnceLock;

#[derive(Debug)]
pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub provider: &'static str,
    pub severity: Severity,
    pub description: &'static str,
    pub pattern: &'static str,
    /// When true, matches whose secret value looks like an obvious
    /// placeholder (documentation examples, "your-key-here") are
    /// discarded. Used by assignment-style rules whose value format is
    /// loose; strict token formats keep it false.
    pub filter_placeholders: bool,
}

pub struct CompiledRule {
    pub rule: &'static Rule,
    pub regex: Regex,
}

static COMPILED: OnceLock<Vec<CompiledRule>> = OnceLock::new();

pub fn rules() -> &'static [Rule] {
    RULES
}

pub fn compiled_rules() -> &'static [CompiledRule] {
    COMPILED.get_or_init(|| {
        RULES
            .iter()
            .map(|rule| CompiledRule {
                rule,
                regex: Regex::new(rule.pattern)
                    .unwrap_or_else(|e| panic!("rule {} has an invalid pattern: {e}", rule.id)),
            })
            .collect()
    })
}

/// Extract the secret value and its byte span within the line from a
/// successful match: named group `secret` first, then group 1, then the
/// whole match.
pub fn extract_secret(caps: &Captures) -> (String, (usize, usize)) {
    if let Some(m) = caps.name("secret") {
        return (m.as_str().to_string(), (m.start(), m.end()));
    }
    if let Some(m) = caps.get(1) {
        return (m.as_str().to_string(), (m.start(), m.end()));
    }
    let m = caps.get(0).expect("a match always has group 0");
    (m.as_str().to_string(), (m.start(), m.end()))
}

/// Rule id used for entropy findings. Entropy is a heuristic engine,
/// not a pattern rule, so it is deliberately not part of `RULES`.
pub const ENTROPY_RULE_ID: &str = "ENTROPY";
pub const ENTROPY_RULE_NAME: &str = "high-entropy-string";
pub const ENTROPY_PROVIDER: &str = "Entropy";

/// Rule ids for the structural zip archive checks in `archive.rs`.
/// Like entropy, these are not line patterns, so they live outside
/// `RULES`; the ids are stable so baselines and allowlists can refer
/// to them.
pub const ARCHIVE_EXEC_RULE_ID: &str = "ARCHIVE-EXEC";
pub const ARCHIVE_EXEC_RULE_NAME: &str = "archive-executable-and-launcher";
pub const ARCHIVE_UNREADABLE_RULE_ID: &str = "ARCHIVE-UNREADABLE";
pub const ARCHIVE_UNREADABLE_RULE_NAME: &str = "archive-uninspectable";
pub const ARCHIVE_PROVIDER: &str = "Archive";

/// Rule id for the structural remote-config redirector check in
/// `redirector.rs`. Like the archive checks, this is a whole-file
/// structural heuristic, not a line pattern, so it lives outside
/// `RULES`.
pub const REDIRECTOR_RULE_ID: &str = "REDIRECTOR";
pub const REDIRECTOR_RULE_NAME: &str = "remote-config-redirector";
pub const REDIRECTOR_PROVIDER: &str = "Redirector";

const RULES: &[Rule] = &[
    // ---------------- AWS ----------------
    Rule {
        id: "SS001",
        name: "aws-access-key-id",
        provider: "AWS",
        severity: Severity::High,
        description: "AWS access key ID (long-lived IAM user key)",
        pattern: r##"AKIA[0-9A-Z]{16}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS002",
        name: "aws-session-access-key-id",
        provider: "AWS",
        severity: Severity::High,
        description: "AWS temporary session access key ID",
        pattern: r##"ASIA[0-9A-Z]{16}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS003",
        name: "aws-secret-access-key",
        provider: "AWS",
        severity: Severity::Critical,
        description: "AWS secret access key in an assignment",
        pattern: r##"(?i)aws_secret_access_key\s*[:=]\s*["']?(?P<secret>[A-Za-z0-9/+]{40})["']?"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS004",
        name: "aws-session-token",
        provider: "AWS",
        severity: Severity::High,
        description: "AWS session token in an assignment",
        pattern: r##"(?i)aws_session_token\s*[:=]\s*["']?(?P<secret>[A-Za-z0-9/+]{100,})["']?"##,
        filter_placeholders: false,
    },
    // ---------------- GCP ----------------
    Rule {
        id: "SS005",
        name: "gcp-api-key",
        provider: "GCP",
        severity: Severity::High,
        description: "Google Cloud API key",
        pattern: r##"AIza[0-9A-Za-z_-]{35}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS006",
        name: "gcp-service-account-key",
        provider: "GCP",
        severity: Severity::Critical,
        description: "Google Cloud service account key file marker",
        pattern: r##""type"\s*:\s*"service_account""##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS007",
        name: "gcp-private-key-id",
        provider: "GCP",
        severity: Severity::Medium,
        description: "Google Cloud service account private key id field",
        pattern: r##""private_key_id"\s*:\s*"(?P<secret>[0-9a-f]{40})""##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS008",
        name: "gcp-oauth-client-secret",
        provider: "GCP",
        severity: Severity::High,
        description: "Google OAuth client secret",
        pattern: r##"GOCSPX-[A-Za-z0-9_-]{28}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS009",
        name: "google-oauth-access-token",
        provider: "GCP",
        severity: Severity::High,
        description: "Google OAuth access token (ya29 prefix)",
        pattern: r##"ya29\.[0-9A-Za-z_-]{20,}"##,
        filter_placeholders: false,
    },
    // ---------------- Azure ----------------
    Rule {
        id: "SS010",
        name: "azure-client-secret",
        provider: "Azure",
        severity: Severity::High,
        description: "Azure AD application client secret in an assignment",
        pattern: r##"(?i)azure_client_secret\s*[:=]\s*["']?(?P<secret>[A-Za-z0-9~._-]{30,45})["']?"##,
        filter_placeholders: true,
    },
    Rule {
        id: "SS011",
        name: "azure-sas-token",
        provider: "Azure",
        severity: Severity::High,
        description: "Azure shared access signature (sig parameter) in a URL",
        pattern: r##"(?i)[?&]sig=(?P<secret>[A-Za-z0-9%]{40,})"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS012",
        name: "azure-storage-account-key",
        provider: "Azure",
        severity: Severity::High,
        description: "Azure Storage account key in a connection string",
        pattern: r##"(?i)AccountKey=(?P<secret>[A-Za-z0-9+/=]{70,})"##,
        filter_placeholders: false,
    },
    // ---------------- GitHub ----------------
    Rule {
        id: "SS013",
        name: "github-pat-classic",
        provider: "GitHub",
        severity: Severity::Critical,
        description: "GitHub classic personal access token",
        pattern: r##"ghp_[A-Za-z0-9]{36}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS014",
        name: "github-oauth-token",
        provider: "GitHub",
        severity: Severity::High,
        description: "GitHub OAuth access token",
        pattern: r##"gho_[A-Za-z0-9]{36}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS015",
        name: "github-user-to-server-token",
        provider: "GitHub",
        severity: Severity::High,
        description: "GitHub App user-to-server token",
        pattern: r##"ghu_[A-Za-z0-9]{36}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS016",
        name: "github-server-to-server-token",
        provider: "GitHub",
        severity: Severity::High,
        description: "GitHub App server-to-server token",
        pattern: r##"ghs_[A-Za-z0-9]{36}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS017",
        name: "github-refresh-token",
        provider: "GitHub",
        severity: Severity::Medium,
        description: "GitHub App refresh token",
        pattern: r##"ghr_[A-Za-z0-9]{36}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS018",
        name: "github-pat-fine-grained",
        provider: "GitHub",
        severity: Severity::Critical,
        description: "GitHub fine-grained personal access token",
        pattern: r##"github_pat_[A-Za-z0-9_]{82}"##,
        filter_placeholders: false,
    },
    // ---------------- GitLab ----------------
    Rule {
        id: "SS019",
        name: "gitlab-pat",
        provider: "GitLab",
        severity: Severity::Critical,
        description: "GitLab personal access token",
        pattern: r##"glpat-[A-Za-z0-9_-]{20}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS020",
        name: "gitlab-runner-token",
        provider: "GitLab",
        severity: Severity::High,
        description: "GitLab runner authentication token",
        pattern: r##"glrt-[A-Za-z0-9_-]{20}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS021",
        name: "gitlab-agent-token",
        provider: "GitLab",
        severity: Severity::High,
        description: "GitLab agent for Kubernetes token",
        pattern: r##"glagent-[A-Za-z0-9_-]{20,}"##,
        filter_placeholders: false,
    },
    // ---------------- Slack ----------------
    Rule {
        id: "SS022",
        name: "slack-bot-token",
        provider: "Slack",
        severity: Severity::High,
        description: "Slack bot user OAuth token (xoxb)",
        pattern: r##"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS023",
        name: "slack-user-token",
        provider: "Slack",
        severity: Severity::High,
        description: "Slack user OAuth token (xoxp)",
        pattern: r##"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[0-9a-f]{32}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS024",
        name: "slack-token-other",
        provider: "Slack",
        severity: Severity::High,
        description: "Slack token of another type (xoxa, xoxr, xoxs)",
        pattern: r##"xox[arse]-[A-Za-z0-9-]{10,}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS025",
        name: "slack-webhook-url",
        provider: "Slack",
        severity: Severity::Medium,
        description: "Slack incoming webhook URL (acts as a bearer secret)",
        pattern: r##"https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS026",
        name: "slack-app-config-token",
        provider: "Slack",
        severity: Severity::High,
        description: "Slack app-level configuration token (xapp)",
        pattern: r##"xapp-[0-9]-[A-Z0-9]{10}-[0-9]{10,}-[0-9a-f]{64}"##,
        filter_placeholders: false,
    },
    // ---------------- Stripe ----------------
    Rule {
        id: "SS027",
        name: "stripe-live-secret-key",
        provider: "Stripe",
        severity: Severity::Critical,
        description: "Stripe live secret API key",
        pattern: r##"sk_live_[A-Za-z0-9]{24,}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS028",
        name: "stripe-restricted-key",
        provider: "Stripe",
        severity: Severity::High,
        description: "Stripe live restricted API key",
        pattern: r##"rk_live_[A-Za-z0-9]{24,}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS029",
        name: "stripe-test-secret-key",
        provider: "Stripe",
        severity: Severity::Low,
        description: "Stripe test secret API key (test mode, still sensitive)",
        pattern: r##"sk_test_[A-Za-z0-9]{24,}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS030",
        name: "stripe-webhook-secret",
        provider: "Stripe",
        severity: Severity::High,
        description: "Stripe webhook signing secret",
        pattern: r##"whsec_[A-Za-z0-9]{32,}"##,
        filter_placeholders: false,
    },
    // ---------------- OpenAI / Anthropic ----------------
    Rule {
        id: "SS031",
        name: "openai-project-key",
        provider: "OpenAI",
        severity: Severity::Critical,
        description: "OpenAI project API key",
        pattern: r##"sk-proj-[A-Za-z0-9_-]{40,}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS032",
        name: "openai-legacy-key",
        provider: "OpenAI",
        severity: Severity::Critical,
        description: "OpenAI legacy API key (48 character suffix)",
        pattern: r##"sk-[A-Za-z0-9]{48}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS033",
        name: "openai-service-account-key",
        provider: "OpenAI",
        severity: Severity::High,
        description: "OpenAI service account API key",
        pattern: r##"sk-svcacct-[A-Za-z0-9_-]{40,}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS034",
        name: "anthropic-api-key",
        provider: "Anthropic",
        severity: Severity::Critical,
        description: "Anthropic API key",
        pattern: r##"sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{40,}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS035",
        name: "anthropic-admin-key",
        provider: "Anthropic",
        severity: Severity::High,
        description: "Anthropic admin API key",
        pattern: r##"sk-ant-admin[0-9]{2}-[A-Za-z0-9_-]{40,}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS036",
        name: "anthropic-oauth-token",
        provider: "Anthropic",
        severity: Severity::Medium,
        description: "Anthropic OAuth token",
        pattern: r##"sk-ant-oat[0-9]{2}-[A-Za-z0-9_-]{40,}"##,
        filter_placeholders: false,
    },
    // ---------------- SendGrid / Twilio / Mail ----------------
    Rule {
        id: "SS037",
        name: "sendgrid-api-key",
        provider: "SendGrid",
        severity: Severity::Critical,
        description: "SendGrid API key",
        pattern: r##"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS038",
        name: "twilio-api-key-sid",
        provider: "Twilio",
        severity: Severity::High,
        description: "Twilio API key SID (SK prefix, 32 hex chars)",
        pattern: r##"SK[0-9a-f]{32}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS039",
        name: "twilio-auth-token",
        provider: "Twilio",
        severity: Severity::High,
        description: "Twilio auth token in an assignment near a Twilio reference",
        pattern: r##"(?i)twilio.{0,40}?auth_token\s*[:=]\s*["']?(?P<secret>[0-9a-f]{32})"##,
        filter_placeholders: true,
    },
    Rule {
        id: "SS040",
        name: "mailgun-api-key",
        provider: "Mailgun",
        severity: Severity::High,
        description: "Mailgun API key",
        pattern: r##"key-[0-9a-f]{32}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS041",
        name: "mailchimp-api-key",
        provider: "Mailchimp",
        severity: Severity::High,
        description: "Mailchimp API key (hex suffix with data centre)",
        pattern: r##"[0-9a-f]{32}-us[0-9]{1,2}\b"##,
        filter_placeholders: false,
    },
    // ---------------- Package registries ----------------
    Rule {
        id: "SS042",
        name: "npm-token",
        provider: "npm",
        severity: Severity::Critical,
        description: "npm access token",
        pattern: r##"npm_[A-Za-z0-9]{36}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS043",
        name: "npm-registry-auth-token",
        provider: "npm",
        severity: Severity::High,
        description: "npm registry auth token in an .npmrc line",
        pattern: r##"//registry\.npmjs\.org/:_authToken=(?P<secret>[A-Za-z0-9_-]{36,})"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS044",
        name: "pypi-token",
        provider: "PyPI",
        severity: Severity::Critical,
        description: "PyPI API token",
        pattern: r##"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS045",
        name: "dockerhub-access-token",
        provider: "Docker Hub",
        severity: Severity::High,
        description: "Docker Hub access token",
        pattern: r##"dckr_pat_[A-Za-z0-9_-]{27}"##,
        filter_placeholders: false,
    },
    // ---------------- Private keys ----------------
    Rule {
        id: "SS046",
        name: "private-key-rsa",
        provider: "Private Key",
        severity: Severity::Critical,
        description: "RSA private key block",
        pattern: r##"-----BEGIN RSA PRIVATE KEY-----"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS047",
        name: "private-key-ec",
        provider: "Private Key",
        severity: Severity::Critical,
        description: "EC private key block",
        pattern: r##"-----BEGIN EC PRIVATE KEY-----"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS048",
        name: "private-key-openssh",
        provider: "Private Key",
        severity: Severity::Critical,
        description: "OpenSSH private key block",
        pattern: r##"-----BEGIN OPENSSH PRIVATE KEY-----"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS049",
        name: "private-key-pgp",
        provider: "Private Key",
        severity: Severity::Critical,
        description: "PGP private key block",
        pattern: r##"-----BEGIN PGP PRIVATE KEY BLOCK-----"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS050",
        name: "private-key-pkcs8",
        provider: "Private Key",
        severity: Severity::Critical,
        description: "PKCS8 private key block",
        pattern: r##"-----BEGIN PRIVATE KEY-----"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS051",
        name: "private-key-dsa",
        provider: "Private Key",
        severity: Severity::Critical,
        description: "DSA private key block",
        pattern: r##"-----BEGIN DSA PRIVATE KEY-----"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS052",
        name: "private-key-encrypted",
        provider: "Private Key",
        severity: Severity::High,
        description: "Encrypted private key block",
        pattern: r##"-----BEGIN ENCRYPTED PRIVATE KEY-----"##,
        filter_placeholders: false,
    },
    // ---------------- Tokens and headers ----------------
    Rule {
        id: "SS053",
        name: "jwt",
        provider: "Token",
        severity: Severity::Medium,
        description: "JSON Web Token (may be a session or service credential)",
        pattern: r##"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS054",
        name: "authorization-bearer",
        provider: "Header",
        severity: Severity::Medium,
        description: "Authorization header with a Bearer token",
        pattern: r##"(?i)authorization\s*:\s*bearer\s+(?P<secret>[A-Za-z0-9._-]{20,})"##,
        filter_placeholders: true,
    },
    Rule {
        id: "SS055",
        name: "authorization-basic",
        provider: "Header",
        severity: Severity::High,
        description: "Authorization header with Basic credentials (base64)",
        pattern: r##"(?i)authorization\s*:\s*basic\s+(?P<secret>[A-Za-z0-9+/=]{8,})"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS056",
        name: "x-api-key-header",
        provider: "Header",
        severity: Severity::High,
        description: "X-Api-Key header or assignment with a key value",
        pattern: r##"(?i)x-api-key\s*[:=]\s*["']?(?P<secret>[A-Za-z0-9_-]{16,})["']?"##,
        filter_placeholders: true,
    },
    Rule {
        id: "SS057",
        name: "url-embedded-credentials",
        provider: "Generic",
        severity: Severity::High,
        description: "HTTP(S) URL with an embedded password",
        pattern: r##"https?://[^:/\s]+:(?P<secret>[^@/\s]{3,})@"##,
        filter_placeholders: false,
    },
    // ---------------- Database connection strings ----------------
    Rule {
        id: "SS058",
        name: "db-postgres-uri",
        provider: "Database",
        severity: Severity::Critical,
        description: "PostgreSQL connection URI with a password",
        pattern: r##"postgres(?:ql)?://[^:/\s]+:(?P<secret>[^@/\s]+)@"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS059",
        name: "db-mysql-uri",
        provider: "Database",
        severity: Severity::Critical,
        description: "MySQL connection URI with a password",
        pattern: r##"mysql://[^:/\s]+:(?P<secret>[^@/\s]+)@"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS060",
        name: "db-mongodb-uri",
        provider: "Database",
        severity: Severity::Critical,
        description: "MongoDB connection URI with a password",
        pattern: r##"mongodb(?:\+srv)?://[^:/\s]+:(?P<secret>[^@/\s]+)@"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS061",
        name: "db-redis-uri",
        provider: "Database",
        severity: Severity::High,
        description: "Redis connection URI with a password",
        pattern: r##"rediss?://[^:/\s]*:(?P<secret>[^@/\s]+)@"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS062",
        name: "db-amqp-uri",
        provider: "Database",
        severity: Severity::High,
        description: "AMQP connection URI with a password",
        pattern: r##"amqps?://[^:/\s]+:(?P<secret>[^@/\s]+)@"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS063",
        name: "db-jdbc-password",
        provider: "Database",
        severity: Severity::High,
        description: "JDBC connection URL with a password parameter",
        pattern: r##"(?i)jdbc:[a-z0-9]+://[^\s"']{0,200}?[?&;]password=(?P<secret>[^&\s"']+)"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS064",
        name: "db-sqlserver-connection-string",
        provider: "Database",
        severity: Severity::High,
        description: "SQL Server (ADO.NET) connection string with a password",
        pattern: r##"(?i)(?:server|data source)\s*=[^;\n]+;(?:[^;\n]+;){0,5}?\s*(?:password|pwd)\s*=\s*(?P<secret>[^;\s"']+)"##,
        filter_placeholders: true,
    },
    // ---------------- Generic assignments ----------------
    Rule {
        id: "SS065",
        name: "generic-password-assignment",
        provider: "Generic",
        severity: Severity::High,
        description: "Password assigned to a variable, key or field",
        pattern: r##"(?i)(?:^|[^A-Za-z0-9])(?:[A-Za-z0-9]+[_-])?(?:password|passwd|pwd)\s*[:=]\s*["']?(?P<secret>[^$\s"'{][^\s"']{3,})"##,
        filter_placeholders: true,
    },
    Rule {
        id: "SS066",
        name: "generic-secret-assignment",
        provider: "Generic",
        severity: Severity::High,
        description: "Value assigned to a secret-named variable, key or field",
        pattern: r##"(?i)(?:^|[^A-Za-z0-9])(?:[A-Za-z0-9]+[_-])?(?:client_secret|secret_key|secret)\s*[:=]\s*["']?(?P<secret>[A-Za-z0-9_./+=-]{12,})["']?"##,
        filter_placeholders: true,
    },
    Rule {
        id: "SS067",
        name: "generic-api-key-assignment",
        provider: "Generic",
        severity: Severity::High,
        description: "Value assigned to an api-key-named variable, key or field",
        pattern: r##"(?i)(?:^|[^A-Za-z0-9])(?:[A-Za-z0-9]+[_-])?api[_-]?key\s*[:=]\s*["']?(?P<secret>[A-Za-z0-9_.-]{16,})["']?"##,
        filter_placeholders: true,
    },
    Rule {
        id: "SS068",
        name: "generic-token-assignment",
        provider: "Generic",
        severity: Severity::High,
        description: "Value assigned to a token-named variable, key or field",
        pattern: r##"(?i)(?:^|[^A-Za-z0-9])(?:[A-Za-z0-9]+[_-])?(?:access[_-]?token|auth[_-]?token|refresh[_-]?token)\s*[:=]\s*["']?(?P<secret>[A-Za-z0-9_./+=-]{16,})["']?"##,
        filter_placeholders: true,
    },
    // ---------------- SaaS and platform tokens ----------------
    Rule {
        id: "SS069",
        name: "heroku-api-key",
        provider: "Heroku",
        severity: Severity::High,
        description: "Heroku API key (UUID format) in an assignment",
        pattern: r##"(?i)heroku_api_key\s*[:=]\s*["']?(?P<secret>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS070",
        name: "square-access-token",
        provider: "Square",
        severity: Severity::Critical,
        description: "Square access token",
        pattern: r##"sq0atp-[A-Za-z0-9_-]{22}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS071",
        name: "square-oauth-secret",
        provider: "Square",
        severity: Severity::Critical,
        description: "Square OAuth application secret",
        pattern: r##"sq0csp-[A-Za-z0-9_-]{43}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS072",
        name: "shopify-access-token",
        provider: "Shopify",
        severity: Severity::Critical,
        description: "Shopify admin API access token",
        pattern: r##"shpat_[0-9a-f]{32}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS073",
        name: "shopify-shared-secret",
        provider: "Shopify",
        severity: Severity::High,
        description: "Shopify shared secret",
        pattern: r##"shpss_[0-9a-f]{32}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS074",
        name: "shopify-custom-app-token",
        provider: "Shopify",
        severity: Severity::High,
        description: "Shopify custom app access token",
        pattern: r##"shpca_[0-9a-f]{32}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS075",
        name: "discord-bot-token",
        provider: "Discord",
        severity: Severity::Critical,
        description: "Discord bot token",
        pattern: r##"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS076",
        name: "discord-webhook-url",
        provider: "Discord",
        severity: Severity::Medium,
        description: "Discord webhook URL (acts as a bearer secret)",
        pattern: r##"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_-]{60,}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS077",
        name: "telegram-bot-token",
        provider: "Telegram",
        severity: Severity::Critical,
        description: "Telegram bot API token",
        pattern: r##"[0-9]{8,10}:[A-Za-z0-9_-]{35}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS078",
        name: "facebook-access-token",
        provider: "Facebook",
        severity: Severity::High,
        description: "Facebook access token (EAAC prefix)",
        pattern: r##"EAACEdEose0cBA[A-Za-z0-9]{20,}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS079",
        name: "age-secret-key",
        provider: "Age",
        severity: Severity::High,
        description: "Age encryption secret key",
        pattern: r##"AGE-SECRET-KEY-1[0-9A-Z]{58}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS080",
        name: "vault-token",
        provider: "HashiCorp Vault",
        severity: Severity::Critical,
        description: "HashiCorp Vault service token",
        pattern: r##"hvs\.[A-Za-z0-9_-]{24,}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS081",
        name: "cloudflare-api-token",
        provider: "Cloudflare",
        severity: Severity::High,
        description: "Cloudflare API token in an assignment",
        pattern: r##"(?i)(?:cf_api_token|cloudflare_api_token)\s*[:=]\s*["']?(?P<secret>[A-Za-z0-9_-]{40})["']?"##,
        filter_placeholders: true,
    },
    Rule {
        id: "SS082",
        name: "digitalocean-token",
        provider: "DigitalOcean",
        severity: Severity::Critical,
        description: "DigitalOcean personal access token",
        pattern: r##"dop_v1_[0-9a-f]{64}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS083",
        name: "huggingface-token",
        provider: "Hugging Face",
        severity: Severity::High,
        description: "Hugging Face access token",
        pattern: r##"hf_[A-Za-z0-9]{34}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS084",
        name: "replicate-token",
        provider: "Replicate",
        severity: Severity::High,
        description: "Replicate API token",
        pattern: r##"r8_[A-Za-z0-9]{37}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS085",
        name: "linear-api-key",
        provider: "Linear",
        severity: Severity::High,
        description: "Linear API key",
        pattern: r##"lin_api_[A-Za-z0-9]{40}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS086",
        name: "newrelic-user-key",
        provider: "New Relic",
        severity: Severity::High,
        description: "New Relic user API key",
        pattern: r##"NRAK-[0-9A-Z]{27}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS087",
        name: "fcm-server-key",
        provider: "Firebase",
        severity: Severity::Medium,
        description: "Firebase Cloud Messaging legacy server key",
        pattern: r##"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{134,}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS088",
        name: "ethereum-private-key",
        provider: "Crypto",
        severity: Severity::Critical,
        description: "Ethereum-style private key (64 hex chars) in an assignment",
        pattern: r##"(?i)private[_-]?key\s*[:=]\s*["']?(?:0x)?(?P<secret>[0-9a-fA-F]{64})["']?"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS089",
        name: "laravel-app-key",
        provider: "Laravel",
        severity: Severity::High,
        description: "Laravel APP_KEY value",
        pattern: r##"APP_KEY\s*=\s*base64:(?P<secret>[A-Za-z0-9+/=]{40,})"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS090",
        name: "grafana-service-account-token",
        provider: "Grafana",
        severity: Severity::High,
        description: "Grafana service account token",
        pattern: r##"glsa_[A-Za-z0-9]{32}_[0-9a-f]{8}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS091",
        name: "sonarqube-token",
        provider: "SonarQube",
        severity: Severity::High,
        description: "SonarQube user or analysis token",
        pattern: r##"sq[ua]_[0-9a-f]{40}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS092",
        name: "recaptcha-key",
        provider: "Google reCAPTCHA",
        severity: Severity::Medium,
        description: "reCAPTCHA key (site and secret keys share this format; secret keys must not be committed)",
        pattern: r##"6L[0-9A-Za-z_-]{38}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS093",
        name: "planetscale-token",
        provider: "PlanetScale",
        severity: Severity::High,
        description: "PlanetScale API token",
        pattern: r##"pscale_tkn_[A-Za-z0-9_-]{40,}"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS094",
        name: "databricks-token",
        provider: "Databricks",
        severity: Severity::High,
        description: "Databricks personal access token",
        pattern: r##"dapi[0-9a-f]{32}"##,
        filter_placeholders: false,
    },
    // ---------------- Licensing platforms ----------------
    Rule {
        id: "SS095",
        name: "auth-gg-secret",
        provider: "auth.gg",
        severity: Severity::High,
        description: "auth.gg application secret or API key in an assignment near an auth.gg reference",
        pattern: r##"(?i)auth[-_. ]?gg\b.{0,80}?(?:secret|api[_-]?key|license[_-]?key)\s*[:=]\s*["']?(?P<secret>[A-Za-z0-9_-]{16,})"##,
        filter_placeholders: true,
    },
    // ---------------- Cryptocurrency addresses ----------------
    // Addresses are public identifiers, not secrets. They are Low
    // severity and informational: the point is that a hardcoded
    // payout or recipient address in source becomes visible in
    // review instead of surfacing only as generic entropy noise.
    Rule {
        id: "SS096",
        name: "ethereum-address",
        provider: "Crypto",
        severity: Severity::Low,
        description: "Ethereum address (0x plus 40 hex characters); informational, addresses are public identifiers",
        pattern: r##"\b0x[0-9a-fA-F]{40}\b"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS097",
        name: "bitcoin-address",
        provider: "Crypto",
        severity: Severity::Low,
        description: "Bitcoin address (legacy, P2SH or bech32 shape); informational, addresses are public identifiers",
        pattern: r##"\b(?:[13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,59})\b"##,
        filter_placeholders: false,
    },
    // ---------------- Malware indicators ----------------
    Rule {
        id: "SS098",
        name: "private-key-persistence",
        provider: "Private Key",
        severity: Severity::High,
        description: "Code writes private key material (private key, seed phrase or mnemonic) to a file; same-line heuristic, verify the destination is an encrypted keystore and not plaintext storage",
        pattern: r##"(?i)(?:\b(?:private[_-]?key|privkey|pk_hex|seed[_-]?phrase|mnemonic)\b.{0,160}?\b(?:fs::write|write_all|file::create|fs\.writefile(?:sync)?|writefile(?:sync)?|files\.write|os\.writefile|ioutil\.writefile|file_put_contents|fwrite|ofstream)\b|\b(?:fs::write|write_all|file::create|fs\.writefile(?:sync)?|writefile(?:sync)?|files\.write|os\.writefile|ioutil\.writefile|file_put_contents|fwrite|ofstream)\b.{0,160}?\b(?:private[_-]?key|privkey|pk_hex|seed[_-]?phrase|mnemonic)\b)"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS099",
        name: "file-host-archive-link",
        provider: "File Host",
        severity: Severity::Low,
        description: "Download link to a file-hosting service frequently abused for malware lures (archive paths, direct-download paths, or a shortener link with a download signal on the same line); verify before trusting",
        pattern: r##"(?i)(?:https?://(?:www\.)?(?:4sync\.com|anonfiles\.com|bayfiles\.com|sendspace\.com|zippyshare\.com)(?:[^\s)"'<>]*?(?:\.zip|\.rar|\.7z|/(?:zip|archive|file|directdownload|download)/)|[^\s)"'<>]*?[?&]download(?:=[^\s)"'<>]*)?)[^\s)"'<>]*|(?:\b(?:download|installer|setup)\b|\.(?:zip|rar|7z)\b).{0,120}?https?://(?:cutt\.ly|bit\.ly|tinyurl\.com|rb\.gy)/[^\s)"'<>]+|https?://(?:cutt\.ly|bit\.ly|tinyurl\.com|rb\.gy)/[^\s)"'<>]+.{0,120}?(?:\b(?:download|installer|setup)\b|\.(?:zip|rar|7z)\b)|https?://(?:cutt\.ly|bit\.ly|tinyurl\.com|rb\.gy)/[^\s)"'<>]*?(?:\b(?:download|installer|setup)\b|\.(?:zip|rar|7z)\b)[^\s)"'<>]*)"##,
        filter_placeholders: false,
    },
    Rule {
        id: "SS100",
        name: "antivirus-disable-instruction",
        provider: "Malware Indicator",
        severity: Severity::Medium,
        description: "Instructions to disable antivirus protection (Windows Defender, real-time protection or antivirus software); a hallmark of malware lure install guides, verify the context before trusting the document",
        pattern: r##"(?i)\b(?:disable|turn off|switch off|deactivate)\s+(?:the\s+|your\s+)?(?:windows\s+defender|defender|windows\s+security|real[-\s]time\s+protection|antivirus(?:\s+protection)?)\b"##,
        filter_placeholders: false,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_substantial_and_ids_are_unique_and_ordered() {
        assert!(
            rules().len() >= 60,
            "registry should hold at least 60 rules, has {}",
            rules().len()
        );
        let mut ids: Vec<&str> = rules().iter().map(|r| r.id).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(total, ids.len(), "rule ids must be unique");
        for (i, r) in rules().iter().enumerate() {
            assert_eq!(r.id, format!("SS{:03}", i + 1), "ids must be sequential");
        }
    }

    #[test]
    fn all_patterns_compile() {
        assert_eq!(compiled_rules().len(), rules().len());
    }
}
