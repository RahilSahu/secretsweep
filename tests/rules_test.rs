//! Per-rule positive and negative tests.
//!
//! Every positive fixture is either a publicly documented example
//! credential (the AWS documentation examples) or a synthetic string
//! assembled from fragments with `concat!`, so no complete,
//! real-looking credential ever appears as a literal in this file.
//! Negatives are near misses: wrong length, wrong charset, public
//! counterparts, or documented placeholders.

use secretsweep::scanline::LineScanner;

fn has_rule(line: &str, id: &str) -> bool {
    LineScanner::default()
        .scan_line("test.txt", 1, line, None)
        .iter()
        .any(|f| f.rule_id == id)
}

macro_rules! rule_case {
    ($name:ident, $id:literal, $positive:expr, $negative:expr) => {
        #[test]
        fn $name() {
            assert!(
                has_rule($positive, $id),
                "expected {} to match: {}",
                $id,
                $positive
            );
            assert!(
                !has_rule($negative, $id),
                "expected {} NOT to match: {}",
                $id,
                $negative
            );
        }
    };
}

// ---------------- AWS ----------------
rule_case!(
    ss001_aws_access_key_id,
    "SS001",
    "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"",
    "aws_access_key_id = \"AKIA123\""
);
rule_case!(
    ss002_aws_session_key,
    "SS002",
    concat!("key = \"ASIA", "1234567890ABCDEF", "\""),
    "key = \"ASIA123\""
);
rule_case!(
    ss003_aws_secret_key,
    "SS003",
    "aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"",
    "aws_secret_access_key = \"tooshort\""
);
rule_case!(
    ss004_aws_session_token,
    "SS004",
    concat!(
        "aws_session_token = \"",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfGh\"",
        "\""
    ),
    "aws_session_token = \"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\""
);

// ---------------- GCP ----------------
rule_case!(
    ss005_gcp_api_key,
    "SS005",
    concat!("key = \"AIza", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r", "\""),
    "key = \"AIzaShort\""
);
rule_case!(
    ss006_gcp_service_account,
    "SS006",
    "{\"type\": \"service_account\", \"project_id\": \"demo\"}",
    "{\"type\": \"user_account\", \"project_id\": \"demo\"}"
);
rule_case!(
    ss007_gcp_private_key_id,
    "SS007",
    "\"private_key_id\": \"0123456789abcdef0123456789abcdef01234567\"",
    "\"private_key_id\": \"xyz\""
);
rule_case!(
    ss008_gcp_oauth_secret,
    "SS008",
    concat!("secret = \"GOCSPX-", "AbCdEfGhIjKlMnOpQrStUvWxYz12", "\""),
    "secret = \"GOCSPX-short\""
);
rule_case!(
    ss009_google_oauth_token,
    "SS009",
    concat!(
        "token = \"ya29.",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "\""
    ),
    "token = \"ya29.short\""
);

// ---------------- Azure ----------------
rule_case!(
    ss010_azure_client_secret,
    "SS010",
    "AZURE_CLIENT_SECRET = \"AbC~dEf.GhI_jKl-MnO.pQr~StU_vWx-Yz0123\"",
    "AZURE_CLIENT_SECRET = \"short\""
);
rule_case!(
    ss011_azure_sas,
    "SS011",
    concat!(
        "url = \"https://acct.blob.core.windows.net/c?sig=",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh",
        "%3D\""
    ),
    "url = \"https://acct.blob.core.windows.net/c?sig=abc\""
);
rule_case!(
    ss012_azure_storage_key,
    "SS012",
    concat!(
        "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/",
        "AbCdEfGhIjKl==",
        ";EndpointSuffix=core.windows.net"
    ),
    "AccountKey=short"
);

// ---------------- GitHub ----------------
rule_case!(
    ss013_github_pat_classic,
    "SS013",
    concat!(
        "token = \"ghp_",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "\""
    ),
    "token = \"ghp_tooshort\""
);
rule_case!(
    ss014_github_oauth,
    "SS014",
    concat!(
        "token = \"gho_",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "\""
    ),
    "token = \"gho_tooshort\""
);
rule_case!(
    ss015_github_user_to_server,
    "SS015",
    concat!(
        "token = \"ghu_",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "\""
    ),
    "token = \"ghu_tooshort\""
);
rule_case!(
    ss016_github_server_to_server,
    "SS016",
    concat!(
        "token = \"ghs_",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "\""
    ),
    "token = \"ghs_tooshort\""
);
rule_case!(
    ss017_github_refresh,
    "SS017",
    concat!(
        "token = \"ghr_",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "\""
    ),
    "token = \"ghr_tooshort\""
);
rule_case!(
    ss018_github_pat_fine_grained,
    "SS018",
    concat!(
        "token = \"github_pat_",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfGhIj",
        "\""
    ),
    "token = \"github_pat_short\""
);

// ---------------- GitLab ----------------
rule_case!(
    ss019_gitlab_pat,
    "SS019",
    concat!("token = \"glpat-", "AbCdEfGhIjKlMnOpQrSt", "\""),
    "token = \"glpat-short\""
);
rule_case!(
    ss020_gitlab_runner,
    "SS020",
    concat!("token = \"glrt-", "AbCdEfGhIjKlMnOpQrSt", "\""),
    "token = \"glrt-short\""
);
rule_case!(
    ss021_gitlab_agent,
    "SS021",
    concat!("token = \"glagent-", "AbCdEfGhIjKlMnOpQrStUvWx", "\""),
    "token = \"glagent-short\""
);

// ---------------- Slack ----------------
rule_case!(
    ss022_slack_bot,
    "SS022",
    concat!(
        "token = \"xoxb-",
        "123456789012",
        "-",
        "1234567890",
        "12-",
        "AbCdEfGhIjKlMnOpQrStUvWx",
        "\""
    ),
    "token = \"xoxb-123-456-abc\""
);
rule_case!(
    ss023_slack_user,
    "SS023",
    concat!(
        "token = \"xoxp-123456789012-123456789012-123456789012-",
        "0123456789abcdef0123456789abcdef",
        "\""
    ),
    "token = \"xoxp-1-2-3-4\""
);
rule_case!(
    ss024_slack_other,
    "SS024",
    "token = \"xoxa-2-AbCdEfGhIjKlMnOp\"",
    "token = \"xoxz-AbCdEfGhIjKlMnOp\""
);
rule_case!(
    ss025_slack_webhook,
    "SS025",
    concat!(
        "hook = \"https://hooks.slack.com/services/",
        "T012AB34CD",
        "/",
        "B012AB34CD",
        "/",
        "AbCdEfGhIjKlMnOpQrStUvWx",
        "\""
    ),
    "hook = \"https://hooks.slack.com/services/T1/B2/abc\""
);
rule_case!(
    ss026_slack_app_token,
    "SS026",
    concat!(
        "token = \"xapp-1-A012AB34CD-1234567890123-",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "\""
    ),
    "token = \"xapp-1-2-3-4\""
);

// ---------------- Stripe ----------------
rule_case!(
    ss027_stripe_live,
    "SS027",
    concat!("stripe = \"sk_live_", "AbCdEfGhIjKlMnOpQrStUvWx", "\""),
    concat!("stripe = \"pk_live_", "AbCdEfGhIjKlMnOpQrStUvWx", "\"")
);
rule_case!(
    ss028_stripe_restricted,
    "SS028",
    concat!("stripe = \"rk_live_", "AbCdEfGhIjKlMnOpQrStUvWx", "\""),
    concat!("stripe = \"rk_test_", "AbCdEfGhIjKlMnOpQrStUvWx", "\"")
);
rule_case!(
    ss029_stripe_test,
    "SS029",
    concat!("stripe = \"sk_test_", "AbCdEfGhIjKlMnOpQrStUvWx", "\""),
    "stripe = \"sk_test_short\""
);
rule_case!(
    ss030_stripe_webhook,
    "SS030",
    concat!(
        "stripe = \"whsec_",
        "AbCdEfGhIjKlMnOpQrStUvWxYz012345",
        "\""
    ),
    "stripe = \"whsec_short\""
);

// ---------------- OpenAI / Anthropic ----------------
rule_case!(
    ss031_openai_project,
    "SS031",
    concat!(
        "key = \"sk-proj-",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfGhIjKl",
        "\""
    ),
    "key = \"sk-proj-short\""
);
rule_case!(
    ss032_openai_legacy,
    "SS032",
    concat!(
        "key = \"sk-",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfGhIjKl",
        "\""
    ),
    "key = \"sk-short\""
);
rule_case!(
    ss033_openai_service_account,
    "SS033",
    concat!(
        "key = \"sk-svcacct-",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfGhIjKl",
        "\""
    ),
    "key = \"sk-svcacct-short\""
);
rule_case!(
    ss034_anthropic_api,
    "SS034",
    concat!(
        "key = \"sk-ant-api03-",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfGhIjKl",
        "\""
    ),
    "key = \"sk-ant-api03-short\""
);
rule_case!(
    ss035_anthropic_admin,
    "SS035",
    concat!(
        "key = \"sk-ant-admin01-",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfGhIjKl",
        "\""
    ),
    "key = \"sk-ant-admin01-short\""
);
rule_case!(
    ss036_anthropic_oauth,
    "SS036",
    concat!(
        "key = \"sk-ant-oat01-",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfGhIjKl",
        "\""
    ),
    "key = \"sk-ant-oat01-short\""
);

// ---------------- SendGrid / Twilio / Mail ----------------
rule_case!(
    ss037_sendgrid,
    "SS037",
    concat!(
        "key = \"SG.",
        "AbCdEfGhIjKlMnOpQrStUv",
        ".",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfG",
        "\""
    ),
    "key = \"SG.short.short\""
);
rule_case!(
    ss038_twilio_sid,
    "SS038",
    concat!("key = \"SK", "0123456789abcdef0123456789abcdef", "\""),
    "key = \"SK123\""
);
rule_case!(
    ss039_twilio_auth_token,
    "SS039",
    "twilio_auth_token = \"0123456789abcdef0123456789abcdef\"",
    "twilio_auth_token = \"xyz\""
);
rule_case!(
    ss040_mailgun,
    "SS040",
    concat!("key = \"key-", "0123456789abcdef0123456789abcdef", "\""),
    "key = \"key-123\""
);
rule_case!(
    ss041_mailchimp,
    "SS041",
    concat!("key = \"", "0123456789abcdef0123456789abcdef", "-us7", "\""),
    concat!("key = \"", "0123456789abcdef0123456789abcdef", "-eu1", "\"")
);

// ---------------- Registries ----------------
rule_case!(
    ss042_npm_token,
    "SS042",
    concat!(
        "token = \"npm_",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "\""
    ),
    "token = \"npm_short\""
);
rule_case!(
    ss043_npmrc_auth,
    "SS043",
    concat!(
        "//registry.npmjs.org/:_authToken=",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    ),
    "//registry.npmjs.org/:_authToken=short"
);
rule_case!(
    ss044_pypi_token,
    "SS044",
    concat!(
        "token = \"pypi-AgEIcHlwaS5vcmc",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfGhIjKlMnOp",
        "\""
    ),
    "token = \"pypi-AgEIcHlwaS5vcmcShort\""
);
rule_case!(
    ss045_dockerhub,
    "SS045",
    concat!("token = \"dckr_pat_", "AbCdEfGhIjKlMnOpQrStUvWxYz0", "\""),
    "token = \"dckr_pat_short\""
);

// ---------------- Private keys ----------------
rule_case!(
    ss046_rsa_key,
    "SS046",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN RSA PUBLIC KEY-----"
);
rule_case!(
    ss047_ec_key,
    "SS047",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN EC PUBLIC KEY-----"
);
rule_case!(
    ss048_openssh_key,
    "SS048",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN OPENSSH PUBLIC KEY-----"
);
rule_case!(
    ss049_pgp_key,
    "SS049",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "-----BEGIN PGP MESSAGE-----"
);
rule_case!(
    ss050_pkcs8_key,
    "SS050",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN CERTIFICATE-----"
);
rule_case!(
    ss051_dsa_key,
    "SS051",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN DSA PUBLIC KEY-----"
);
rule_case!(
    ss052_encrypted_key,
    "SS052",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED MESSAGE-----"
);

// ---------------- Tokens and headers ----------------
rule_case!(
    ss053_jwt,
    "SS053",
    concat!(
        "token = \"",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        ".",
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        ".",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "\""
    ),
    "token = \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature\""
);
rule_case!(
    ss054_bearer_header,
    "SS054",
    "Authorization: Bearer AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "Authorization: Bearer short"
);
rule_case!(
    ss055_basic_header,
    "SS055",
    "Authorization: Basic dXNlcjpwYXNzd29yZA==",
    "Authorization: Basic abc"
);
rule_case!(
    ss056_x_api_key,
    "SS056",
    "X-Api-Key: AbCdEfGhIjKlMnOpQrStUvWx",
    "X-Api-Key: short"
);
rule_case!(
    ss057_url_credentials,
    "SS057",
    "endpoint = \"https://admin:Sup3rSecret@db.internal:5432/x\"",
    "endpoint = \"https://user@host/path\""
);

// ---------------- Databases ----------------
rule_case!(
    ss058_postgres_uri,
    "SS058",
    "url = \"postgres://appuser:DbPass123@db.internal:5432/app\"",
    "url = \"postgres://user@host/db\""
);
rule_case!(
    ss059_mysql_uri,
    "SS059",
    "url = \"mysql://root:DbPass123@localhost/app\"",
    "url = \"mysql://user@host/db\""
);
rule_case!(
    ss060_mongodb_uri,
    "SS060",
    "url = \"mongodb+srv://user:DbPass123@cluster.example.net/db\"",
    "url = \"mongodb://user@host/db\""
);
rule_case!(
    ss061_redis_uri,
    "SS061",
    "url = \"redis://:RedisPass123@127.0.0.1:6379/0\"",
    "url = \"redis://host:6379/0\""
);
rule_case!(
    ss062_amqp_uri,
    "SS062",
    "url = \"amqp://guest:GuestPass123@rabbit:5672/vhost\"",
    "url = \"amqp://host/vhost\""
);
rule_case!(
    ss063_jdbc_password,
    "SS063",
    "url = \"jdbc:mysql://db.internal:3306/app?user=u&password=JdbcPass123\"",
    "url = \"jdbc:mysql://host/db?user=u\""
);
rule_case!(
    ss064_sqlserver_connstring,
    "SS064",
    "conn = \"Server=db.internal;Database=app;User Id=sa;Password=SqlPass123;\"",
    "conn = \"Server=host;Database=db;User Id=sa;\""
);

// ---------------- Generic assignments ----------------
rule_case!(
    ss065_generic_password,
    "SS065",
    "DB_PASSWORD=Sup3rSecretPass",
    "password = \"your-password-here\""
);
rule_case!(
    ss066_generic_secret,
    "SS066",
    "client_secret = \"AbCdEfGhIjKlMnOpQrStUvWxYz012345\"",
    "client_secret = \"replace-with-real-secret\""
);
rule_case!(
    ss067_generic_api_key,
    "SS067",
    "api_key = \"AbCdEfGhIjKlMnOpQrStUvWx\"",
    "api_key = \"your-api-key-here\""
);
rule_case!(
    ss068_generic_token,
    "SS068",
    "refresh_token = \"AbCdEfGhIjKlMnOpQrStUvWxYz012345\"",
    "access_token = \"demo-access-token-1234\""
);

// ---------------- SaaS and platforms ----------------
rule_case!(
    ss069_heroku,
    "SS069",
    "HEROKU_API_KEY = 123e4567-e89b-12d3-a456-426614174000",
    "HEROKU_API_KEY = not-a-uuid"
);
rule_case!(
    ss070_square_access,
    "SS070",
    concat!("token = \"sq0atp-", "AbCdEfGhIjKlMnOpQrStUv", "\""),
    "token = \"sq0atp-short\""
);
rule_case!(
    ss071_square_secret,
    "SS071",
    concat!(
        "token = \"sq0csp-",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfG",
        "\""
    ),
    "token = \"sq0csp-short\""
);
rule_case!(
    ss072_shopify_access,
    "SS072",
    concat!("token = \"shpat_", "0123456789abcdef0123456789abcdef", "\""),
    "token = \"shpat_nothexvalue\""
);
rule_case!(
    ss073_shopify_shared,
    "SS073",
    concat!("token = \"shpss_", "0123456789abcdef0123456789abcdef", "\""),
    "token = \"shpss_short\""
);
rule_case!(
    ss074_shopify_custom,
    "SS074",
    concat!("token = \"shpca_", "0123456789abcdef0123456789abcdef", "\""),
    "token = \"shpca_short\""
);
rule_case!(
    ss075_discord_bot,
    "SS075",
    concat!(
        "token = \"",
        "M",
        "AbCdEfGhIjKlMnOpQrStUvW",
        ".",
        "AbCdEf",
        ".",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0",
        "\""
    ),
    "token = \"AbCdEfGhIjKlMnOpQrStUv.AbCdEf.AbCdEfGhIjKlMnOpQrStUvWxYz0\""
);
rule_case!(
    ss076_discord_webhook,
    "SS076",
    concat!(
        "hook = \"https://discord.com/api/webhooks/123456789012345678/",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfGhIjKlMnOpQrStUvWx",
        "\""
    ),
    "hook = \"https://discord.com/api/webhooks/123/abc\""
);
rule_case!(
    ss077_telegram_bot,
    "SS077",
    concat!(
        "token = \"123456789:",
        "AbCdEfGhIjKlMnOpQrStUvWxYz012345678",
        "\""
    ),
    "token = \"12345678:short\""
);
rule_case!(
    ss078_facebook,
    "SS078",
    concat!("token = \"EAACEdEose0cBA", "AbCdEfGhIjKlMnOpQrSt", "\""),
    "token = \"EAACEdEose0cB\""
);
rule_case!(
    ss079_age_key,
    "SS079",
    concat!(
        "key = \"AGE-SECRET-KEY-1",
        "QWERTYUIOPASDFGHJKLZXCVBNM1234567890",
        "QWERTYUIOPASDFGHJKLZXC",
        "\""
    ),
    "key = \"AGE-SECRET-KEY-1SHORT\""
);
rule_case!(
    ss080_vault_token,
    "SS080",
    concat!("token = \"hvs.", "AbCdEfGhIjKlMnOpQrStUvWx", "\""),
    "token = \"hvs.short\""
);
rule_case!(
    ss081_cloudflare,
    "SS081",
    concat!(
        "CF_API_TOKEN = ",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCd"
    ),
    "CF_API_TOKEN = short"
);
rule_case!(
    ss082_digitalocean,
    "SS082",
    concat!(
        "token = \"dop_v1_",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "\""
    ),
    "token = \"dop_v1_short\""
);
rule_case!(
    ss083_huggingface,
    "SS083",
    concat!("token = \"hf_", "AbCdEfGhIjKlMnOpQrStUvWxYz01234567", "\""),
    "token = \"hf_short\""
);
rule_case!(
    ss084_replicate,
    "SS084",
    concat!(
        "token = \"r8_",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "A",
        "\""
    ),
    "token = \"r8_short\""
);
rule_case!(
    ss085_linear,
    "SS085",
    concat!(
        "key = \"lin_api_",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCd",
        "\""
    ),
    "key = \"lin_api_short\""
);
rule_case!(
    ss086_newrelic,
    "SS086",
    concat!("key = \"NRAK-", "ABCDEFGHIJKLMNOPQRSTUVWXYZ1", "\""),
    "key = \"NRAK-SHORT\""
);
rule_case!(
    ss087_fcm_key,
    "SS087",
    concat!(
        "key = \"AAAA",
        "AbCdEfG",
        ":",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "\""
    ),
    "key = \"AAAAAbCdEfG:short\""
);
rule_case!(
    ss088_ethereum_key,
    "SS088",
    concat!(
        "private_key = \"",
        "0123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcdef",
        "\""
    ),
    "private_key = \"0123456789abcdef\""
);
rule_case!(
    ss089_laravel_key,
    "SS089",
    concat!(
        "APP_KEY=base64:",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AbCd=="
    ),
    "APP_KEY=base64:short"
);
rule_case!(
    ss090_grafana_token,
    "SS090",
    concat!(
        "token = \"glsa_",
        "AbCdEfGhIjKlMnOpQrStUvWxYz012345",
        "_0123abcd",
        "\""
    ),
    "token = \"glsa_short\""
);
rule_case!(
    ss091_sonarqube_token,
    "SS091",
    concat!(
        "token = \"sqa_",
        "0123456789abcdef0123456789abcdef",
        "01234567",
        "\""
    ),
    concat!(
        "token = \"sqx_",
        "0123456789abcdef0123456789abcdef",
        "01234567",
        "\""
    )
);
rule_case!(
    ss092_recaptcha,
    "SS092",
    concat!("key = \"6L", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab", "\""),
    "key = \"6Lshort\""
);
rule_case!(
    ss093_planetscale,
    "SS093",
    concat!(
        "token = \"pscale_tkn_",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "AbCd",
        "\""
    ),
    "token = \"pscale_tkn_short\""
);
rule_case!(
    ss094_databricks,
    "SS094",
    concat!("token = \"dapi", "0123456789abcdef0123456789abcdef", "\""),
    "token = \"dapishort\""
);

// ---------------- Licensing platforms ----------------
rule_case!(
    ss095_auth_gg_secret,
    "SS095",
    concat!(
        "// auth.gg application secret = \"",
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "\""
    ),
    "auth.gg is a licensing platform for software sellers"
);

// ---------------- Cryptocurrency addresses ----------------
rule_case!(
    ss096_ethereum_address,
    "SS096",
    concat!(
        "payout_address = \"0x",
        "de0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        "\""
    ),
    "commit = \"de0b295669a9fd93d5f28d9ec85e40f4cb697bae\""
);
rule_case!(
    ss097_bitcoin_address,
    "SS097",
    "payout = \"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\"",
    concat!(
        "payout = \"0x",
        "de0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
        "\""
    )
);

// ---------------- Malware indicators ----------------
rule_case!(
    ss098_private_key_persistence,
    "SS098",
    "fs::write(&path, &pk_hex).unwrap();",
    "let pk_hex = derive_key(&seed);"
);
rule_case!(
    ss099_file_host_archive_link,
    "SS099",
    "Download: https://www.4sync.com/zip/AbCdEfGh/Project_V193.html",
    "https://github.com/example/project/releases/download/v1.0/tool.zip"
);

#[test]
fn ss096_longer_hex_after_0x_is_not_an_address() {
    // 0x plus 64 hex characters is private-key length, not an
    // address; the word boundary must reject it.
    let line = concat!(
        "value = \"0x",
        "0123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcdef",
        "\""
    );
    assert!(!has_rule(line, "SS096"));
}

#[test]
fn ss097_bech32_address_matches() {
    // BIP-173 test vector address.
    assert!(has_rule(
        "payout = \"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\"",
        "SS097"
    ));
}

#[test]
fn ss098_write_without_key_material_is_clean() {
    assert!(!has_rule("fs::write(&path, &report).unwrap();", "SS098"));
    assert!(!has_rule(
        "fs.writeFileSync(\"notes.txt\", JSON.stringify(privateNotes));",
        "SS098"
    ));
}

#[test]
fn ss098_javascript_write_of_a_private_key_matches() {
    assert!(has_rule(
        "fs.writeFileSync(\"key.txt\", privateKey);",
        "SS098"
    ));
}

#[test]
fn ss099_file_host_homepage_alone_is_clean() {
    assert!(!has_rule("mirror: https://www.4sync.com/", "SS099"));
    assert!(!has_rule("docs at https://www.sendspace.com/help", "SS099"));
}

#[test]
fn ss099_direct_download_paths_without_archive_extension_match() {
    // Wave 2 miss: a 4sync directDownload URL carries no archive
    // extension, and a sendspace /file/ path is the download itself.
    assert!(has_rule(
        "Get it: https://www.4sync.com/web/directDownload/AbCdEfGh/Project_V193",
        "SS099"
    ));
    assert!(has_rule(
        "Mirror: https://www.sendspace.com/file/xYz123Ab",
        "SS099"
    ));
    assert!(has_rule(
        "Link: https://anonfiles.com/d/AbCdEfGh?download=1",
        "SS099"
    ));
}

#[test]
fn ss099_shortener_with_a_download_signal_matches() {
    // The Adobe lure pushed its download through a shortener with
    // the signal in the surrounding text, not in the URL.
    assert!(has_rule("Download: https://cutt.ly/AbC123x", "SS099"));
    assert!(has_rule(
        "Mirror (installer): https://rb.gy/xy12ab",
        "SS099"
    ));
    assert!(has_rule(
        "Get it at https://tinyurl.com/abcd1234, setup included",
        "SS099"
    ));
    assert!(has_rule(
        "Loader.zip mirror: https://bit.ly/3XyZ987",
        "SS099"
    ));
}

#[test]
fn ss099_bare_shortener_without_a_signal_is_clean() {
    assert!(!has_rule("Our page: https://bit.ly/3XyZ987", "SS099"));
    assert!(!has_rule("https://cutt.ly/AbC123x", "SS099"));
    assert!(!has_rule(
        "Release notes moved: https://tinyurl.com/abcd1234",
        "SS099"
    ));
}

// ---------------- Antivirus-disable instructions ----------------
rule_case!(
    ss100_antivirus_disable_instruction,
    "SS100",
    "Step 4: disable Defender antivirus protection, then run the installer",
    "Windows Defender detected the file and blocked it"
);

#[test]
fn ss100_instruction_variants_match() {
    assert!(has_rule(
        "Please turn off real-time protection first",
        "SS100"
    ));
    assert!(has_rule(
        "Disable your antivirus before installing",
        "SS100"
    ));
    assert!(has_rule(
        "switch off Windows Security, then install",
        "SS100"
    ));
    assert!(has_rule(
        "You must disable Windows Defender real-time protection",
        "SS100"
    ));
    assert!(has_rule("Deactivate the antivirus and retry", "SS100"));
}

#[test]
fn ss100_detection_context_is_clean() {
    assert!(!has_rule("Detected by Windows Defender", "SS100"));
    assert!(!has_rule(
        "The antivirus flagged the download as a trojan",
        "SS100"
    ));
    assert!(!has_rule(
        "Keep your antivirus enabled and up to date",
        "SS100"
    ));
    assert!(!has_rule(
        "Antivirus protection is disabled by group policy",
        "SS100"
    ));
}
