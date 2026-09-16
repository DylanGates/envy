//! Provider descriptor schema (PRD §10). Purely data shapes — no behavior.
//! Uses arrays for credentials and health checks so a single provider can
//! declare multiple credential kinds and health-check operations without
//! any Rust code changes. See `docs/provider-testing-vision.md` for the
//! vision this schema implements.

use std::collections::HashMap;

use serde::Deserialize;

/// Top-level provider descriptor, loaded from a `.toml` file.
///
/// Adding a provider = adding a `.toml` file to the user provider directory
/// (`envy provider validate` checks it first). No recompilation needed.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderDescriptor {
    /// Stable, lowercase identifier (e.g. `"openai"`). Primary key in the
    /// registry and in `make_authenticated_request` calls.
    pub id: String,
    /// Human-readable display name (e.g. `"OpenAI"`).
    pub name: String,
    /// Documentation URL for this provider.
    #[serde(default)]
    pub docs_url: Option<String>,
    /// Credential rotation guidance URL.
    #[serde(default)]
    pub rotation_url: Option<String>,
    /// Allowed hostnames for all outbound requests. The first entry is used
    /// as the base host when building URLs from relative paths. Every
    /// resolved URL's host must appear in this list — this is the domain
    /// allow-list that prevents steering authenticated requests at an
    /// arbitrary host (see `docs/intent.md` operating constraints).
    pub domains: Vec<String>,
    /// One entry per credential kind this provider accepts (e.g. API key,
    /// webhook secret). A provider may have more than one.
    #[serde(default)]
    pub credentials: Vec<CredentialDescriptor>,
    /// Read-only health-check operations. The first entry is the default
    /// for `envy check` (level-1 testing from provider-testing-vision.md).
    #[serde(default)]
    pub health_checks: Vec<HealthCheckDescriptor>,
}

/// One credential kind a provider accepts (e.g. "api_key", "webhook_secret").
#[derive(Debug, Clone, Deserialize)]
pub struct CredentialDescriptor {
    /// Short, stable name for this credential kind (e.g. `"api_key"`).
    /// Used as a label in findings and as a selector in capability calls.
    pub name: String,
    /// Variable name aliases that identify this credential in project files
    /// (e.g. `["OPENAI_API_KEY"]`). Case-insensitive during classification.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Token value prefixes that identify this credential by shape
    /// (e.g. `["sk-"]`). Matched as a string prefix of the candidate value.
    #[serde(default)]
    pub prefixes: Vec<String>,
    /// How the credential is injected into a request:
    /// - `"bearer"` → `Authorization: Bearer <value>`
    /// - `"header"` → custom header named by `header_name`
    pub auth_style: String,
    /// Header name when `auth_style = "header"`. Required for header-style
    /// injection; ignored for bearer.
    #[serde(default)]
    pub header_name: Option<String>,
    /// Fixed additional headers always sent alongside this credential
    /// (e.g. `{"anthropic-version": "2023-06-01"}`).
    #[serde(default)]
    pub extra_headers: HashMap<String, String>,
    /// Default risk rating: `"low"`, `"medium"`, or `"high"`.
    #[serde(default = "default_risk")]
    pub risk: String,
}

fn default_risk() -> String {
    "medium".to_string()
}

/// One read-only health-check operation for a provider.
#[derive(Debug, Clone, Deserialize)]
pub struct HealthCheckDescriptor {
    /// Stable ID for this health check (e.g. `"models"`, `"account"`).
    pub id: String,
    /// HTTP method. Only `"GET"` is treated as safe by default; anything
    /// else requires explicit consent before the trusted core will execute it.
    pub method: String,
    /// Path relative to the provider's first domain, e.g. `"/v1/models"`.
    pub path: String,
    /// True when this operation is purely read-only with no side effects.
    /// Defaults to `true`. Set to `false` for any check that writes state.
    #[serde(default = "default_true")]
    pub safe: bool,
    /// HTTP status codes that indicate a valid, active credential.
    #[serde(default)]
    pub success_statuses: Vec<u16>,
    /// Maps HTTP status codes (as strings) to envy status words:
    /// `"valid"`, `"invalid"`, `"expired"`, `"limited"`, or `"unknown"`.
    #[serde(default)]
    pub status_mapping: HashMap<String, String>,
    /// Response header/field names to scrub from audit logs.
    #[serde(default)]
    pub redaction_fields: Vec<String>,
}

fn default_true() -> bool {
    true
}
