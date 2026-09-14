//! The provider descriptor schema (PRD §10). Purely data shapes — no
//! behavior. `health_check`/`auth`/`redaction` are parsed and stored
//! correctly but not executed anywhere yet; that's separately-scoped
//! future work once a real HTTP client exists.

use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderDescriptor {
    pub id: String,
    pub name: String,
    pub detection: Detection,
    pub credential: Credential,
    pub network: Network,
    pub auth: Auth,
    pub health_check: HealthCheck,
    pub redaction: Redaction,
    pub docs: Docs,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Detection {
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub prefixes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Credential {
    pub kind: String,
    pub risk: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Network {
    pub base_url: String,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Auth {
    /// How the credential is injected into a request: "bearer" (an
    /// `Authorization: Bearer <value>` header) or "header" (a custom
    /// header named by `header_name`).
    pub style: String,
    #[serde(default)]
    pub header_name: Option<String>,
    #[serde(default)]
    pub extra_headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HealthCheck {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub status_mapping: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Redaction {
    #[serde(default)]
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Docs {
    #[serde(default)]
    pub documentation_url: Option<String>,
    #[serde(default)]
    pub rotation_url: Option<String>,
}
