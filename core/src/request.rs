//! Executes an authenticated request to a provider on behalf of a
//! capability caller, using a vault-stored secret the caller never sees
//! (FR-11's `make_authenticated_request`) and applying FR-12's
//! redaction: the injected credential value never appears in any error
//! or log message this module produces.

use std::time::Duration;

use crate::error::CoreError;
use crate::policy::{self, PolicyDecision, PolicyRequest};
use crate::provider::{ProviderDescriptor, Registry};
use crate::vault::Vault;

pub struct AuthenticatedRequest<'a> {
    pub provider_id: &'a str,
    pub secret_name: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub query: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedResponse {
    pub status: u16,
    pub mapped_status: String,
    pub body: String,
}

pub fn execute(
    vault: &Vault,
    registry: &Registry,
    req: &AuthenticatedRequest,
) -> Result<AuthenticatedResponse, CoreError> {
    let descriptor = registry
        .descriptors()
        .iter()
        .find(|d| d.id == req.provider_id)
        .ok_or_else(|| CoreError::ProviderNotFound(req.provider_id.to_string()))?;

    let policy_request = PolicyRequest {
        operation: "make_authenticated_request",
        provider: Some(&descriptor.id),
        domain: descriptor.network.allowed_domains.first().map(String::as_str),
        agent_identity: None,
        method: req.method,
    };
    match policy::evaluate(&policy_request) {
        PolicyDecision::Allow => {}
        PolicyDecision::RequireConsent { reason } => return Err(CoreError::ConsentRequired(reason)),
        PolicyDecision::Deny { reason } => return Err(CoreError::PolicyDenied(reason)),
    }

    let secret_value = vault.get_secret(req.secret_name)?;
    let secret_value = String::from_utf8(secret_value)
        .map_err(|_| CoreError::Http("stored credential is not valid UTF-8".to_string()))?;

    let url = build_url(descriptor, req.path, &req.query)?;
    let headers = auth_headers(descriptor, &secret_value);

    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(10)))
        .build();
    let agent: ureq::Agent = config.into();

    let mut builder = match req.method.to_ascii_uppercase().as_str() {
        "GET" => agent.get(url.as_str()),
        "DELETE" => agent.delete(url.as_str()),
        "HEAD" => agent.head(url.as_str()),
        other => {
            return Err(CoreError::Http(format!(
                "method '{other}' requires a request body, which isn't supported yet"
            )));
        }
    };
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }

    let mut response = builder
        .call()
        .map_err(|e| CoreError::Http(describe_transport_error(&e)))?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|e| CoreError::Http(format!("failed to read response body: {e}")))?;

    let outcome = if (200..300).contains(&status) { "success" } else { "error" };
    vault.log_event(&crate::audit::AuditEvent {
        subject: Some("mcp-adapter"),
        project: None,
        provider: Some(&descriptor.id),
        operation: "make_authenticated_request",
        endpoint_host: url.host_str(),
        outcome,
        redaction_summary: Some("Authorization/auth header redacted from logs"),
    })?;

    Ok(AuthenticatedResponse {
        status,
        mapped_status: map_status(descriptor, status).to_string(),
        body,
    })
}

/// Builds the target URL from the descriptor's `base_url` + a
/// caller-supplied path and query, then verifies the resulting host is
/// in `allowed_domains` — the security boundary preventing a caller from
/// steering an "authenticated" request at an arbitrary host.
fn build_url(
    descriptor: &ProviderDescriptor,
    path: &str,
    query: &[(String, String)],
) -> Result<url::Url, CoreError> {
    let base = url::Url::parse(&descriptor.network.base_url)
        .map_err(|e| CoreError::Http(format!("invalid base_url in descriptor: {e}")))?;
    let mut joined = base
        .join(path.trim_start_matches('/'))
        .map_err(|e| CoreError::RequestBlocked(format!("invalid path '{path}': {e}")))?;

    {
        let mut pairs = joined.query_pairs_mut();
        for (key, value) in query {
            pairs.append_pair(key, value);
        }
    }

    let host = joined
        .host_str()
        .ok_or_else(|| CoreError::RequestBlocked("URL has no host".to_string()))?;
    if !descriptor.network.allowed_domains.iter().any(|d| d == host) {
        return Err(CoreError::RequestBlocked(format!(
            "host '{host}' is not in this provider's allowed_domains"
        )));
    }

    Ok(joined)
}

/// Builds the headers that inject the credential, per the descriptor's
/// `auth.style`.
fn auth_headers(descriptor: &ProviderDescriptor, secret_value: &str) -> Vec<(String, String)> {
    crate::auth::build_auth_headers(
        &descriptor.auth.style,
        descriptor.auth.header_name.as_deref(),
        &descriptor.auth.extra_headers,
        secret_value,
    )
}

fn map_status(descriptor: &ProviderDescriptor, status: u16) -> &str {
    descriptor
        .health_check
        .status_mapping
        .get(&status.to_string())
        .map(String::as_str)
        .unwrap_or("unknown")
}

/// Describes a ureq transport error without ever including request
/// headers (which would include the injected credential).
fn describe_transport_error(err: &ureq::Error) -> String {
    format!("transport error: {err}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // No bundled provider files exist right now (removed to be rebuilt
    // under the array-based schema in docs/provider-testing-vision.md),
    // so these tests build minimal descriptors inline instead of reading
    // real provider `.toml` files.

    const STRIPE_LIKE: &str = r#"
id = "stripe"
name = "Stripe"
[detection]
aliases = ["STRIPE_SECRET_KEY", "STRIPE_API_KEY", "STRIPE_KEY"]
prefixes = ["sk_live_", "sk_test_"]
[credential]
kind = "api_key"
risk = "high"
[network]
base_url = "https://api.stripe.com"
allowed_domains = ["api.stripe.com"]
[auth]
style = "bearer"
[health_check]
method = "GET"
url = "https://api.stripe.com/v1/balance"
[health_check.status_mapping]
"200" = "valid"
"401" = "invalid"
[redaction]
fields = ["Authorization"]
[docs]
"#;

    const ANTHROPIC_LIKE: &str = r#"
id = "anthropic"
name = "Anthropic"
[detection]
aliases = ["ANTHROPIC_API_KEY"]
prefixes = ["sk-ant-"]
[credential]
kind = "api_key"
risk = "high"
[network]
base_url = "https://api.anthropic.com"
allowed_domains = ["api.anthropic.com"]
[auth]
style = "header"
header_name = "x-api-key"
extra_headers = { "anthropic-version" = "2023-06-01" }
[health_check]
method = "GET"
url = "https://api.anthropic.com/v1/models"
[redaction]
fields = ["x-api-key"]
[docs]
"#;

    fn stripe_descriptor() -> ProviderDescriptor {
        toml::from_str(STRIPE_LIKE).unwrap()
    }

    fn anthropic_descriptor() -> ProviderDescriptor {
        toml::from_str(ANTHROPIC_LIKE).unwrap()
    }

    #[test]
    fn build_url_joins_base_and_path_with_query() {
        let descriptor = stripe_descriptor();
        let url = build_url(&descriptor, "/v1/balance", &[("expand".to_string(), "a".to_string())]).unwrap();
        assert_eq!(url.as_str(), "https://api.stripe.com/v1/balance?expand=a");
    }

    #[test]
    fn build_url_rejects_host_outside_allowed_domains() {
        let descriptor = stripe_descriptor();
        // Absolute-URL-shaped "path" attempting to escape to another host.
        let result = build_url(&descriptor, "https://evil.example.com/steal", &[]);
        assert!(matches!(result, Err(CoreError::RequestBlocked(_))));
    }

    #[test]
    fn build_url_rejects_path_traversal_out_of_the_provider() {
        let descriptor = stripe_descriptor();
        let result = build_url(&descriptor, "../../evil.example.com/", &[]);
        // Either blocked outright, or resolves back onto api.stripe.com
        // (the only host build_url is allowed to keep) — never anything
        // else.
        if let Ok(url) = result {
            assert_eq!(url.host_str(), Some("api.stripe.com"));
        }
    }

    // Full auth-header-building coverage (bearer, header style, extra
    // headers, unknown-style fallback) lives in `auth.rs`'s own tests,
    // against the generic function this wrapper delegates to. These two
    // just confirm the wrapper passes the right descriptor fields through.
    #[test]
    fn auth_headers_wraps_bearer_style_descriptor() {
        let descriptor = stripe_descriptor();
        let headers = auth_headers(&descriptor, "sk_live_abc123");
        assert_eq!(headers, vec![("Authorization".to_string(), "Bearer sk_live_abc123".to_string())]);
    }

    #[test]
    fn auth_headers_wraps_header_style_descriptor_with_extra_headers() {
        let descriptor = anthropic_descriptor();
        let headers = auth_headers(&descriptor, "sk-ant-abc123");
        let map: HashMap<_, _> = headers.into_iter().collect();
        assert_eq!(map.get("x-api-key"), Some(&"sk-ant-abc123".to_string()));
        assert_eq!(map.get("anthropic-version"), Some(&"2023-06-01".to_string()));
    }

    #[test]
    fn map_status_known_and_unknown_codes() {
        let descriptor = stripe_descriptor();
        assert_eq!(map_status(&descriptor, 200), "valid");
        assert_eq!(map_status(&descriptor, 401), "invalid");
        assert_eq!(map_status(&descriptor, 999), "unknown");
    }

    #[test]
    fn execute_fails_with_provider_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = crate::keychain::InMemoryKeyStore::new();
        let vault = crate::vault::init_with_keystore(dir.path(), &keystore).unwrap();
        let registry = Registry::from_descriptors(vec![stripe_descriptor()]);

        let req = AuthenticatedRequest {
            provider_id: "not-a-real-provider",
            secret_name: "whatever",
            method: "GET",
            path: "/",
            query: vec![],
        };
        let result = execute(&vault, &registry, &req);
        assert!(matches!(result, Err(CoreError::ProviderNotFound(_))));
    }

    #[test]
    fn execute_fails_with_secret_not_found_before_any_network_call() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = crate::keychain::InMemoryKeyStore::new();
        let vault = crate::vault::init_with_keystore(dir.path(), &keystore).unwrap();
        let registry = Registry::from_descriptors(vec![stripe_descriptor()]);

        let req = AuthenticatedRequest {
            provider_id: "stripe",
            secret_name: "STRIPE_KEY", // never added
            method: "GET",
            path: "/v1/balance",
            query: vec![],
        };
        let result = execute(&vault, &registry, &req);
        assert!(matches!(result, Err(CoreError::SecretNotFound(_))));
    }

    #[test]
    fn execute_fails_closed_on_non_get_method() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = crate::keychain::InMemoryKeyStore::new();
        let vault = crate::vault::init_with_keystore(dir.path(), &keystore).unwrap();
        vault.add_secret("STRIPE_KEY", b"sk_live_abc123").unwrap();
        let registry = Registry::from_descriptors(vec![stripe_descriptor()]);

        let req = AuthenticatedRequest {
            provider_id: "stripe",
            secret_name: "STRIPE_KEY",
            method: "POST",
            path: "/v1/charges",
            query: vec![],
        };
        let result = execute(&vault, &registry, &req);
        assert!(matches!(result, Err(CoreError::ConsentRequired(_))));
    }
}
