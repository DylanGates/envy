//! Executes an authenticated request to a provider on behalf of a
//! capability caller, using a vault-stored secret the caller never sees
//! (FR-11's `make_authenticated_request`) and applying FR-12's
//! redaction: the injected credential value never appears in any error
//! or log message this module produces.

use std::time::Duration;

use crate::error::CoreError;
use crate::policy::{self, PolicyDecision, PolicyRequest};
use crate::provider::Registry;
use crate::provider::descriptor::{CredentialDescriptor, ProviderDescriptor};
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

    // Use the first credential descriptor. Future work: callers may
    // specify a credential name to select from multiple kinds on the same
    // provider (e.g. "api_key" vs "webhook_secret").
    let cred = descriptor.credentials.first().ok_or_else(|| {
        CoreError::InvalidRequest(format!(
            "provider '{}' has no credentials configured",
            req.provider_id
        ))
    })?;

    let has_active_consent = vault.has_active_consent(&descriptor.id, "make_authenticated_request")?;
    let policy_request = PolicyRequest {
        operation: "make_authenticated_request",
        provider: Some(&descriptor.id),
        domain: descriptor.domains.first().map(String::as_str),
        agent_identity: None,
        method: req.method,
        has_active_consent,
    };
    match policy::evaluate(&policy_request) {
        PolicyDecision::Allow => {}
        PolicyDecision::RequireConsent { reason } => {
            return Err(CoreError::ConsentRequired(reason));
        }
        PolicyDecision::Deny { reason } => return Err(CoreError::PolicyDenied(reason)),
    }

    let secret_value = vault.get_secret(req.secret_name)?;
    let secret_value = String::from_utf8(secret_value)
        .map_err(|_| CoreError::Http("stored credential is not valid UTF-8".to_string()))?;

    let url = build_url(&descriptor.domains, req.path, &req.query)?;
    let headers = auth_headers(cred, &secret_value);

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

    // The credential value must never reach the caller, even if the
    // provider echoes it back in its response body — not just kept out of
    // logs (see `docs/provider-testing-vision.md`'s threat model).
    let leaked_in_body = body.contains(&secret_value);
    let body = crate::redact::redact_body(&body, &secret_value);

    let outcome = if (200..300).contains(&status) {
        "success"
    } else {
        "error"
    };
    let redaction_summary = if leaked_in_body {
        "Authorization/auth header redacted from logs; secret value found and redacted from response body"
    } else {
        "Authorization/auth header redacted from logs"
    };
    vault.log_event(&crate::audit::AuditEvent {
        subject: Some("mcp-adapter"),
        project: None,
        provider: Some(&descriptor.id),
        operation: "make_authenticated_request",
        endpoint_host: url.host_str(),
        outcome,
        redaction_summary: Some(redaction_summary),
    })?;

    Ok(AuthenticatedResponse {
        status,
        mapped_status: map_status(descriptor, status).to_string(),
        body,
    })
}

/// Builds a URL from the provider's domain list and a caller-supplied
/// relative path, then verifies the resulting host is within `domains`.
/// This is the security boundary that prevents steering authenticated
/// requests at an arbitrary host (see `docs/intent.md`).
pub(crate) fn build_url(
    domains: &[String],
    path: &str,
    query: &[(String, String)],
) -> Result<url::Url, CoreError> {
    let domain = domains
        .first()
        .ok_or_else(|| CoreError::Http("provider has no configured domains".to_string()))?;
    let base = url::Url::parse(&format!("https://{domain}/"))
        .map_err(|e| CoreError::Http(format!("invalid domain in descriptor: {e}")))?;
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
    if !domains.iter().any(|d| d == host) {
        return Err(CoreError::RequestBlocked(format!(
            "host '{host}' is not in this provider's allowed domains"
        )));
    }

    Ok(joined)
}

/// Builds the headers that inject the credential, per the credential
/// descriptor's `auth_style`.
fn auth_headers(cred: &CredentialDescriptor, secret_value: &str) -> Vec<(String, String)> {
    crate::auth::build_auth_headers(
        &cred.auth_style,
        cred.header_name.as_deref(),
        &cred.extra_headers,
        secret_value,
    )
}

/// Maps an HTTP status to a provider-defined envy status word using the
/// first health check's `status_mapping`. Returns `"unknown"` when no
/// mapping is configured — never treats an unmapped status as invalid.
pub(crate) fn map_status(descriptor: &ProviderDescriptor, status: u16) -> &str {
    descriptor
        .health_checks
        .first()
        .and_then(|hc| hc.status_mapping.get(&status.to_string()))
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

    // Inline test fixtures using the array-based schema
    // (docs/provider-testing-vision.md §"Schema evolution").
    const STRIPE_LIKE: &str = r#"
id = "stripe"
name = "Stripe"
domains = ["api.stripe.com"]

[[credentials]]
name = "api_key"
aliases = ["STRIPE_SECRET_KEY", "STRIPE_API_KEY", "STRIPE_KEY"]
prefixes = ["sk_live_", "sk_test_"]
auth_style = "bearer"
risk = "high"

[[health_checks]]
id = "balance"
method = "GET"
path = "/v1/balance"
safe = true
success_statuses = [200]
status_mapping = { "200" = "valid", "401" = "invalid" }
"#;

    const ANTHROPIC_LIKE: &str = r#"
id = "anthropic"
name = "Anthropic"
domains = ["api.anthropic.com"]

[[credentials]]
name = "api_key"
aliases = ["ANTHROPIC_API_KEY"]
prefixes = ["sk-ant-"]
auth_style = "header"
header_name = "x-api-key"
extra_headers = { "anthropic-version" = "2023-06-01" }
risk = "high"

[[health_checks]]
id = "models"
method = "GET"
path = "/v1/models"
safe = true
success_statuses = [200]
"#;

    fn stripe_descriptor() -> ProviderDescriptor {
        toml::from_str(STRIPE_LIKE).unwrap()
    }

    fn anthropic_descriptor() -> ProviderDescriptor {
        toml::from_str(ANTHROPIC_LIKE).unwrap()
    }

    #[test]
    fn build_url_joins_domain_and_path_with_query() {
        let domains = vec!["api.stripe.com".to_string()];
        let url = build_url(
            &domains,
            "/v1/balance",
            &[("expand".to_string(), "a".to_string())],
        )
        .unwrap();
        assert_eq!(url.as_str(), "https://api.stripe.com/v1/balance?expand=a");
    }

    #[test]
    fn build_url_rejects_host_outside_allowed_domains() {
        let domains = vec!["api.stripe.com".to_string()];
        // An absolute URL as path must not escape to another host.
        let result = build_url(&domains, "https://evil.example.com/steal", &[]);
        assert!(matches!(result, Err(CoreError::RequestBlocked(_))));
    }

    #[test]
    fn build_url_rejects_path_traversal_out_of_the_provider() {
        let domains = vec!["api.stripe.com".to_string()];
        let result = build_url(&domains, "../../evil.example.com/", &[]);
        // Either blocked outright or resolves onto api.stripe.com — never
        // onto any other host.
        if let Ok(url) = result {
            assert_eq!(url.host_str(), Some("api.stripe.com"));
        }
    }

    #[test]
    fn auth_headers_wraps_bearer_style_credential() {
        let descriptor = stripe_descriptor();
        let cred = descriptor.credentials.first().unwrap();
        let headers = auth_headers(cred, "sk_live_abc123");
        assert_eq!(
            headers,
            vec![(
                "Authorization".to_string(),
                "Bearer sk_live_abc123".to_string()
            )]
        );
    }

    #[test]
    fn auth_headers_wraps_header_style_credential_with_extra_headers() {
        let descriptor = anthropic_descriptor();
        let cred = descriptor.credentials.first().unwrap();
        let headers = auth_headers(cred, "sk-ant-abc123");
        let map: HashMap<_, _> = headers.into_iter().collect();
        assert_eq!(map.get("x-api-key"), Some(&"sk-ant-abc123".to_string()));
        assert_eq!(
            map.get("anthropic-version"),
            Some(&"2023-06-01".to_string())
        );
    }

    #[test]
    fn map_status_known_and_unknown_codes() {
        let descriptor = stripe_descriptor();
        assert_eq!(map_status(&descriptor, 200), "valid");
        assert_eq!(map_status(&descriptor, 401), "invalid");
        assert_eq!(map_status(&descriptor, 999), "unknown");
    }

    #[test]
    fn map_status_returns_unknown_when_no_health_checks_configured() {
        // A provider with no health checks should not panic — unknown is
        // the safe default (never report invalid without evidence).
        let descriptor: ProviderDescriptor = toml::from_str(
            r#"
id = "bare"
name = "Bare"
domains = ["api.bare.com"]

[[credentials]]
name = "api_key"
aliases = ["BARE_KEY"]
auth_style = "bearer"
"#,
        )
        .unwrap();
        assert_eq!(map_status(&descriptor, 200), "unknown");
        assert_eq!(map_status(&descriptor, 401), "unknown");
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

    #[test]
    fn execute_fails_when_provider_has_no_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = crate::keychain::InMemoryKeyStore::new();
        let vault = crate::vault::init_with_keystore(dir.path(), &keystore).unwrap();
        let descriptor: ProviderDescriptor = toml::from_str(
            r#"
id = "empty"
name = "Empty"
domains = ["api.empty.com"]
"#,
        )
        .unwrap();
        let registry = Registry::from_descriptors(vec![descriptor]);

        let req = AuthenticatedRequest {
            provider_id: "empty",
            secret_name: "EMPTY_KEY",
            method: "GET",
            path: "/",
            query: vec![],
        };
        let result = execute(&vault, &registry, &req);
        assert!(matches!(result, Err(CoreError::InvalidRequest(_))));
    }

    #[test]
    #[ignore = "touches the real network"]
    fn execute_over_real_network_allows_non_get_with_consent_and_redacts_response() {
        // Exercises the full new path end to end against a real endpoint:
        // a non-GET call fails closed without consent (existing coverage,
        // execute_fails_closed_on_non_get_method), then succeeds once
        // `Vault::grant_consent` has been called — and httpbin.org's
        // /delete endpoint conveniently echoes request headers back in its
        // JSON response body, which doubles as a real-world proof that
        // the leaked credential never reaches the caller.
        let dir = tempfile::tempdir().unwrap();
        let keystore = crate::keychain::InMemoryKeyStore::new();
        let vault = crate::vault::init_with_keystore(dir.path(), &keystore).unwrap();
        let secret_value = "envy-live-test-token-do-not-leak";
        vault.add_secret("HTTPBIN_KEY", secret_value.as_bytes()).unwrap();
        vault
            .grant_consent(
                "httpbin",
                "make_authenticated_request",
                std::time::Duration::from_secs(300),
                Some("test"),
            )
            .unwrap();

        let descriptor: ProviderDescriptor = toml::from_str(
            r#"
id = "httpbin"
name = "httpbin"
domains = ["httpbin.org"]

[[credentials]]
name = "api_key"
aliases = ["HTTPBIN_KEY"]
auth_style = "bearer"
"#,
        )
        .unwrap();
        let registry = Registry::from_descriptors(vec![descriptor]);

        let req = AuthenticatedRequest {
            provider_id: "httpbin",
            secret_name: "HTTPBIN_KEY",
            method: "DELETE",
            path: "/delete",
            query: vec![],
        };

        let response =
            execute(&vault, &registry, &req).expect("consent should have unblocked this non-GET call");
        assert_eq!(response.status, 200);
        assert!(!response.body.contains(secret_value), "secret leaked into response body");
        assert!(response.body.contains("[REDACTED]"), "expected the echoed header to be redacted");
    }
}
