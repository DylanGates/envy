//! Credential testing — `docs/provider-testing-vision.md`'s levels 1, 2,
//! and 4:
//! - Level 4, `check_adhoc`: the caller supplies a secret name, a URL, and
//!   an auth style directly, with no provider descriptor or registry
//!   lookup involved. The "universal" half of `check_credential` (FR-11).
//! - Level 1, `check_cataloged`: the caller names an installed provider by
//!   id; envy runs that provider's own cataloged, verified `health_check`.
//! - Level 2 falls out of level 1: a recognized provider with zero
//!   `[[health_checks]]` configured reports `CredentialStatus::NotAttempted`
//!   rather than erroring or guessing an endpoint.
//! Level 3 (unknown-secret entropy detection) is scan-time work, not here.
//!
//! Hard guardrails (see `docs/intent.md`): HTTPS only; always a GET, never
//! a write/destructive method; ad-hoc mode's caller-supplied `url` is
//! their explicit consent for this one call, cataloged mode's provider
//! domain was already reviewed at `provider install`/`validate` time —
//! envy never guesses or probes multiple endpoints in either mode; a
//! network failure or unrecognized status maps to `Unknown`, never
//! `Invalid` — a credential is never blamed for an outage.

use std::time::Duration;

use crate::error::CoreError;
use crate::policy::{self, PolicyDecision, PolicyRequest};
use crate::provider::Registry;
use crate::vault::Vault;

pub struct AdHocCheckRequest<'a> {
    /// Who's asking — `"cli"` or `"mcp-adapter"` — recorded in the audit
    /// event so it's clear where the check actually came from.
    pub subject: &'a str,
    pub secret_name: &'a str,
    pub url: &'a str,
    pub auth_style: &'a str,
    pub header_name: Option<&'a str>,
}

/// Level 1: check a stored secret against a specific, installed
/// provider's cataloged health check. `provider_id` is required and
/// explicit — envy never infers which provider a secret belongs to by
/// re-classifying its value (see `docs/intent.md`'s "never guess" rule).
pub struct CatalogedCheckRequest<'a> {
    pub subject: &'a str,
    pub secret_name: &'a str,
    pub provider_id: &'a str,
}

/// The full status vocabulary from `docs/ontology.md`'s "Health check"
/// entry / `HealthCheckDescriptor::status_mapping`'s doc comment. Ad-hoc
/// mode (no `status_mapping` to consult) can only ever produce
/// `Valid`/`Invalid`/`Unknown`; `Expired`/`Limited` are only reachable
/// through a descriptor's own mapping, and `NotAttempted` only through
/// `check_cataloged`'s level-2 fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialStatus {
    Valid,
    Invalid,
    Expired,
    Limited,
    Unknown,
    NotAttempted,
}

impl CredentialStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialStatus::Valid => "valid",
            CredentialStatus::Invalid => "invalid",
            CredentialStatus::Expired => "expired",
            CredentialStatus::Limited => "limited",
            CredentialStatus::Unknown => "unknown",
            CredentialStatus::NotAttempted => "not_attempted",
        }
    }

    /// Parses a descriptor's `status_mapping` word (from
    /// `request::map_status`) into the typed status. Anything
    /// unrecognized falls through to `Unknown`, never `Invalid` —
    /// preserves the "never blame the credential for an outage" guardrail
    /// even if a descriptor's `status_mapping` contains a typo.
    pub fn from_word(word: &str) -> CredentialStatus {
        match word {
            "valid" => CredentialStatus::Valid,
            "invalid" => CredentialStatus::Invalid,
            "expired" => CredentialStatus::Expired,
            "limited" => CredentialStatus::Limited,
            _ => CredentialStatus::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub status: CredentialStatus,
    pub http_status: Option<u16>,
    /// Human-readable explanation, populated for `NotAttempted` (why
    /// nothing was tried) — `None` in every other case.
    pub detail: Option<String>,
}

pub fn check_adhoc(vault: &Vault, req: &AdHocCheckRequest) -> Result<CheckResult, CoreError> {
    let url = url::Url::parse(req.url)
        .map_err(|e| CoreError::InvalidRequest(format!("invalid url: {e}")))?;
    if url.scheme() != "https" {
        return Err(CoreError::RequestBlocked(
            "only https URLs are allowed for credential checks".to_string(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| CoreError::RequestBlocked("URL has no host".to_string()))?
        .to_string();

    if req.auth_style == "header" && req.header_name.is_none() {
        return Err(CoreError::InvalidRequest(
            "auth_style \"header\" requires header_name".to_string(),
        ));
    }

    // Checking is inherently read-only: method is always GET, and the
    // target host (there's no provider id in ad-hoc mode) stands in for
    // "provider" so this still goes through the same policy gate as the
    // provider-descriptor path.
    let policy_request = PolicyRequest {
        operation: "check_credential",
        provider: Some(&host),
        domain: Some(&host),
        agent_identity: None,
        method: "GET",
        command: None,
        has_active_consent: false,
    };
    match policy::evaluate(&policy_request) {
        PolicyDecision::Allow => {}
        PolicyDecision::RequireConsent { reason } => {
            return Err(CoreError::ConsentRequired(reason));
        }
        PolicyDecision::Deny { reason } => return Err(CoreError::PolicyDenied(reason)),
    }

    let secret_value = vault.get_secret(req.secret_name)?;
    let secret_value = String::from_utf8(secret_value).map_err(|_| {
        CoreError::InvalidRequest("stored credential is not valid UTF-8".to_string())
    })?;

    let headers = crate::auth::build_auth_headers(
        req.auth_style,
        req.header_name,
        &std::collections::HashMap::new(),
        &secret_value,
    );

    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(10)))
        .build();
    let agent: ureq::Agent = config.into();

    let mut builder = agent.get(url.as_str());
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }

    let (status, http_status) = match builder.call() {
        Ok(mut response) => {
            let code = response.status().as_u16();
            // Reading the body isn't needed for a status check, but does
            // it anyway to let the connection be released cleanly.
            let _ = response.body_mut().read_to_string();
            (map_http_status(code), Some(code))
        }
        // A transport/connection error tells us nothing about whether
        // the credential itself is good — never report Invalid here.
        Err(_) => (CredentialStatus::Unknown, None),
    };

    vault.log_event(&crate::audit::AuditEvent {
        subject: Some(req.subject),
        project: None,
        provider: Some("ad-hoc"),
        operation: "check_credential",
        endpoint_host: Some(&host),
        outcome: if status == CredentialStatus::Valid {
            "success"
        } else {
            "error"
        },
        redaction_summary: Some("auth header redacted from logs"),
    })?;

    Ok(CheckResult {
        status,
        http_status,
        detail: None,
    })
}

fn map_http_status(status: u16) -> CredentialStatus {
    match status {
        200..=299 => CredentialStatus::Valid,
        401 | 403 => CredentialStatus::Invalid,
        _ => CredentialStatus::Unknown,
    }
}

/// Level 1 (`docs/provider-testing-vision.md`): checks a stored secret
/// against `req.provider_id`'s own cataloged, verified health check.
/// Falls back to level 2's `NotAttempted` — no policy check, no vault
/// read, no network call — when the provider is recognized but has no
/// `[[health_checks]]` configured.
pub fn check_cataloged(
    vault: &Vault,
    registry: &Registry,
    req: &CatalogedCheckRequest,
) -> Result<CheckResult, CoreError> {
    let descriptor = registry
        .descriptors()
        .iter()
        .find(|d| d.id == req.provider_id)
        .ok_or_else(|| CoreError::ProviderNotFound(req.provider_id.to_string()))?;

    let Some(health_check) = descriptor.health_checks.first() else {
        return Ok(CheckResult {
            status: CredentialStatus::NotAttempted,
            http_status: None,
            detail: Some(format!(
                "no verified health operation configured for provider '{}'",
                descriptor.id
            )),
        });
    };

    // Use the first credential descriptor for auth style — same known
    // limitation `request::execute` already documents; a future caller
    // may want to select among multiple credential kinds explicitly.
    let cred = descriptor.credentials.first().ok_or_else(|| {
        CoreError::InvalidRequest(format!(
            "provider '{}' has no credentials configured",
            descriptor.id
        ))
    })?;

    // Health checks are GET-only by construction — enforced already at
    // `provider install`/`validate` time (`commands/provider.rs`'s
    // `check_descriptor`), so this is always "GET" here, same as ad-hoc.
    let policy_request = PolicyRequest {
        operation: "check_credential",
        provider: Some(&descriptor.id),
        domain: descriptor.domains.first().map(String::as_str),
        agent_identity: None,
        method: "GET",
        command: None,
        has_active_consent: false,
    };
    match policy::evaluate(&policy_request) {
        PolicyDecision::Allow => {}
        PolicyDecision::RequireConsent { reason } => {
            return Err(CoreError::ConsentRequired(reason));
        }
        PolicyDecision::Deny { reason } => return Err(CoreError::PolicyDenied(reason)),
    }

    let secret_value = vault.get_secret(req.secret_name)?;
    let secret_value = String::from_utf8(secret_value).map_err(|_| {
        CoreError::InvalidRequest("stored credential is not valid UTF-8".to_string())
    })?;

    let headers = crate::auth::build_auth_headers(
        &cred.auth_style,
        cred.header_name.as_deref(),
        &cred.extra_headers,
        &secret_value,
    );

    let url = crate::request::build_url(&descriptor.domains, &health_check.path, &[])?;

    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(10)))
        .build();
    let agent: ureq::Agent = config.into();

    let mut builder = agent.get(url.as_str());
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }

    let (status, http_status) = match builder.call() {
        Ok(mut response) => {
            let code = response.status().as_u16();
            let _ = response.body_mut().read_to_string();
            let word = crate::request::map_status(descriptor, code);
            (CredentialStatus::from_word(word), Some(code))
        }
        // Same outage guardrail as check_adhoc: a transport/connection
        // error tells us nothing about the credential itself.
        Err(_) => (CredentialStatus::Unknown, None),
    };

    vault.log_event(&crate::audit::AuditEvent {
        subject: Some(req.subject),
        project: None,
        provider: Some(&descriptor.id),
        operation: "check_credential",
        endpoint_host: url.host_str(),
        outcome: if status == CredentialStatus::Valid {
            "success"
        } else {
            "error"
        },
        redaction_summary: Some("auth header redacted from logs"),
    })?;

    Ok(CheckResult {
        status,
        http_status,
        detail: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::InMemoryKeyStore;
    use crate::provider::descriptor::ProviderDescriptor;
    use crate::vault::init_with_keystore;

    fn test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let keystore = InMemoryKeyStore::new();
        let vault = init_with_keystore(dir.path(), &keystore).unwrap();
        (dir, vault)
    }

    #[test]
    fn map_http_status_known_codes() {
        assert_eq!(map_http_status(200), CredentialStatus::Valid);
        assert_eq!(map_http_status(204), CredentialStatus::Valid);
        assert_eq!(map_http_status(401), CredentialStatus::Invalid);
        assert_eq!(map_http_status(403), CredentialStatus::Invalid);
        assert_eq!(map_http_status(404), CredentialStatus::Unknown);
        assert_eq!(map_http_status(500), CredentialStatus::Unknown);
    }

    #[test]
    fn rejects_non_https_url() {
        let (_dir, vault) = test_vault();
        vault.add_secret("KEY", b"value").unwrap();
        let req = AdHocCheckRequest {
            subject: "cli",
            secret_name: "KEY",
            url: "http://example.com/me",
            auth_style: "bearer",
            header_name: None,
        };
        let result = check_adhoc(&vault, &req);
        assert!(matches!(result, Err(CoreError::RequestBlocked(_))));
    }

    #[test]
    fn rejects_header_style_without_header_name() {
        let (_dir, vault) = test_vault();
        vault.add_secret("KEY", b"value").unwrap();
        let req = AdHocCheckRequest {
            subject: "cli",
            secret_name: "KEY",
            url: "https://example.com/me",
            auth_style: "header",
            header_name: None,
        };
        let result = check_adhoc(&vault, &req);
        assert!(matches!(result, Err(CoreError::InvalidRequest(_))));
    }

    #[test]
    fn fails_with_secret_not_found_before_any_network_call() {
        let (_dir, vault) = test_vault();
        let req = AdHocCheckRequest {
            subject: "cli",
            secret_name: "DOES_NOT_EXIST",
            url: "https://example.com/me",
            auth_style: "bearer",
            header_name: None,
        };
        let result = check_adhoc(&vault, &req);
        assert!(matches!(result, Err(CoreError::SecretNotFound(_))));
    }

    const HTTPBIN_LIKE: &str = r#"
id = "httpbin"
name = "httpbin"
domains = ["httpbin.org"]

[[credentials]]
name = "api_key"
aliases = ["HTTPBIN_KEY"]
auth_style = "bearer"

[[health_checks]]
id = "status"
method = "GET"
path = "/status/200"
safe = true
success_statuses = [200]
status_mapping = { "200" = "valid", "401" = "invalid", "410" = "expired", "429" = "limited" }
"#;

    fn httpbin_descriptor() -> ProviderDescriptor {
        toml::from_str(HTTPBIN_LIKE).unwrap()
    }

    const NO_HEALTH_CHECKS: &str = r#"
id = "bare"
name = "Bare"
domains = ["api.bare.com"]

[[credentials]]
name = "api_key"
aliases = ["BARE_KEY"]
auth_style = "bearer"
"#;

    #[test]
    fn check_cataloged_fails_with_provider_not_found() {
        let (_dir, vault) = test_vault();
        let registry = Registry::from_descriptors(vec![httpbin_descriptor()]);
        let req = CatalogedCheckRequest {
            subject: "cli",
            secret_name: "whatever",
            provider_id: "not-a-real-provider",
        };
        let result = check_cataloged(&vault, &registry, &req);
        assert!(matches!(result, Err(CoreError::ProviderNotFound(_))));
    }

    #[test]
    fn check_cataloged_returns_not_attempted_when_no_health_checks_configured() {
        let (_dir, vault) = test_vault();
        let descriptor: ProviderDescriptor = toml::from_str(NO_HEALTH_CHECKS).unwrap();
        let registry = Registry::from_descriptors(vec![descriptor]);
        // Deliberately a secret that was never added: if check_cataloged
        // reached the vault-read step, this would fail with
        // SecretNotFound instead of returning Ok(NotAttempted) — proving
        // the level-2 fallback returns before any vault read or network
        // call, not just before a successful one.
        let req = CatalogedCheckRequest {
            subject: "cli",
            secret_name: "DOES_NOT_EXIST",
            provider_id: "bare",
        };
        let result = check_cataloged(&vault, &registry, &req).unwrap();
        assert_eq!(result.status, CredentialStatus::NotAttempted);
        assert!(result.http_status.is_none());
        assert!(result.detail.unwrap().contains("bare"));
    }

    #[test]
    fn check_cataloged_fails_with_secret_not_found_before_any_network_call() {
        let (_dir, vault) = test_vault();
        let registry = Registry::from_descriptors(vec![httpbin_descriptor()]);
        let req = CatalogedCheckRequest {
            subject: "cli",
            secret_name: "DOES_NOT_EXIST",
            provider_id: "httpbin",
        };
        let result = check_cataloged(&vault, &registry, &req);
        assert!(matches!(result, Err(CoreError::SecretNotFound(_))));
    }

    #[test]
    fn credential_status_from_word_never_produces_invalid_for_unrecognized_words() {
        assert_eq!(
            CredentialStatus::from_word("valid"),
            CredentialStatus::Valid
        );
        assert_eq!(
            CredentialStatus::from_word("invalid"),
            CredentialStatus::Invalid
        );
        assert_eq!(
            CredentialStatus::from_word("expired"),
            CredentialStatus::Expired
        );
        assert_eq!(
            CredentialStatus::from_word("limited"),
            CredentialStatus::Limited
        );
        assert_eq!(
            CredentialStatus::from_word("unknown"),
            CredentialStatus::Unknown
        );
        assert_eq!(
            CredentialStatus::from_word("some-typo"),
            CredentialStatus::Unknown
        );
        assert_eq!(CredentialStatus::from_word(""), CredentialStatus::Unknown);
    }

    #[test]
    #[ignore = "touches the real network"]
    fn check_cataloged_over_real_network_round_trips_a_full_status_word() {
        // httpbin.org/status/410 always returns 410, which HTTPBIN_LIKE's
        // status_mapping maps to "expired" — proving the descriptor's own
        // word reaches CredentialStatus::Expired end to end, not just the
        // original three-value Valid/Invalid/Unknown set.
        let (_dir, vault) = test_vault();
        vault.add_secret("HTTPBIN_KEY", b"whatever-value").unwrap();
        let mut descriptor = httpbin_descriptor();
        descriptor.health_checks[0].path = "/status/410".to_string();
        let registry = Registry::from_descriptors(vec![descriptor]);

        let req = CatalogedCheckRequest {
            subject: "cli",
            secret_name: "HTTPBIN_KEY",
            provider_id: "httpbin",
        };
        let result = check_cataloged(&vault, &registry, &req).unwrap();
        assert_eq!(result.status, CredentialStatus::Expired);
        assert_eq!(result.http_status, Some(410));
    }
}
