//! Ad-hoc credential testing — vision testing level 4
//! (`docs/provider-testing-vision.md`): the caller supplies a secret
//! name, a URL, and an auth style directly, with no provider descriptor
//! or registry lookup involved. This is the "universal" half of
//! `check_credential` (FR-11) — provider-descriptor-based checking
//! (level 1, using a cataloged `health_check`) is separate, unbuilt work.
//!
//! Hard guardrails (see `docs/intent.md`): HTTPS only; always a GET,
//! never a write/destructive method; the caller's own `url` is their
//! explicit consent for this one call, envy never guesses or probes
//! multiple endpoints; a network failure or unrecognized status maps to
//! `Unknown`, never `Invalid` — a credential is never blamed for an
//! outage.

use std::time::Duration;

use crate::error::CoreError;
use crate::policy::{self, PolicyDecision, PolicyRequest};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialStatus {
    Valid,
    Invalid,
    Unknown,
}

impl CredentialStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialStatus::Valid => "valid",
            CredentialStatus::Invalid => "invalid",
            CredentialStatus::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckResult {
    pub status: CredentialStatus,
    pub http_status: Option<u16>,
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
    };
    match policy::evaluate(&policy_request) {
        PolicyDecision::Allow => {}
        PolicyDecision::RequireConsent { reason } => return Err(CoreError::ConsentRequired(reason)),
        PolicyDecision::Deny { reason } => return Err(CoreError::PolicyDenied(reason)),
    }

    let secret_value = vault.get_secret(req.secret_name)?;
    let secret_value = String::from_utf8(secret_value)
        .map_err(|_| CoreError::InvalidRequest("stored credential is not valid UTF-8".to_string()))?;

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
        outcome: if status == CredentialStatus::Valid { "success" } else { "error" },
        redaction_summary: Some("auth header redacted from logs"),
    })?;

    Ok(CheckResult { status, http_status })
}

fn map_http_status(status: u16) -> CredentialStatus {
    match status {
        200..=299 => CredentialStatus::Valid,
        401 | 403 => CredentialStatus::Invalid,
        _ => CredentialStatus::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::InMemoryKeyStore;
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
}
