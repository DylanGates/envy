//! Policy evaluation (FR-10).
//!
//! One rule implemented so far: purely local vault operations are
//! allowed; provider-facing GET requests are treated as read-only and
//! allowed; anything else provider-facing requires consent. There's no
//! consent flow yet, so `RequireConsent`/`Deny` are both handled by
//! callers as "fail closed," not as a pause-and-ask. Real per-project/
//! secret/domain/agent-identity policy (and a way to configure it) is
//! future work.

/// A capability request to evaluate against policy.
pub struct PolicyRequest<'a> {
    pub operation: &'a str,
    pub provider: Option<&'a str>,
    pub domain: Option<&'a str>,
    pub agent_identity: Option<&'a str>,
    pub method: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    RequireConsent { reason: String },
    Deny { reason: String },
}

/// Evaluates a request. No `provider` → `Allow` (purely local). A
/// `provider` with a `GET` method → `Allow` (read-only, per PRD's
/// "read-only by default, consent for writes"). A `provider` with any
/// other method → `RequireConsent`.
pub fn evaluate(request: &PolicyRequest) -> PolicyDecision {
    match request.provider {
        None => PolicyDecision::Allow,
        Some(_provider) if request.method.eq_ignore_ascii_case("GET") => PolicyDecision::Allow,
        Some(provider) => PolicyDecision::RequireConsent {
            reason: format!(
                "operation '{}' ({} {}) would contact provider '{provider}' — requires explicit consent",
                request.operation, request.method, request.operation
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_operation_is_allowed() {
        let request = PolicyRequest {
            operation: "list",
            provider: None,
            domain: None,
            agent_identity: None,
            method: "GET",
        };
        assert_eq!(evaluate(&request), PolicyDecision::Allow);
    }

    #[test]
    fn provider_facing_get_is_allowed() {
        let request = PolicyRequest {
            operation: "make_authenticated_request",
            provider: Some("context7"),
            domain: Some("context7.com"),
            agent_identity: Some("agent-123"),
            method: "GET",
        };
        assert_eq!(evaluate(&request), PolicyDecision::Allow);
    }

    #[test]
    fn provider_facing_non_get_requires_consent() {
        let request = PolicyRequest {
            operation: "make_authenticated_request",
            provider: Some("stripe"),
            domain: Some("api.stripe.com"),
            agent_identity: Some("agent-123"),
            method: "POST",
        };
        match evaluate(&request) {
            PolicyDecision::RequireConsent { reason } => {
                assert!(reason.contains("make_authenticated_request"));
                assert!(reason.contains("stripe"));
            }
            other => panic!("expected RequireConsent, got {other:?}"),
        }
    }
}
