//! Response-side redaction (FR-12's other half — see
//! `docs/feature-proposals.md`'s "near-term #2"). Request-side redaction
//! (the injected auth header never appears in logs/errors) already exists
//! in `request.rs`/`check.rs`/`auth.rs`; this covers a provider echoing
//! the credential value back in its response body, so the value never
//! reaches the MCP caller either — not just never reaches logs.

/// Replaces every literal occurrence of `secret` in `body` with a fixed
/// placeholder. Case-sensitive, exact-substring match only — a safety net
/// for a provider echoing the credential back verbatim, not a scanner for
/// re-encoded/derived forms of the value.
///
/// Guards against an empty `secret`: `str::replace` with an empty pattern
/// would otherwise insert the placeholder between every character of
/// `body`.
pub fn redact_body(body: &str, secret: &str) -> String {
    if secret.is_empty() {
        return body.to_string();
    }
    body.replace(secret, "[REDACTED]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_body_is_unchanged() {
        assert_eq!(redact_body("", "sk_live_abc"), "");
    }

    #[test]
    fn no_match_is_unchanged() {
        assert_eq!(redact_body(r#"{"ok":true}"#, "sk_live_abc"), r#"{"ok":true}"#);
    }

    #[test]
    fn redacts_a_single_occurrence() {
        let body = r#"{"token":"sk_live_abc"}"#;
        assert_eq!(redact_body(body, "sk_live_abc"), r#"{"token":"[REDACTED]"}"#);
    }

    #[test]
    fn redacts_multiple_occurrences() {
        let body = "sk_live_abc and again sk_live_abc";
        assert_eq!(redact_body(body, "sk_live_abc"), "[REDACTED] and again [REDACTED]");
    }

    #[test]
    fn empty_secret_is_a_no_op() {
        let body = "some response body";
        assert_eq!(redact_body(body, ""), body);
    }
}
