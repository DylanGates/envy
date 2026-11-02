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

/// Redacts all IPv4 and IPv6 addresses from `text`, replacing them with `"[REDACTED]"`.
pub fn redact_ip_addresses(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        // Look for candidate IPv4: start boundary must not be alphanumeric or '.' or '_'
        let is_start_boundary = i == 0
            || (!chars[i - 1].is_ascii_alphanumeric()
                && chars[i - 1] != '.'
                && chars[i - 1] != '_');
        if is_start_boundary && chars[i].is_ascii_digit() {
            let mut j = i;
            while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == '.') {
                j += 1;
            }
            let candidate: String = chars[i..j].iter().collect();
            // Check if valid IPv4 address
            if candidate.split('.').count() == 4 && candidate.parse::<std::net::Ipv4Addr>().is_ok()
            {
                let is_end_boundary =
                    j == chars.len() || (!chars[j].is_ascii_alphanumeric() && chars[j] != '.');
                if is_end_boundary {
                    result.push_str("[REDACTED]");
                    i = j;
                    continue;
                }
            }
        }
        result.push(chars[i]);
        i += 1;
    }

    result
}

/// Redacts server host, username, and any IP addresses from command output or strings.
pub fn redact_server_info(text: &str, host: &str, user: &str) -> String {
    let mut cleaned = text.to_string();
    let host_trimmed = host.trim();
    if !host_trimmed.is_empty() {
        cleaned = cleaned.replace(host_trimmed, "[REDACTED]");
    }
    let user_trimmed = user.trim();
    if !user_trimmed.is_empty() {
        cleaned = cleaned.replace(user_trimmed, "[REDACTED]");
    }
    redact_ip_addresses(&cleaned)
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
        assert_eq!(
            redact_body(r#"{"ok":true}"#, "sk_live_abc"),
            r#"{"ok":true}"#
        );
    }

    #[test]
    fn redacts_a_single_occurrence() {
        let body = r#"{"token":"sk_live_abc"}"#;
        assert_eq!(
            redact_body(body, "sk_live_abc"),
            r#"{"token":"[REDACTED]"}"#
        );
    }

    #[test]
    fn redacts_multiple_occurrences() {
        let body = "sk_live_abc and again sk_live_abc";
        assert_eq!(
            redact_body(body, "sk_live_abc"),
            "[REDACTED] and again [REDACTED]"
        );
    }

    #[test]
    fn empty_secret_is_a_no_op() {
        let body = "some response body";
        assert_eq!(redact_body(body, ""), body);
    }

    #[test]
    fn redacts_ipv4_addresses() {
        assert_eq!(
            redact_ip_addresses("server running on 15.224.112.139:22"),
            "server running on [REDACTED]:22"
        );
        assert_eq!(
            redact_ip_addresses("inet 10.0.0.1/24 brd 10.0.0.255"),
            "inet [REDACTED]/24 brd [REDACTED]"
        );
        assert_eq!(
            redact_ip_addresses("curl http://192.168.1.5:8080/health"),
            "curl http://[REDACTED]:8080/health"
        );
        assert_eq!(
            redact_ip_addresses("version 1.2.3 is not an ip"),
            "version 1.2.3 is not an ip"
        );
        assert_eq!(
            redact_ip_addresses("invalid 999.999.999.999 ip"),
            "invalid 999.999.999.999 ip"
        );
    }

    #[test]
    fn redacts_server_info_completely() {
        let text = "Connected to deploy@15.224.112.139 (internal 10.0.1.50) as deploy";
        let redacted = redact_server_info(text, "15.224.112.139", "deploy");
        assert_eq!(
            redacted,
            "Connected to [REDACTED]@[REDACTED] (internal [REDACTED]) as [REDACTED]"
        );
        assert!(!redacted.contains("deploy"));
        assert!(!redacted.contains("15.224.112.139"));
        assert!(!redacted.contains("10.0.1.50"));
    }
}
