//! Auth-header injection, shared by the provider-descriptor path
//! (`request.rs`) and the ad-hoc path (`check.rs`) so both build headers
//! the same way instead of duplicating this logic.

use std::collections::HashMap;

/// Builds the headers that inject a credential value, per an auth style:
/// `"bearer"` → `Authorization: Bearer <value>`; `"header"` → the given
/// header name set to the raw value; anything else falls back to bearer.
/// `extra_headers` are appended verbatim (e.g. a fixed API version
/// header some providers require alongside the credential).
pub fn build_auth_headers(
    style: &str,
    header_name: Option<&str>,
    extra_headers: &HashMap<String, String>,
    secret_value: &str,
) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    match style {
        "bearer" => headers.push(("Authorization".to_string(), format!("Bearer {secret_value}"))),
        "header" => {
            let name = header_name.unwrap_or("Authorization").to_string();
            headers.push((name, secret_value.to_string()));
        }
        _ => headers.push(("Authorization".to_string(), format!("Bearer {secret_value}"))),
    }
    for (name, value) in extra_headers {
        headers.push((name.clone(), value.clone()));
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_style() {
        let headers = build_auth_headers("bearer", None, &HashMap::new(), "sk_live_abc123");
        assert_eq!(
            headers,
            vec![("Authorization".to_string(), "Bearer sk_live_abc123".to_string())]
        );
    }

    #[test]
    fn header_style_with_extra_headers() {
        let mut extra = HashMap::new();
        extra.insert("anthropic-version".to_string(), "2023-06-01".to_string());
        let headers = build_auth_headers("header", Some("x-api-key"), &extra, "sk-ant-abc123");
        let map: HashMap<_, _> = headers.into_iter().collect();
        assert_eq!(map.get("x-api-key"), Some(&"sk-ant-abc123".to_string()));
        assert_eq!(map.get("anthropic-version"), Some(&"2023-06-01".to_string()));
    }

    #[test]
    fn unknown_style_falls_back_to_bearer() {
        let headers = build_auth_headers("something-else", None, &HashMap::new(), "value");
        assert_eq!(headers, vec![("Authorization".to_string(), "Bearer value".to_string())]);
    }
}
