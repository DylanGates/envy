//! Candidate extraction from project files (FR-05).
//!
//! Supports two extraction strategies:
//! 1. `.env`-format parser for `*.env` and `*.env.*` files — exact
//!    `KEY=VALUE` parsing, handles shell quoting and comments.
//! 2. Line-by-line pattern matching for all other text files — looks
//!    for `IDENTIFIER = "value"` and `IDENTIFIER: value` patterns
//!    common in source code and config files.
//!
//! No file contents or extracted values are sent anywhere outside this
//! module. Values are returned to the scanner as raw strings; the
//! scanner decides whether to classify and surface them.

use std::path::Path;

/// A raw extracted candidate before classification.
pub(super) struct RawCandidate {
    pub line: usize,
    pub var_name: String,
    /// The candidate value as a UTF-8 string. May contain the whole
    /// value (env file) or a fragment (pattern match).
    pub value_str: String,
}

/// Extracts candidates from a single file.
/// Returns an error string (not `CoreError`) because extraction errors
/// are non-fatal — we log them as read errors and continue.
pub(super) fn extract_candidates(path: &Path) -> Result<Vec<RawCandidate>, String> {
    let content = std::fs::read(path).map_err(|e| format!("{e}"))?;

    // Skip files that aren't valid UTF-8 (likely binary).
    let text = match std::str::from_utf8(&content) {
        Ok(s) => s,
        Err(_) => return Ok(vec![]),
    };

    if is_env_file(path) {
        Ok(parse_env_file(text))
    } else {
        Ok(parse_generic(text))
    }
}

/// Returns true for files that use the `.env` key=value format.
pub(super) fn is_env_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    // Matches: .env  .env.local  .env.production  etc.
    name == ".env"
        || name.starts_with(".env.")
        || path.extension().and_then(|e| e.to_str()) == Some("env")
}

/// Parses a `.env`-format file, returning one candidate per entry that's
/// long enough to be worth surfacing as a scan finding. Parsing mechanics
/// (comments, `export` prefix, quote stripping, shell-expansion
/// skipping) live in the shared `crate::dotenv` module — this wrapper
/// only adds the scan-specific "is this long enough to matter" filter.
/// (`envy import --env` uses `crate::dotenv::parse` directly, with no
/// length filter, since the user explicitly named the file.)
fn parse_env_file(text: &str) -> Vec<RawCandidate> {
    crate::dotenv::parse(text)
        .into_iter()
        // Skip very short values — they're almost never secrets.
        .filter(|e| e.value.len() >= 8)
        .map(|e| RawCandidate {
            line: e.line,
            var_name: e.key,
            value_str: e.value,
        })
        .collect()
}

/// Scans a generic source or config file line by line, looking for
/// patterns that suggest a key/value assignment. Intentionally
/// conservative — false negatives are better than false positives
/// (low-confidence candidates will be filtered by the entropy gate).
fn parse_generic(text: &str) -> Vec<RawCandidate> {
    let mut candidates = Vec::new();

    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with("//")
            || line.starts_with('#')
            || line.starts_with('*')
        {
            continue;
        }

        // Pattern: UPPER_IDENTIFIER = "value"  or  UPPER_IDENTIFIER = 'value'
        // (assignment in source code — config files, inline definitions)
        if let Some(candidate) = extract_assignment(line, i + 1) {
            if candidate.value_str.len() >= 8 {
                candidates.push(candidate);
            }
        }
    }

    candidates
}

/// Tries to extract a `KEY = "value"` or `KEY = 'value'` assignment
/// from a single line. Only recognises UPPER_SNAKE_CASE keys (a strong
/// signal that this is an env-var-style secret name).
fn extract_assignment(line: &str, line_num: usize) -> Option<RawCandidate> {
    // Find `=` or `:` separator.
    let sep_pos = line.find(['=', ':'])?;
    let key_raw = line[..sep_pos].trim();
    // Take the last whitespace-separated token as the identifier
    // (handles `const FOO = ...`, `let FOO = ...`, YAML `FOO: ...` etc.).
    let key = key_raw.split_whitespace().last().unwrap_or(key_raw);

    // Only UPPER_SNAKE identifiers (at least 3 chars to avoid noise).
    if key.len() < 3 || !is_upper_snake(key) {
        return None;
    }

    // Strip trailing source-code punctuation (`;`, `,`) before quote check.
    let rhs = line[sep_pos + 1..].trim().trim_end_matches([';', ',']);

    // Require a quoted value on the RHS (reduces noise vs unquoted).
    let value = if (rhs.starts_with('"') && rhs.ends_with('"') && rhs.len() > 2)
        || (rhs.starts_with('\'') && rhs.ends_with('\'') && rhs.len() > 2)
    {
        &rhs[1..rhs.len() - 1]
    } else {
        return None;
    };

    Some(RawCandidate {
        line: line_num,
        var_name: key.to_string(),
        value_str: value.to_string(),
    })
}

/// True when `s` is UPPER_SNAKE_CASE (all uppercase letters, digits, underscores).
fn is_upper_snake(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_file_basic_key_value() {
        let text = "STRIPE_KEY=sk_live_abc123def\nDB_URL=postgres://localhost/db\n";
        let candidates = parse_env_file(text);
        // Both values are > 8 chars and are returned; classification
        // (entropy/provider) decides which actually look like secrets.
        assert_eq!(candidates.len(), 2);
        let stripe = candidates.iter().find(|c| c.var_name == "STRIPE_KEY");
        assert!(stripe.is_some());
        assert_eq!(stripe.unwrap().value_str, "sk_live_abc123def");
    }

    #[test]
    fn env_file_skips_comments_and_empty_lines() {
        let text = "# This is a comment\n\nKEY=value_that_is_long_enough\n";
        let candidates = parse_env_file(text);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].var_name, "KEY");
    }

    #[test]
    fn env_file_strips_double_quotes() {
        let text = r#"API_KEY="sk_live_abc123def456""#;
        let candidates = parse_env_file(text);
        assert_eq!(candidates[0].value_str, "sk_live_abc123def456");
    }

    #[test]
    fn env_file_strips_single_quotes() {
        let text = "API_KEY='sk_live_abc123def456'";
        let candidates = parse_env_file(text);
        assert_eq!(candidates[0].value_str, "sk_live_abc123def456");
    }

    #[test]
    fn env_file_skips_short_values() {
        let text = "PORT=3000\nAPI_KEY=sk_live_abc123def\n";
        let candidates = parse_env_file(text);
        // PORT=3000 is < 8 chars, skipped. API_KEY is fine.
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].var_name, "API_KEY");
    }

    #[test]
    fn env_file_handles_export_prefix() {
        let text = "export STRIPE_KEY=sk_live_abc123def456\n";
        let candidates = parse_env_file(text);
        assert_eq!(candidates[0].var_name, "STRIPE_KEY");
    }

    #[test]
    fn env_file_skips_shell_expansions() {
        let text = "PATH=$PATH:/usr/local/bin\nAPI_KEY=sk_live_abc123def\n";
        let candidates = parse_env_file(text);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].var_name, "API_KEY");
    }

    #[test]
    fn generic_extracts_quoted_upper_snake() {
        let text = r#"const OPENAI_API_KEY = "sk-abc123def456ghi";"#;
        let candidates = parse_generic(text);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].var_name, "OPENAI_API_KEY");
        assert_eq!(candidates[0].value_str, "sk-abc123def456ghi");
    }

    #[test]
    fn generic_ignores_lowercase_keys() {
        let text = r#"let api_key = "sk-abc123def456ghi";"#;
        let candidates = parse_generic(text);
        assert!(candidates.is_empty());
    }

    #[test]
    fn is_env_file_matches_dotenv_variants() {
        assert!(is_env_file(Path::new(".env")));
        assert!(is_env_file(Path::new(".env.local")));
        assert!(is_env_file(Path::new(".env.production")));
        assert!(is_env_file(Path::new("secrets.env")));
        assert!(!is_env_file(Path::new("main.rs")));
        assert!(!is_env_file(Path::new("config.toml")));
    }

    #[test]
    fn is_upper_snake_rejects_mixed_case() {
        assert!(is_upper_snake("STRIPE_KEY"));
        assert!(is_upper_snake("API_KEY_123"));
        assert!(!is_upper_snake("stripeKey"));
        assert!(!is_upper_snake("Stripe_Key"));
        assert!(!is_upper_snake(""));
    }
}
