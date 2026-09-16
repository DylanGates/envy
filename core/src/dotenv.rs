//! Shared `.env`-format parsing/formatting.
//!
//! Used by both `scanner::extract` (which layers its own
//! candidate-worthiness filtering on top — see there) and
//! `envy export --env`/`envy import --env` (which read/write `.env`
//! files faithfully, with no filtering — the user explicitly named the
//! file, so every line in it is honored).

/// One parsed `KEY=VALUE` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub line: usize,
    pub key: String,
    pub value: String,
}

/// Parses `.env`-format text into every syntactically valid `KEY=VALUE`
/// line. Skips comments and blank lines, strips a leading `export `,
/// requires a valid identifier key, skips empty values, and skips
/// `$`-prefixed values (a shell expansion, never a literal secret).
/// Surrounding single or double quotes are stripped; double-quoted
/// values also get `\"`/`\\` unescaped.
pub fn parse(text: &str) -> Vec<Entry> {
    let mut entries = Vec::new();

    for (i, line) in text.lines().enumerate() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();

        let Some(eq_pos) = line.find('=') else {
            continue;
        };
        let key = line[..eq_pos].trim();
        let raw_val = line[eq_pos + 1..].trim();

        if key.is_empty() || !is_identifier(key) {
            continue;
        }
        if raw_val.is_empty() || raw_val.starts_with('$') {
            continue;
        }

        let value = strip_quotes(raw_val);

        entries.push(Entry {
            line: i + 1,
            key: key.to_string(),
            value,
        });
    }

    entries
}

/// Renders one `KEY=VALUE` line, always double-quoting the value and
/// escaping embedded `"` and `\` so it round-trips safely through
/// [`parse`] regardless of content (spaces, `#`, quotes, etc.).
pub fn format_line(key: &str, value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("{key}=\"{escaped}\"")
}

/// True when `s` looks like a shell identifier: letters, digits,
/// underscores, starting with a letter or underscore.
fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Strips surrounding single or double quotes from a value. For
/// double-quoted values, also unescapes `\"` → `"` and `\\` → `\`
/// (no other escape sequences are interpreted).
fn strip_quotes(s: &str) -> String {
    if s.len() >= 2 {
        if s.starts_with('"') && s.ends_with('"') {
            let inner = &s[1..s.len() - 1];
            return unescape_double_quoted(inner);
        }
        if s.starts_with('\'') && s.ends_with('\'') {
            return s[1..s.len() - 1].to_string();
        }
    }
    s.to_string()
}

fn unescape_double_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('"') => {
                    out.push('"');
                    chars.next();
                }
                Some('\\') => {
                    out.push('\\');
                    chars.next();
                }
                _ => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_key_value() {
        let entries = parse("STRIPE_KEY=sk_live_abc123def\nDB_URL=postgres://localhost/db\n");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "STRIPE_KEY");
        assert_eq!(entries[0].value, "sk_live_abc123def");
    }

    #[test]
    fn skips_comments_and_empty_lines() {
        let entries = parse("# comment\n\nKEY=value\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "KEY");
    }

    #[test]
    fn strips_double_quotes() {
        let entries = parse(r#"API_KEY="sk_live_abc123""#);
        assert_eq!(entries[0].value, "sk_live_abc123");
    }

    #[test]
    fn strips_single_quotes() {
        let entries = parse("API_KEY='sk_live_abc123'");
        assert_eq!(entries[0].value, "sk_live_abc123");
    }

    #[test]
    fn handles_export_prefix() {
        let entries = parse("export STRIPE_KEY=sk_live_abc123\n");
        assert_eq!(entries[0].key, "STRIPE_KEY");
    }

    #[test]
    fn skips_shell_expansions() {
        let entries = parse("PATH=$PATH:/usr/local/bin\nAPI_KEY=sk_live_abc\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "API_KEY");
    }

    #[test]
    fn does_not_filter_by_length() {
        // Unlike the scanner's wrapper, the shared parser is faithful —
        // a short value is still a valid entry.
        let entries = parse("PORT=3000\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value, "3000");
    }

    #[test]
    fn format_line_round_trips_value_with_space_and_hash() {
        let line = format_line("KEY", "value with space #and-hash");
        let entries = parse(&line);
        assert_eq!(entries[0].value, "value with space #and-hash");
    }

    #[test]
    fn format_line_round_trips_embedded_quote_and_backslash() {
        let line = format_line("KEY", r#"has "quotes" and \backslash\"#);
        let entries = parse(&line);
        assert_eq!(entries[0].value, r#"has "quotes" and \backslash\"#);
    }
}
