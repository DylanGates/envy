//! TTL parsing for `envy consent grant` (see `docs/feature-proposals.md`'s
//! consent-flow sketch, simplified: a grant is a time-boxed row in the
//! vault, checked by `policy::evaluate` via `Vault::has_active_consent`).

use std::time::Duration;

use crate::error::CoreError;

/// Default TTL when `--ttl` is omitted — short enough to keep blast
/// radius small, long enough to cover a real multi-call task.
pub const DEFAULT_TTL: &str = "5m";

/// Parses a duration string of the form `<number><unit>`, where unit is
/// one of `s`/`m`/`h`/`d` (seconds/minutes/hours/days), e.g. `"30s"`,
/// `"5m"`, `"1h"`, `"2d"`. Case-insensitive. A missing or unrecognized
/// unit is rejected rather than guessed, so `--ttl 5` (ambiguous: five
/// what?) is a clear error, not a silent default.
pub fn parse_ttl(s: &str) -> Result<Duration, CoreError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(CoreError::InvalidRequest(
            "ttl must not be empty (e.g. \"5m\", \"1h\")".to_string(),
        ));
    }

    let (digits, unit) = s.split_at(s.len() - 1);
    let amount: u64 = digits.parse().map_err(|_| {
        CoreError::InvalidRequest(format!(
            "invalid ttl \"{s}\" — expected a number followed by s/m/h/d, e.g. \"5m\""
        ))
    })?;

    let seconds = match unit.to_ascii_lowercase().as_str() {
        "s" => amount,
        "m" => amount.saturating_mul(60),
        "h" => amount.saturating_mul(3600),
        "d" => amount.saturating_mul(86400),
        other => {
            return Err(CoreError::InvalidRequest(format!(
                "invalid ttl unit \"{other}\" in \"{s}\" — expected one of s/m/h/d"
            )));
        }
    };

    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_seconds_minutes_hours_days() {
        assert_eq!(parse_ttl("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_ttl("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_ttl("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_ttl("2d").unwrap(), Duration::from_secs(172800));
    }

    #[test]
    fn is_case_insensitive() {
        assert_eq!(parse_ttl("5M").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_ttl("1H").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn default_ttl_parses() {
        assert_eq!(parse_ttl(DEFAULT_TTL).unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn rejects_missing_unit() {
        assert!(matches!(parse_ttl("5"), Err(CoreError::InvalidRequest(_))));
    }

    #[test]
    fn rejects_unknown_unit() {
        assert!(matches!(parse_ttl("5x"), Err(CoreError::InvalidRequest(_))));
    }

    #[test]
    fn rejects_non_numeric_amount() {
        assert!(matches!(
            parse_ttl("fives"),
            Err(CoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn rejects_empty_string() {
        assert!(matches!(parse_ttl(""), Err(CoreError::InvalidRequest(_))));
    }
}
