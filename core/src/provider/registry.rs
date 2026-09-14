//! Loads provider descriptors — bundled defaults (compile-time embedded,
//! so envy works out of the box) plus any `*.toml` files found in the
//! user's provider directory at startup (true runtime loading, so a new
//! provider can be added with zero recompilation). Also implements FR-06
//! detection/classification against whatever's loaded.
//!
//! No bundled descriptors are shipped right now: the 6 originally built
//! (Stripe, OpenAI, GitHub, Anthropic, Resend, Context7) were removed to
//! be rebuilt under the array-based schema in
//! `docs/provider-testing-vision.md` (`[[credentials]]`/`[[health_checks]]`)
//! instead of migrating the old flat shape in place.

use std::collections::HashMap;
use std::path::PathBuf;

use directories::ProjectDirs;

use crate::error::CoreError;
use crate::provider::descriptor::ProviderDescriptor;

/// (name, source) pairs for the bundled defaults. Adding a provider =
/// add a `.toml` file under `providers/` + one line here.
const BUNDLED: &[(&str, &str)] = &[];

pub struct Registry {
    descriptors: Vec<ProviderDescriptor>,
}

/// A user-directory descriptor that failed to parse. Reported, not
/// fatal — it's the user's own file, not a bug in envy.
#[derive(Debug)]
pub struct LoadWarning {
    pub path: PathBuf,
    pub message: String,
}

impl Registry {
    /// Builds a registry directly from a list of descriptors, bypassing
    /// bundled/user-directory loading entirely. `#[cfg(test)]`-only —
    /// for other modules' tests that need a small, controlled registry
    /// (e.g. `request.rs`'s tests) without depending on real provider
    /// files.
    #[cfg(test)]
    pub(crate) fn from_descriptors(descriptors: Vec<ProviderDescriptor>) -> Registry {
        Registry { descriptors }
    }

    pub fn descriptors(&self) -> &[ProviderDescriptor] {
        &self.descriptors
    }

    /// Loads bundled defaults, then overlays `*.toml` files from the
    /// user's provider directory (a descriptor with the same `id`
    /// replaces the bundled one, letting a user customize a shipped
    /// provider). Bundled parse failures are a hard error (envy's own
    /// bug); user-directory parse failures are collected as warnings and
    /// skipped.
    pub fn load() -> Result<(Registry, Vec<LoadWarning>), CoreError> {
        let mut by_id: HashMap<String, ProviderDescriptor> = HashMap::new();

        for (name, source) in BUNDLED {
            let descriptor: ProviderDescriptor =
                toml::from_str(source).map_err(|e| CoreError::BundledProviderDescriptor {
                    name,
                    message: e.to_string(),
                })?;
            by_id.insert(descriptor.id.clone(), descriptor);
        }

        let mut warnings = Vec::new();
        if let Some(dir) = user_provider_dir() {
            if dir.exists() {
                for entry in read_toml_files(&dir, &mut warnings) {
                    match toml::from_str::<ProviderDescriptor>(&entry.contents) {
                        Ok(descriptor) => {
                            by_id.insert(descriptor.id.clone(), descriptor);
                        }
                        Err(e) => warnings.push(LoadWarning {
                            path: entry.path,
                            message: e.to_string(),
                        }),
                    }
                }
            }
        }

        let mut descriptors: Vec<_> = by_id.into_values().collect();
        descriptors.sort_by(|a, b| a.id.cmp(&b.id));

        Ok((Registry { descriptors }, warnings))
    }

    /// FR-06: classifies a candidate against every loaded descriptor.
    /// Returns every match (a value could plausibly fit more than one
    /// provider), highest confidence first.
    pub fn classify(&self, var_name: &str, value: &str) -> Vec<Finding> {
        let mut findings: Vec<Finding> = self
            .descriptors
            .iter()
            .filter_map(|descriptor| classify_one(descriptor, var_name, value))
            .collect();
        findings.sort_by_key(|f| std::cmp::Reverse(f.confidence));
        findings
    }
}

fn classify_one(descriptor: &ProviderDescriptor, var_name: &str, value: &str) -> Option<Finding> {
    let mut evidence = Vec::new();

    let alias_match = descriptor
        .detection
        .aliases
        .iter()
        .any(|alias| var_name.eq_ignore_ascii_case(alias));
    if alias_match {
        evidence.push(format!("variable name matches known alias '{var_name}'"));
    }

    let prefix_match = descriptor
        .detection
        .prefixes
        .iter()
        .find(|prefix| value.starts_with(prefix.as_str()));
    if let Some(prefix) = prefix_match {
        evidence.push(format!("value starts with known prefix '{prefix}'"));
    }

    let confidence = match (alias_match, prefix_match.is_some()) {
        (true, true) => Confidence::High,
        (true, false) | (false, true) => Confidence::Medium,
        (false, false) => return None,
    };

    Some(Finding {
        provider_id: descriptor.id.clone(),
        provider_name: descriptor.name.clone(),
        credential_kind: descriptor.credential.kind.clone(),
        risk: descriptor.credential.risk.clone(),
        confidence,
        evidence,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub provider_id: String,
    pub provider_name: String,
    pub credential_kind: String,
    pub risk: String,
    pub confidence: Confidence,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

fn user_provider_dir() -> Option<PathBuf> {
    ProjectDirs::from("dev", "envy", "envy").map(|dirs| dirs.data_dir().join("providers"))
}

struct TomlFile {
    path: PathBuf,
    contents: String,
}

fn read_toml_files(dir: &std::path::Path, warnings: &mut Vec<LoadWarning>) -> Vec<TomlFile> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            warnings.push(LoadWarning {
                path: dir.to_path_buf(),
                message: e.to_string(),
            });
            return Vec::new();
        }
    };

    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .filter_map(|path| match std::fs::read_to_string(&path) {
            Ok(contents) => Some(TomlFile { path, contents }),
            Err(e) => {
                warnings.push(LoadWarning {
                    path,
                    message: e.to_string(),
                });
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No bundled descriptors are shipped right now (see this file's
    /// module doc) — the previous 6 were removed to be rebuilt under the
    /// array-based schema in `docs/provider-testing-vision.md`.
    #[test]
    fn load_succeeds_with_no_bundled_providers() {
        let (registry, warnings) = Registry::load().unwrap();
        assert!(warnings.is_empty());
        assert!(BUNDLED.is_empty());
        // Whatever's here comes only from a real user provider directory,
        // if one happens to exist on this machine — not asserted either
        // way, just confirming load() doesn't require any bundled data.
        let _ = registry.descriptors();
    }

    fn test_descriptor(toml_str: &str) -> ProviderDescriptor {
        toml::from_str(toml_str).expect("valid test descriptor TOML")
    }

    const STRIPE_LIKE: &str = r#"
id = "stripe"
name = "Stripe"
[detection]
aliases = ["STRIPE_SECRET_KEY", "STRIPE_API_KEY", "STRIPE_KEY"]
prefixes = ["sk_live_", "sk_test_"]
[credential]
kind = "api_key"
risk = "high"
[network]
base_url = "https://api.stripe.com"
allowed_domains = ["api.stripe.com"]
[auth]
style = "bearer"
[health_check]
method = "GET"
url = "https://api.stripe.com/v1/balance"
[redaction]
fields = ["Authorization"]
[docs]
"#;

    const GITHUB_LIKE: &str = r#"
id = "github"
name = "GitHub"
[detection]
aliases = ["GITHUB_TOKEN", "GH_TOKEN"]
prefixes = ["ghp_", "github_pat_"]
[credential]
kind = "access_token"
risk = "high"
[network]
base_url = "https://api.github.com"
allowed_domains = ["api.github.com"]
[auth]
style = "bearer"
[health_check]
method = "GET"
url = "https://api.github.com/rate_limit"
[redaction]
fields = ["Authorization"]
[docs]
"#;

    #[test]
    fn user_directory_descriptor_is_picked_up() {
        // This test can't easily control ProjectDirs' real location, so
        // it exercises the lower-level building blocks directly instead
        // of Registry::load()'s full path resolution.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("example.toml"),
            r#"
id = "example"
name = "Example"
[detection]
aliases = ["EXAMPLE_KEY"]
prefixes = ["ex_"]
[credential]
kind = "api_key"
risk = "low"
[network]
base_url = "https://example.com"
allowed_domains = []
[auth]
style = "bearer"
[health_check]
method = "GET"
url = "https://example.com/health"
[redaction]
fields = []
[docs]
"#,
        )
        .unwrap();

        let mut warnings = Vec::new();
        let files = read_toml_files(dir.path(), &mut warnings);
        assert!(warnings.is_empty());
        assert_eq!(files.len(), 1);
        let descriptor: ProviderDescriptor = toml::from_str(&files[0].contents).unwrap();
        assert_eq!(descriptor.id, "example");
    }

    #[test]
    fn malformed_user_file_becomes_a_warning_not_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("broken.toml"), "this is not valid toml [[[").unwrap();

        let mut warnings = Vec::new();
        let files = read_toml_files(dir.path(), &mut warnings);
        assert!(warnings.is_empty()); // read succeeded; parsing happens in load()
        assert_eq!(files.len(), 1);
        let result: Result<ProviderDescriptor, _> = toml::from_str(&files[0].contents);
        assert!(result.is_err());
    }

    fn stripe_and_github_registry() -> Registry {
        Registry {
            descriptors: vec![test_descriptor(STRIPE_LIKE), test_descriptor(GITHUB_LIKE)],
        }
    }

    #[test]
    fn classify_valid_looking_value() {
        let registry = stripe_and_github_registry();
        let findings = registry.classify("STRIPE_SECRET_KEY", "sk_live_abc123");
        let stripe = findings
            .iter()
            .find(|f| f.provider_id == "stripe")
            .expect("expected a stripe match");
        assert_eq!(stripe.confidence, Confidence::High);
        assert_eq!(stripe.evidence.len(), 2);
    }

    #[test]
    fn classify_invalid_looking_value_has_no_match() {
        let registry = stripe_and_github_registry();
        let findings = registry.classify("DATABASE_URL", "postgres://localhost/db");
        assert!(findings.is_empty());
    }

    #[test]
    fn classify_ambiguous_value_is_medium_confidence() {
        let registry = stripe_and_github_registry();
        // Right prefix, but a variable name that isn't a known alias.
        let findings = registry.classify("SOME_RANDOM_VAR", "sk_live_abc123");
        let stripe = findings
            .iter()
            .find(|f| f.provider_id == "stripe")
            .expect("expected a stripe match on prefix alone");
        assert_eq!(stripe.confidence, Confidence::Medium);
        assert_eq!(stripe.evidence.len(), 1);
    }

    #[test]
    fn classify_github_valid_looking_value() {
        let registry = stripe_and_github_registry();
        let findings = registry.classify("GITHUB_TOKEN", "ghp_abcdefghijklmnop");
        let github = findings
            .iter()
            .find(|f| f.provider_id == "github")
            .expect("expected a github match");
        assert_eq!(github.confidence, Confidence::High);
    }
}
