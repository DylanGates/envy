//! Loads provider descriptors — bundled defaults (compile-time embedded)
//! plus any `*.toml` files found in the user's provider directory at
//! startup (runtime loading, zero recompilation). Also implements FR-06
//! detection/classification against whatever's loaded.
//!
//! No bundled descriptors are shipped: envy is a universal engine. The
//! provider knowledge base is user-authored and community-contributed, not
//! a curated list baked into the binary. See `examples/providers/` for
//! ready-made descriptors and `_template.toml` for the authoring guide.
//! Use `envy provider validate <file>` to check a descriptor before
//! installing it.

use std::collections::HashMap;
use std::path::PathBuf;

use directories::ProjectDirs;

use crate::error::CoreError;
use crate::provider::descriptor::{CredentialDescriptor, ProviderDescriptor};

/// Bundled defaults. Intentionally empty — envy ships no fixed provider
/// list. `examples/providers/` has ready-made descriptors users can copy
/// to their provider directory.
const BUNDLED: &[(&str, &str)] = &[];

pub struct Registry {
    descriptors: Vec<ProviderDescriptor>,
}

/// A user-directory descriptor that failed to parse. Reported as a warning
/// on stderr; not fatal — it is the user's own file.
#[derive(Debug)]
pub struct LoadWarning {
    pub path: PathBuf,
    pub message: String,
}

impl Registry {
    /// Builds a registry from a fixed descriptor list, bypassing file
    /// loading entirely. `#[cfg(test)]`-only — for tests that need a
    /// small, controlled registry without touching the filesystem.
    #[cfg(test)]
    pub(crate) fn from_descriptors(descriptors: Vec<ProviderDescriptor>) -> Registry {
        Registry { descriptors }
    }

    pub fn descriptors(&self) -> &[ProviderDescriptor] {
        &self.descriptors
    }

    /// Loads bundled defaults (none), then overlays `*.toml` files from the
    /// user's provider directory. A user-directory descriptor with the same
    /// `id` as a bundled one replaces it. Bundled parse failures are a hard
    /// error (envy's own bug); user-directory parse failures are collected
    /// as warnings and skipped so one bad file doesn't block the rest.
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

    /// FR-06: classifies a candidate against every loaded descriptor and
    /// every credential kind within each descriptor. Returns all matches —
    /// a value can plausibly fit more than one provider or credential kind.
    /// Results are sorted highest confidence first.
    pub fn classify(&self, var_name: &str, value: &str) -> Vec<Finding> {
        let mut findings: Vec<Finding> = self
            .descriptors
            .iter()
            .flat_map(|descriptor| {
                descriptor
                    .credentials
                    .iter()
                    .filter_map(|cred| classify_one(descriptor, cred, var_name, value))
            })
            .collect();
        findings.sort_by_key(|f| std::cmp::Reverse(f.confidence));
        findings
    }
}

fn classify_one(
    descriptor: &ProviderDescriptor,
    cred: &CredentialDescriptor,
    var_name: &str,
    value: &str,
) -> Option<Finding> {
    let mut evidence = Vec::new();

    let alias_match = cred
        .aliases
        .iter()
        .any(|alias| var_name.eq_ignore_ascii_case(alias));
    if alias_match {
        evidence.push(format!("variable name matches alias '{var_name}'"));
    }

    let prefix_match = cred
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
        credential_name: cred.name.clone(),
        risk: cred.risk.clone(),
        confidence,
        evidence,
    })
}

/// A classification result for one candidate against one credential kind
/// within one provider descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub provider_id: String,
    pub provider_name: String,
    /// The credential kind within the provider (e.g. `"api_key"`).
    pub credential_name: String,
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

/// The directory `Registry::load()` scans for user-authored `*.toml`
/// descriptors — also `envy provider install`'s copy destination
/// (`src/commands/provider.rs`, in the `cli` crate).
pub fn user_provider_dir() -> Option<PathBuf> {
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

    /// No bundled descriptors are shipped — the registry starts empty and
    /// grows only from the user's provider directory.
    #[test]
    fn load_succeeds_with_no_bundled_providers() {
        let (registry, warnings) = Registry::load().unwrap();
        assert!(warnings.is_empty());
        assert!(BUNDLED.is_empty());
        let _ = registry.descriptors();
    }

    fn test_descriptor(toml_str: &str) -> ProviderDescriptor {
        toml::from_str(toml_str).expect("valid test descriptor TOML")
    }

    // Inline test fixtures using the array-based schema
    // (docs/provider-testing-vision.md §"Schema evolution").
    const STRIPE_LIKE: &str = r#"
id = "stripe"
name = "Stripe"
domains = ["api.stripe.com"]

[[credentials]]
name = "api_key"
aliases = ["STRIPE_SECRET_KEY", "STRIPE_API_KEY", "STRIPE_KEY"]
prefixes = ["sk_live_", "sk_test_"]
auth_style = "bearer"
risk = "high"

[[health_checks]]
id = "balance"
method = "GET"
path = "/v1/balance"
safe = true
success_statuses = [200]
status_mapping = { "200" = "valid", "401" = "invalid" }
"#;

    const GITHUB_LIKE: &str = r#"
id = "github"
name = "GitHub"
domains = ["api.github.com"]

[[credentials]]
name = "access_token"
aliases = ["GITHUB_TOKEN", "GH_TOKEN"]
prefixes = ["ghp_", "github_pat_"]
auth_style = "bearer"
risk = "high"

[[health_checks]]
id = "rate_limit"
method = "GET"
path = "/rate_limit"
safe = true
success_statuses = [200]
status_mapping = { "200" = "valid", "401" = "invalid" }
"#;

    fn stripe_and_github_registry() -> Registry {
        Registry {
            descriptors: vec![test_descriptor(STRIPE_LIKE), test_descriptor(GITHUB_LIKE)],
        }
    }

    #[test]
    fn user_directory_descriptor_is_picked_up() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("example.toml"),
            r#"
id = "example"
name = "Example"
domains = ["example.com"]

[[credentials]]
name = "api_key"
aliases = ["EXAMPLE_KEY"]
prefixes = ["ex_"]
auth_style = "bearer"
risk = "low"

[[health_checks]]
id = "health"
method = "GET"
path = "/health"
safe = true
success_statuses = [200]
"#,
        )
        .unwrap();

        let mut warnings = Vec::new();
        let files = read_toml_files(dir.path(), &mut warnings);
        assert!(warnings.is_empty());
        assert_eq!(files.len(), 1);
        let descriptor: ProviderDescriptor = toml::from_str(&files[0].contents).unwrap();
        assert_eq!(descriptor.id, "example");
        assert_eq!(descriptor.credentials.len(), 1);
        assert_eq!(descriptor.health_checks.len(), 1);
    }

    #[test]
    fn malformed_user_file_becomes_a_warning_not_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("broken.toml"), "this is not valid toml [[[").unwrap();

        let mut warnings = Vec::new();
        let files = read_toml_files(dir.path(), &mut warnings);
        assert!(warnings.is_empty()); // read ok; parse error surfaced in load()
        assert_eq!(files.len(), 1);
        let result: Result<ProviderDescriptor, _> = toml::from_str(&files[0].contents);
        assert!(result.is_err());
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
        assert_eq!(stripe.credential_name, "api_key");
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
        // Right prefix, but variable name is not a known alias.
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
        assert_eq!(github.credential_name, "access_token");
    }

    #[test]
    fn provider_with_multiple_credential_kinds_matches_each_independently() {
        let multi = test_descriptor(
            r#"
id = "acme"
name = "Acme"
domains = ["api.acme.com"]

[[credentials]]
name = "api_key"
aliases = ["ACME_API_KEY"]
prefixes = ["acme_key_"]
auth_style = "bearer"

[[credentials]]
name = "webhook_secret"
aliases = ["ACME_WEBHOOK_SECRET"]
prefixes = ["acme_wh_"]
auth_style = "header"
header_name = "x-acme-signature"
"#,
        );
        let registry = Registry::from_descriptors(vec![multi]);

        let key_findings = registry.classify("ACME_API_KEY", "acme_key_abc");
        assert_eq!(key_findings.len(), 1);
        assert_eq!(key_findings[0].credential_name, "api_key");

        let wh_findings = registry.classify("ACME_WEBHOOK_SECRET", "acme_wh_xyz");
        assert_eq!(wh_findings.len(), 1);
        assert_eq!(wh_findings[0].credential_name, "webhook_secret");
    }
}
