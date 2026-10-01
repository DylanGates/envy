//! Project scanner — FR-04, FR-05, FR-06.
//!
//! Walks a directory tree (gitignore-aware), extracts key/value candidates
//! from project files, classifies them against the provider registry, and
//! scores unrecognized values with Shannon entropy. No file contents or
//! plaintext values are sent anywhere outside the trusted core.
//!
//! Design decisions:
//! - Candidate stores the plaintext value in memory only for the duration
//!   of the scan session. `import_into` encrypts it immediately on call.
//! - Provider matching is additive enrichment: a candidate with no
//!   registry match is still returned (entropy alone is enough to flag a
//!   likely secret). The registry being empty never suppresses findings.
//! - Deduplication is by variable name within a single scan run. Cross-run
//!   deduplication uses the vault's keyed fingerprint (not done here).

mod extract;
mod walk;

use std::path::{Path, PathBuf};

use crate::audit::AuditEvent;
use crate::error::CoreError;
use crate::provider::registry::{Finding, Registry};
use crate::vault::Vault;

/// Minimum Shannon entropy (bits per character) for a value to be treated
/// as a likely secret when there is no provider registry match. Values at
/// or above this threshold look random enough to warrant flagging.
const ENTROPY_THRESHOLD: f64 = 3.5;

/// Minimum value length considered for entropy-based flagging. Very short
/// values (e.g. single words, small numbers) produce misleadingly high
/// entropy scores.
const MIN_ENTROPY_LEN: usize = 16;

/// A credential candidate found during a scan. Carries enough information
/// to display a masked finding to the user and, if selected, import the
/// value into the vault.
///
/// The plaintext `value` is held in memory only for the duration of the
/// scan session. Call `import_into` to encrypt and store it; the value
/// then drops with the `Candidate`.
pub struct Candidate {
    /// Source file path.
    pub path: PathBuf,
    /// 1-based line number in the source file.
    pub line: usize,
    /// Variable name as it appears in the source (e.g. `STRIPE_SECRET_KEY`).
    pub var_name: String,
    /// Masked display value — most of the value replaced with `*`.
    pub masked_value: String,
    /// Registry classification results, highest confidence first.
    /// Empty when no loaded provider descriptor matched.
    pub findings: Vec<Finding>,
    /// Shannon entropy of the raw value. Higher = more random = more
    /// likely to be a secret.
    pub entropy: f64,
    /// Plaintext value. Lives only in memory; encrypted on `import_into`.
    pub(crate) value: Vec<u8>,
}

impl Candidate {
    /// Whether this candidate looks like a secret even without a registry
    /// match — i.e. the value is long enough and random enough to flag.
    pub fn looks_like_secret(&self) -> bool {
        !self.findings.is_empty()
            || (self.value.len() >= MIN_ENTROPY_LEN && self.entropy >= ENTROPY_THRESHOLD)
    }

    /// Encrypts and stores this candidate's value in the vault under
    /// `var_name`, then records an audit event. Fails with
    /// `SecretAlreadyExists` if the name is already taken.
    pub fn import_into(&self, vault: &Vault) -> Result<(), CoreError> {
        vault.add_secret(&self.var_name, &self.value)?;
        vault.log_event(&AuditEvent {
            subject: Some("cli"),
            project: None,
            provider: self.findings.first().map(|f| f.provider_id.as_str()),
            operation: "import",
            endpoint_host: None,
            outcome: "success",
            redaction_summary: Some(&format!(
                "imported '{}' from {}:{}",
                self.var_name,
                self.path.display(),
                self.line
            )),
        })?;
        Ok(())
    }

    /// Imports this candidate into the vault and replaces the plaintext value in the
    /// source file with `envy://<var_name>`, creating a `.bak` file first.
    pub fn import_and_remediate(&self, vault: &Vault) -> Result<PathBuf, CoreError> {
        let value_str = String::from_utf8(self.value.clone()).map_err(|_| {
            CoreError::InvalidRequest(
                "secret contains non-UTF-8 bytes; cannot remediate in text file".to_string(),
            )
        })?;

        // Import into vault first (fail closed if secret already exists)
        self.import_into(vault)?;

        // Remediate source file
        let backup = crate::remediate::remediate_file(&self.path, &self.var_name, &value_str)?;

        vault.log_event(&AuditEvent {
            subject: Some("cli"),
            project: None,
            provider: self.findings.first().map(|f| f.provider_id.as_str()),
            operation: "remediate",
            endpoint_host: None,
            outcome: "success",
            redaction_summary: Some(&format!(
                "remediated '{}' in {} (backup at {})",
                self.var_name,
                self.path.display(),
                backup.display()
            )),
        })?;

        Ok(backup)
    }
}
/// Result of a scan run.
pub struct ScanResult {
    /// All candidates found, in file-walk order.
    pub candidates: Vec<Candidate>,
    /// Files that could not be read (permission errors, etc.).
    pub read_errors: Vec<(PathBuf, String)>,
    /// Every `.env`-family file recognized during the walk (per
    /// `extract::is_env_file`), regardless of whether it produced any
    /// candidates. Sorted for deterministic output. Lets callers warn
    /// when more than one exists — envy has no way to know which file a
    /// project actually loads.
    pub env_files: Vec<PathBuf>,
}

/// Scans `root` for credential candidates.
///
/// Respects `.gitignore`, `.ignore`, and standard ignore rules via the
/// `ignore` crate. Skips binary files, files larger than 1 MiB, and
/// directories named `target`, `node_modules`, `.git`, and `dist`.
pub fn scan(root: &Path, registry: &Registry) -> ScanResult {
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut read_errors: Vec<(PathBuf, String)> = Vec::new();
    // Keyed on (file, var_name), not var_name alone: collapses an
    // accidental literal repeat within one file, but no longer suppresses
    // the same name showing up in a *different* file — that's a real
    // finding (see `env_files`/cross-file-duplicate reporting in
    // `src/commands/scan.rs`), not noise to hide.
    let mut seen_names: std::collections::HashSet<(PathBuf, String)> =
        std::collections::HashSet::new();
    let mut env_files: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    for path in walk::walk(root) {
        if extract::is_env_file(&path) {
            env_files.insert(path.clone());
        }

        match extract::extract_candidates(&path) {
            Ok(raw) => {
                for raw_candidate in raw {
                    if !seen_names.insert((path.clone(), raw_candidate.var_name.clone())) {
                        continue;
                    }

                    let findings =
                        registry.classify(&raw_candidate.var_name, &raw_candidate.value_str);
                    let entropy = shannon_entropy(raw_candidate.value_str.as_bytes());
                    let masked = mask(&raw_candidate.value_str);

                    let candidate = Candidate {
                        path: path.clone(),
                        line: raw_candidate.line,
                        var_name: raw_candidate.var_name,
                        masked_value: masked,
                        findings,
                        entropy,
                        value: raw_candidate.value_str.into_bytes(),
                    };

                    // Only surface values that look like secrets.
                    if candidate.looks_like_secret() {
                        candidates.push(candidate);
                    }
                }
            }
            Err(e) => read_errors.push((path, e)),
        }
    }

    let mut env_files: Vec<PathBuf> = env_files.into_iter().collect();
    env_files.sort();

    ScanResult {
        candidates,
        read_errors,
        env_files,
    }
}

/// Masks a credential value for display: keeps the first 4 characters
/// visible and replaces the rest with `*`. Values shorter than 4
/// characters are fully masked.
fn mask(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 4 {
        // Too short to reveal any prefix — mask everything.
        return "*".repeat(chars.len());
    }
    let visible: String = chars[..4].iter().collect();
    let stars = "*".repeat(chars.len() - 4);
    format!("{visible}{stars}")
}

/// Shannon entropy in bits per character for `data`.
pub(crate) fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_keeps_first_four_chars() {
        assert_eq!(mask("sk_live_abc123"), "sk_l**********");
        assert_eq!(mask("abc"), "***");
        assert_eq!(mask(""), "");
    }

    #[test]
    fn entropy_zero_for_uniform_string() {
        // All same character → 0 entropy.
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
    }

    #[test]
    fn entropy_high_for_random_looking_value() {
        // A random-looking key should score well above the threshold.
        let e = shannon_entropy(b"sk_live_a1B2c3D4e5F6g7H8");
        assert!(
            e > ENTROPY_THRESHOLD,
            "entropy {e} should be above {ENTROPY_THRESHOLD}"
        );
    }

    #[test]
    fn entropy_low_for_simple_word() {
        let e = shannon_entropy(b"password");
        // "password" has some entropy but low diversity.
        assert!(e < 3.0, "entropy {e} should be low for a simple word");
    }

    #[test]
    fn candidate_looks_like_secret_with_high_entropy() {
        let c = Candidate {
            path: PathBuf::from("test.env"),
            line: 1,
            var_name: "UNKNOWN_KEY".to_string(),
            masked_value: "abcd****".to_string(),
            findings: vec![],
            entropy: 4.2,
            value: b"abcdefghijklmnopqrst".to_vec(),
        };
        assert!(c.looks_like_secret());
    }

    #[test]
    fn candidate_does_not_look_like_secret_with_low_entropy_and_no_findings() {
        let c = Candidate {
            path: PathBuf::from("test.env"),
            line: 1,
            var_name: "SIMPLE_VAR".to_string(),
            masked_value: "pass****".to_string(),
            findings: vec![],
            entropy: 2.0,
            value: b"password".to_vec(),
        };
        assert!(!c.looks_like_secret());
    }

    #[test]
    fn scan_records_every_env_family_file_found() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "STRIPE_KEY=sk_live_a1B2c3D4e5F6g7H8\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".env.production"),
            "STRIPE_KEY=sk_live_z9Y8x7W6v5U4t3S2\n",
        )
        .unwrap();
        // A non-env file should never count toward env_files.
        std::fs::write(dir.path().join("config.toml"), "port = 8080\n").unwrap();

        let registry = Registry::from_descriptors(vec![]);
        let result = scan(dir.path(), &registry);

        let mut names: Vec<String> = result
            .env_files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        names.sort();
        assert_eq!(names, vec![".env", ".env.production"]);
    }

    #[test]
    fn scan_surfaces_the_same_var_name_from_different_files() {
        // Regression test: candidates used to be deduplicated by
        // var_name alone, globally across the whole run, so the second
        // file's value was silently dropped and never shown at all.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "STRIPE_KEY=sk_live_a1B2c3D4e5F6g7H8\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".env.production"),
            "STRIPE_KEY=sk_live_z9Y8x7W6v5U4t3S2\n",
        )
        .unwrap();

        let registry = Registry::from_descriptors(vec![]);
        let result = scan(dir.path(), &registry);

        let stripe_candidates: Vec<&Candidate> = result
            .candidates
            .iter()
            .filter(|c| c.var_name == "STRIPE_KEY")
            .collect();
        assert_eq!(
            stripe_candidates.len(),
            2,
            "expected one candidate per file"
        );
        let mut paths: Vec<String> = stripe_candidates
            .iter()
            .map(|c| c.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        paths.sort();
        assert_eq!(paths, vec![".env", ".env.production"]);
    }

    #[test]
    fn scan_still_collapses_a_literal_repeat_within_one_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "STRIPE_KEY=sk_live_a1B2c3D4e5F6g7H8\nSTRIPE_KEY=sk_live_a1B2c3D4e5F6g7H8\n",
        )
        .unwrap();

        let registry = Registry::from_descriptors(vec![]);
        let result = scan(dir.path(), &registry);

        let stripe_candidates: Vec<&Candidate> = result
            .candidates
            .iter()
            .filter(|c| c.var_name == "STRIPE_KEY")
            .collect();
        assert_eq!(stripe_candidates.len(), 1);
    }
}
