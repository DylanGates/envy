//! SSH Key, Host Profile & Infrastructure management (Phase 5).
//!
//! Stores SSH private keys securely in the encrypted vault under `credential_kind = "ssh_key"`,
//! computes real OpenSSH `SHA256:` fingerprints from public key blobs, and manages host
//! connection profiles and pinned host keys.
//!
//! All private-key handling here is in memory (`ssh-key` crate); nothing in this module writes
//! key material to disk or spawns `ssh-keygen`.

use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey};
use std::path::Path;
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::vault::Vault;

/// Represents metadata for a stored SSH private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyInfo {
    pub name: String,
    pub key_type: String,
    pub fingerprint: String,
    pub comment: Option<String>,
}

/// Represents a configured server/host profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshHostProfile {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub identity: String,
    pub known_host_required: bool,
    /// Pinned OpenSSH host key (`"<type> <base64>"`, public data), set by
    /// `envy ssh trust`. `None` means the host has not been pinned yet.
    #[serde(default)]
    pub host_key: Option<String>,
}

/// Represents a parsed Host block from ~/.ssh/config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfigEntry {
    pub host_alias: String,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity_file: Option<String>,
}

/// Parses an OpenSSH config file (e.g. `~/.ssh/config`) into entries.
pub fn parse_ssh_config(content: &str) -> Vec<SshConfigEntry> {
    let mut entries = Vec::new();
    let mut current: Option<SshConfigEntry> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let Some(key) = parts.next() else { continue };
        let value = parts.collect::<Vec<_>>().join(" ");

        if key.eq_ignore_ascii_case("Host") {
            if let Some(entry) = current.take() {
                if !entry.host_alias.contains('*') && !entry.host_alias.contains('?') {
                    entries.push(entry);
                }
            }
            current = Some(SshConfigEntry {
                host_alias: value,
                hostname: None,
                user: None,
                port: None,
                identity_file: None,
            });
        } else if let Some(entry) = &mut current {
            if key.eq_ignore_ascii_case("HostName") {
                entry.hostname = Some(value);
            } else if key.eq_ignore_ascii_case("User") {
                entry.user = Some(value);
            } else if key.eq_ignore_ascii_case("Port") {
                entry.port = value.parse().ok();
            } else if key.eq_ignore_ascii_case("IdentityFile") {
                entry.identity_file = Some(value);
            }
        }
    }

    if let Some(entry) = current {
        if !entry.host_alias.contains('*') && !entry.host_alias.contains('?') {
            entries.push(entry);
        }
    }

    entries
}
/// `credential_kind` value for SSH private keys stored in the vault.
pub const SSH_KEY_KIND: &str = "ssh_key";

/// `vault_meta` marker recording that the one-time `credential_kind` backfill ran.
const BACKFILL_MARKER: &str = "ssh_key_kind_backfill_v1";

fn invalid(msg: impl Into<String>) -> CoreError {
    CoreError::InvalidRequest(msg.into())
}

/// Parses an unencrypted OpenSSH private key held in memory.
pub fn parse_private_key(bytes: &[u8]) -> Result<PrivateKey, CoreError> {
    let key = PrivateKey::from_openssh(bytes)
        .map_err(|e| invalid(format!("not a valid OpenSSH private key: {e}")))?;
    if key.is_encrypted() {
        return Err(invalid(
            "passphrase-protected SSH keys are not supported yet; remove the passphrase with `ssh-keygen -p` and import again",
        ));
    }
    Ok(key)
}

/// Real OpenSSH `SHA256:` fingerprint of a public key (same as `ssh-keygen -lf`).
pub fn fingerprint(public: &PublicKey) -> String {
    public.fingerprint(HashAlg::Sha256).to_string()
}

fn non_empty(comment: &str) -> Option<String> {
    if comment.is_empty() {
        None
    } else {
        Some(comment.to_string())
    }
}

/// Parses an OpenSSH private key or a one-line public key and returns
/// `(key_type, SHA256 fingerprint, comment)`. The fingerprint is always
/// computed from the **public** key blob, never from private material.
pub fn inspect_ssh_key(content: &str) -> Result<(String, String, Option<String>), CoreError> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(invalid("SSH key content is empty"));
    }
    let public = if trimmed.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        parse_private_key(trimmed.as_bytes())?.public_key().clone()
    } else if trimmed.starts_with("-----BEGIN") {
        return Err(invalid(
            "only OpenSSH-format keys are supported; convert PEM keys with `ssh-keygen -p -f <key>`",
        ));
    } else {
        PublicKey::from_openssh(trimmed)
            .map_err(|e| invalid(format!("not a valid OpenSSH public key: {e}")))?
    };
    Ok((
        public.algorithm().as_str().to_string(),
        fingerprint(&public),
        non_empty(public.comment()),
    ))
}

fn info_for(name: &str, public: &PublicKey) -> SshKeyInfo {
    SshKeyInfo {
        name: name.to_string(),
        key_type: public.algorithm().as_str().to_string(),
        fingerprint: fingerprint(public),
        comment: non_empty(public.comment()),
    }
}

/// Decrypts the named identity in memory and returns its public key. The
/// decrypted bytes are zeroized before this returns.
pub fn load_public_key(vault: &Vault, name: &str) -> Result<PublicKey, CoreError> {
    let raw = Zeroizing::new(vault.get_secret(name)?);
    let private = parse_private_key(&raw)
        .map_err(|e| invalid(format!("identity '{name}' is not a usable SSH key: {e}")))?;
    Ok(private.public_key().clone())
}

/// Imports an SSH private key file from disk into the vault and marks it
/// `credential_kind = "ssh_key"`.
pub fn import_ssh_key(
    vault: &Vault,
    name: &str,
    file_path: &Path,
) -> Result<SshKeyInfo, CoreError> {
    let content = Zeroizing::new(std::fs::read(file_path).map_err(|e| CoreError::Io {
        path: file_path.to_path_buf(),
        source: e,
    })?);
    let private = parse_private_key(&content)?;
    let info = info_for(name, private.public_key());
    vault.add_secret(name, &content)?;
    vault.set_credential_kind(name, SSH_KEY_KIND)?;
    Ok(info)
}

/// Generates a new Ed25519 keypair **in memory** and stores the private key
/// in the vault. Returns the key info and the OpenSSH public key line.
pub fn generate_ssh_key(
    vault: &Vault,
    name: &str,
    algorithm: &str,
    comment: Option<&str>,
) -> Result<(SshKeyInfo, String), CoreError> {
    if !algorithm.eq_ignore_ascii_case("ed25519") {
        return Err(invalid(format!(
            "unsupported SSH key algorithm '{algorithm}': only ed25519 is supported"
        )));
    }
    let mut rng = rand::rngs::OsRng;
    let mut private = PrivateKey::random(&mut rng, Algorithm::Ed25519)
        .map_err(|e| invalid(format!("failed to generate Ed25519 key: {e}")))?;
    private.set_comment(comment.unwrap_or(name));
    let pem = private
        .to_openssh(LineEnding::LF)
        .map_err(|e| invalid(format!("failed to encode key: {e}")))?;
    let public_line = private
        .public_key()
        .to_openssh()
        .map_err(|e| invalid(format!("failed to encode public key: {e}")))?;
    let info = info_for(name, private.public_key());
    vault.add_secret(name, pem.as_bytes())?;
    vault.set_credential_kind(name, SSH_KEY_KIND)?;
    Ok((info, public_line))
}

/// Derives the OpenSSH public key line for a stored identity, in memory.
pub fn export_ssh_public_key(vault: &Vault, name: &str) -> Result<String, CoreError> {
    load_public_key(vault, name)?
        .to_openssh()
        .map_err(|e| invalid(format!("failed to encode public key: {e}")))
}

/// One-time backfill (G9): marks pre-existing SSH keys with
/// `credential_kind = "ssh_key"`. Runs at most once per vault; afterwards
/// [`list_ssh_keys`] never decrypts non-SSH secrets.
pub fn backfill_ssh_key_kinds(vault: &Vault) -> Result<usize, CoreError> {
    if vault.get_meta(BACKFILL_MARKER)?.is_some() {
        return Ok(0);
    }
    let mut marked = 0;
    for meta in vault.list_secrets()? {
        if meta.credential_kind.is_some() {
            continue;
        }
        let raw = Zeroizing::new(vault.get_secret(&meta.name)?);
        if raw.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----")
            && PrivateKey::from_openssh(&raw[..]).is_ok()
        {
            vault.set_credential_kind(&meta.name, SSH_KEY_KIND)?;
            marked += 1;
        }
    }
    vault.set_meta(BACKFILL_MARKER, "done")?;
    Ok(marked)
}

/// Lists SSH identities (`credential_kind = "ssh_key"`) with real fingerprints.
pub fn list_ssh_keys(vault: &Vault) -> Result<Vec<SshKeyInfo>, CoreError> {
    backfill_ssh_key_kinds(vault)?;
    let mut out = Vec::new();
    for meta in vault.list_secrets()? {
        if meta.credential_kind.as_deref() != Some(SSH_KEY_KIND) {
            continue;
        }
        if let Ok(public) = load_public_key(vault, &meta.name) {
            out.push(info_for(&meta.name, &public));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Host key pinning (M0 / G3)
// ---------------------------------------------------------------------------

/// Parses a pinned host key (`"<type> <base64> [comment]"`).
pub fn parse_host_key(host_key: &str) -> Result<PublicKey, CoreError> {
    PublicKey::from_openssh(host_key.trim())
        .map_err(|e| invalid(format!("invalid pinned host key: {e}")))
}

/// Normalises a host key to `"<type> <base64>"` (drops any comment).
pub fn normalize_host_key(host_key: &str) -> Result<String, CoreError> {
    let public = parse_host_key(host_key)?;
    let line = public
        .to_openssh()
        .map_err(|e| invalid(format!("failed to encode host key: {e}")))?;
    Ok(line
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" "))
}

/// Raw SSH wire blob of a pinned host key (what `session-bind` carries).
pub fn host_key_blob(host_key: &str) -> Result<Vec<u8>, CoreError> {
    parse_host_key(host_key)?
        .to_bytes()
        .map_err(|e| invalid(format!("failed to encode host key: {e}")))
}

/// `known_hosts` host pattern: `host` for port 22, `[host]:port` otherwise.
pub fn known_hosts_pattern(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

/// The single `known_hosts` line for a pinned profile, or `None` if unpinned.
pub fn known_hosts_line(profile: &SshHostProfile) -> Result<Option<String>, CoreError> {
    match &profile.host_key {
        None => Ok(None),
        Some(k) => Ok(Some(format!(
            "{} {}",
            known_hosts_pattern(&profile.host, profile.port),
            normalize_host_key(k)?
        ))),
    }
}

/// Refuses a profile that requires a pinned host key but has none.
pub fn ensure_host_pinned(profile: &SshHostProfile) -> Result<(), CoreError> {
    if profile.known_host_required && profile.host_key.is_none() {
        return Err(CoreError::PolicyDenied(format!(
            "host '{}' requires a pinned host key but none is stored; run `envy ssh trust {}` first",
            profile.name, profile.name
        )));
    }
    Ok(())
}

/// Picks the preferred host key from `ssh-keyscan` output
/// (ed25519 > ecdsa > rsa). Lines look like `host keytype base64`.
pub fn select_preferred_host_key(keyscan_output: &str) -> Option<String> {
    let keys: Vec<String> = keyscan_output
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            (parts.len() >= 3).then(|| format!("{} {}", parts[1], parts[2]))
        })
        .filter(|k| parse_host_key(k).is_ok())
        .collect();
    for prefix in ["ssh-ed25519", "ecdsa-sha2-", "rsa-sha2-", "ssh-rsa"] {
        if let Some(k) = keys.iter().find(|k| k.starts_with(prefix)) {
            return Some(k.clone());
        }
    }
    None
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keychain::InMemoryKeyStore;
    use crate::vault::init_with_keystore;

    /// Created with `ssh-keygen -t ed25519 -N "" -C envy-fixture`.
    /// `ssh-keygen -lf` printed:
    /// `256 SHA256:oRt4xK5cQVYqNgXayeIVs70ccdbXSVxIxDQGqDTOSkQ envy-fixture (ED25519)`.
    /// Test-only key; it protects nothing.
    pub(crate) const FIXTURE_ED25519: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAenIL+RyilLKurnRJXE0KIPe0Ox/uaZ5QvQ6l8h9sLiAAAAJBI6aR/SOmk
fwAAAAtzc2gtZWQyNTUxOQAAACAenIL+RyilLKurnRJXE0KIPe0Ox/uaZ5QvQ6l8h9sLiA
AAAEDEA83Xh9ytVBfEx8HqnW3uSYGbgyzxw+85Dte3o9rSdh6cgv5HKKUsq6udElcTQog9
7Q7H+5pnlC9DqXyH2wuIAAAADGVudnktZml4dHVyZQE=
-----END OPENSSH PRIVATE KEY-----
";
    pub(crate) const FIXTURE_ED25519_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB6cgv5HKKUsq6udElcTQog97Q7H+5pnlC9DqXyH2wuI envy-fixture";
    pub(crate) const FIXTURE_FINGERPRINT: &str =
        "SHA256:oRt4xK5cQVYqNgXayeIVs70ccdbXSVxIxDQGqDTOSkQ";

    #[test]
    fn fixture_fingerprint_matches_ssh_keygen() {
        let (key_type, fp, comment) = inspect_ssh_key(FIXTURE_ED25519).unwrap();
        assert_eq!(key_type, "ssh-ed25519");
        assert_eq!(fp, FIXTURE_FINGERPRINT);
        assert_eq!(comment.as_deref(), Some("envy-fixture"));
        // Public line gives the same fingerprint.
        let (_, pub_fp, _) = inspect_ssh_key(FIXTURE_ED25519_PUB).unwrap();
        assert_eq!(pub_fp, FIXTURE_FINGERPRINT);
    }

    #[test]
    fn inspect_rejects_garbage_key() {
        let fake_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n";
        assert!(inspect_ssh_key(fake_key).is_err());
        assert!(inspect_ssh_key("").is_err());
    }

    #[test]
    fn inspect_and_import_ssh_key() {
        let temp_dir = tempfile::tempdir().unwrap();
        let key_file = temp_dir.path().join("id_ed25519");
        std::fs::write(&key_file, FIXTURE_ED25519).unwrap();

        let store = InMemoryKeyStore::new();
        let vault = init_with_keystore(temp_dir.path(), &store).unwrap();

        let info = import_ssh_key(&vault, "deploy_key", &key_file).unwrap();
        assert_eq!(info.name, "deploy_key");
        assert_eq!(info.key_type, "ssh-ed25519");
        assert_eq!(info.fingerprint, FIXTURE_FINGERPRINT);
        assert_eq!(
            vault.get_secret("deploy_key").unwrap(),
            FIXTURE_ED25519.as_bytes()
        );
        let meta = vault.get_secret_metadata("deploy_key").unwrap();
        assert_eq!(meta.credential_kind.as_deref(), Some(SSH_KEY_KIND));
        assert_eq!(
            export_ssh_public_key(&vault, "deploy_key").unwrap(),
            FIXTURE_ED25519_PUB
        );
    }

    #[test]
    fn generate_is_in_memory_and_listed_by_kind() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = InMemoryKeyStore::new();
        let vault = init_with_keystore(temp_dir.path(), &store).unwrap();
        vault.add_secret("stripe_key", b"sk_test_not_ssh").unwrap();

        let (info, public_line) =
            generate_ssh_key(&vault, "gen", "ed25519", Some("me@test")).unwrap();
        assert!(public_line.starts_with("ssh-ed25519 "));
        assert!(public_line.ends_with(" me@test"));
        let (_, fp, _) = inspect_ssh_key(&public_line).unwrap();
        assert_eq!(fp, info.fingerprint);
        assert!(generate_ssh_key(&vault, "rsa", "rsa", None).is_err());

        let keys = list_ssh_keys(&vault).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "gen");
    }

    #[test]
    fn backfill_marks_legacy_ssh_keys_once() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = InMemoryKeyStore::new();
        let vault = init_with_keystore(temp_dir.path(), &store).unwrap();
        // Legacy import path: stored without credential_kind.
        vault
            .add_secret("legacy", FIXTURE_ED25519.as_bytes())
            .unwrap();
        vault.add_secret("other", b"plain").unwrap();
        assert_eq!(backfill_ssh_key_kinds(&vault).unwrap(), 1);
        assert_eq!(backfill_ssh_key_kinds(&vault).unwrap(), 0);
        let keys = list_ssh_keys(&vault).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].fingerprint, FIXTURE_FINGERPRINT);
    }

    #[test]
    fn host_key_helpers_and_unpinned_refusal() {
        let mut profile = SshHostProfile {
            name: "prod".into(),
            host: "127.0.0.1".into(),
            port: 2222,
            user: "deploy".into(),
            identity: "k".into(),
            known_host_required: true,
            host_key: None,
        };
        assert!(matches!(
            ensure_host_pinned(&profile),
            Err(CoreError::PolicyDenied(_))
        ));
        assert_eq!(known_hosts_line(&profile).unwrap(), None);

        let scan = format!(
            "# 127.0.0.1:2222 SSH-2.0-OpenSSH\n[127.0.0.1]:2222 {}\n",
            FIXTURE_ED25519_PUB.trim_end_matches(" envy-fixture")
        );
        let pinned = select_preferred_host_key(&scan).unwrap();
        profile.host_key = Some(pinned.clone());
        ensure_host_pinned(&profile).unwrap();
        assert_eq!(
            known_hosts_line(&profile).unwrap().unwrap(),
            format!("[127.0.0.1]:2222 {pinned}")
        );
        assert_eq!(known_hosts_pattern("h", 22), "h");
        assert!(select_preferred_host_key("garbage line here").is_none());
    }
}
