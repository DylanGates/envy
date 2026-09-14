use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::keychain::{KeyStore, OsKeychain};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    provider TEXT,
    credential_kind TEXT,
    ciphertext BLOB NOT NULL,
    nonce BLOB NOT NULL,
    fingerprint TEXT NOT NULL,
    risk TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    subject TEXT,
    project TEXT,
    provider TEXT,
    operation TEXT NOT NULL,
    endpoint_host TEXT,
    outcome TEXT NOT NULL,
    redaction_summary TEXT
);
"#;

#[derive(Debug, Serialize, Deserialize)]
struct VaultConfig {
    vault_id: String,
    schema_version: u32,
}

/// A handle to an opened vault.
pub struct Vault {
    pub vault_id: String,
    pub(crate) conn: rusqlite::Connection,
    /// The vault's master key, kept in memory only for this handle's
    /// lifetime. Never logged or printed. `add_secret` derives the
    /// encryption/fingerprint subkeys from it on demand.
    key: [u8; 32],
}

impl Vault {
    /// Encrypts `value` and stores it under `name`. Fails with
    /// [`CoreError::SecretAlreadyExists`] if `name` is already in use.
    pub fn add_secret(&self, name: &str, value: &[u8]) -> Result<(), CoreError> {
        let enc_key = crate::crypto::derive_encryption_key(&self.key);
        let fp_key = crate::crypto::derive_fingerprint_key(&self.key);
        let (nonce, ciphertext) = crate::crypto::encrypt(&enc_key, value);
        let fingerprint = crate::crypto::fingerprint(&fp_key, value);

        let result = self.conn.execute(
            "INSERT INTO secrets (id, name, ciphertext, nonce, fingerprint) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![name, name, ciphertext, nonce.as_slice(), fingerprint],
        );

        match result {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(CoreError::SecretAlreadyExists(name.to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Decrypts and returns the value stored under `name`.
    pub fn get_secret(&self, name: &str) -> Result<Vec<u8>, CoreError> {
        use rusqlite::OptionalExtension;

        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT ciphertext, nonce FROM secrets WHERE id = ?1",
                rusqlite::params![name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let (ciphertext, nonce) = row.ok_or_else(|| CoreError::SecretNotFound(name.to_string()))?;
        let nonce: [u8; 12] = nonce.try_into().map_err(|_| CoreError::DecryptionFailed)?;

        let enc_key = crate::crypto::derive_encryption_key(&self.key);
        crate::crypto::decrypt(&enc_key, &nonce, &ciphertext)
    }
}

/// Creates and opens the local vault under `<project_root>/.envy/`.
///
/// Safe to call repeatedly: if a complete vault already exists, this just
/// opens it rather than regenerating the key or schema.
pub fn init(project_root: &Path) -> Result<Vault, CoreError> {
    init_with_keystore(project_root, &OsKeychain)
}

/// Opens an existing vault under `<project_root>/.envy/`.
pub fn open(project_root: &Path) -> Result<Vault, CoreError> {
    open_with_keystore(project_root, &OsKeychain)
}

pub(crate) fn init_with_keystore(project_root: &Path, keystore: &dyn KeyStore) -> Result<Vault, CoreError> {
    let envy_dir = project_root.join(".envy");
    let db_path = envy_dir.join("vault.db");
    let config_path = envy_dir.join("config.toml");

    let db_exists = db_path.exists();
    let config_exists = config_path.exists();

    if db_exists && config_exists {
        return open_with_keystore(project_root, keystore);
    }
    if db_exists != config_exists {
        return Err(CoreError::PartialVault(envy_dir));
    }

    std::fs::create_dir_all(&envy_dir).map_err(|source| CoreError::Io {
        path: envy_dir.clone(),
        source,
    })?;

    let vault_id = generate_vault_id();
    let key = crate::crypto::generate_key();
    keystore.store_key(&vault_id, &key)?;

    let mut conn = rusqlite::Connection::open(&db_path)?;
    let tx = conn.transaction()?;
    tx.execute_batch(SCHEMA)?;
    tx.commit()?;

    let config = VaultConfig {
        vault_id: vault_id.clone(),
        schema_version: 1,
    };
    let toml_str = toml::to_string_pretty(&config)?;
    std::fs::write(&config_path, toml_str).map_err(|source| CoreError::Io {
        path: config_path.clone(),
        source,
    })?;

    enforce_permissions(&envy_dir, &db_path)?;

    Ok(Vault {
        vault_id,
        conn,
        key,
    })
}

fn open_with_keystore(project_root: &Path, keystore: &dyn KeyStore) -> Result<Vault, CoreError> {
    let envy_dir = project_root.join(".envy");
    let db_path = envy_dir.join("vault.db");
    let config_path = envy_dir.join("config.toml");

    let db_exists = db_path.exists();
    let config_exists = config_path.exists();

    if !db_exists && !config_exists {
        return Err(CoreError::VaultNotFound(envy_dir));
    }
    if db_exists != config_exists {
        return Err(CoreError::PartialVault(envy_dir));
    }

    check_permissions(&envy_dir, &db_path)?;

    let config_str = std::fs::read_to_string(&config_path).map_err(|source| CoreError::Io {
        path: config_path.clone(),
        source,
    })?;
    let config: VaultConfig = toml::from_str(&config_str)?;

    // Also confirms the key still resolves (fails closed if the keychain
    // entry is missing/inaccessible).
    let key = keystore.load_key(&config.vault_id)?;

    let conn = rusqlite::Connection::open(&db_path)?;

    Ok(Vault {
        vault_id: config.vault_id,
        conn,
        key,
    })
}

fn generate_vault_id() -> String {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(unix)]
fn enforce_permissions(dir: &Path, db_path: &Path) -> Result<(), CoreError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|source| {
        CoreError::Io {
            path: dir.to_path_buf(),
            source,
        }
    })?;
    std::fs::set_permissions(db_path, std::fs::Permissions::from_mode(0o600)).map_err(|source| {
        CoreError::Io {
            path: db_path.to_path_buf(),
            source,
        }
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn enforce_permissions(_dir: &Path, _db_path: &Path) -> Result<(), CoreError> {
    // Windows ACL hardening is not implemented yet; tracked as a known gap.
    Ok(())
}

#[cfg(unix)]
fn check_permissions(dir: &Path, db_path: &Path) -> Result<(), CoreError> {
    use std::os::unix::fs::PermissionsExt;
    for path in [dir, db_path] {
        let mode = std::fs::metadata(path)
            .map_err(|source| CoreError::Io {
                path: path.to_path_buf(),
                source,
            })?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(CoreError::InsecurePermissions(path.to_path_buf()));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_dir: &Path, _db_path: &Path) -> Result<(), CoreError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::InMemoryKeyStore;

    #[test]
    fn init_creates_vault_files() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = InMemoryKeyStore::new();
        let vault = init_with_keystore(dir.path(), &keystore).unwrap();
        assert!(dir.path().join(".envy/vault.db").exists());
        assert!(dir.path().join(".envy/config.toml").exists());
        assert!(!vault.vault_id.is_empty());
    }

    #[test]
    fn init_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = InMemoryKeyStore::new();
        let first = init_with_keystore(dir.path(), &keystore).unwrap();
        let second = init_with_keystore(dir.path(), &keystore).unwrap();
        assert_eq!(first.vault_id, second.vault_id);
    }

    #[test]
    fn open_round_trips_after_init() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = InMemoryKeyStore::new();
        let created = init_with_keystore(dir.path(), &keystore).unwrap();
        let opened = open_with_keystore(dir.path(), &keystore).unwrap();
        assert_eq!(created.vault_id, opened.vault_id);
    }

    #[test]
    fn open_fails_on_partial_vault() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".envy")).unwrap();
        std::fs::write(dir.path().join(".envy/vault.db"), b"").unwrap();
        // config.toml deliberately left missing.
        let keystore = InMemoryKeyStore::new();
        let result = open_with_keystore(dir.path(), &keystore);
        assert!(matches!(result, Err(CoreError::PartialVault(_))));
    }

    #[test]
    fn open_fails_on_vault_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = InMemoryKeyStore::new();
        let result = open_with_keystore(dir.path(), &keystore);
        assert!(matches!(result, Err(CoreError::VaultNotFound(_))));
    }

    #[test]
    fn add_secret_round_trips_through_raw_storage() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = InMemoryKeyStore::new();
        let vault = init_with_keystore(dir.path(), &keystore).unwrap();
        vault.add_secret("STRIPE_KEY", b"sk_live_abc123").unwrap();

        let (ciphertext, nonce): (Vec<u8>, Vec<u8>) = vault
            .conn
            .query_row(
                "SELECT ciphertext, nonce FROM secrets WHERE id = ?1",
                rusqlite::params!["STRIPE_KEY"],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        let enc_key = crate::crypto::derive_encryption_key(&vault.key);
        let decrypted = crate::crypto::decrypt(&enc_key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, b"sk_live_abc123");
    }

    #[test]
    fn add_secret_rejects_duplicate_name() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = InMemoryKeyStore::new();
        let vault = init_with_keystore(dir.path(), &keystore).unwrap();
        vault.add_secret("STRIPE_KEY", b"sk_live_abc123").unwrap();
        let result = vault.add_secret("STRIPE_KEY", b"sk_live_different");
        assert!(matches!(result, Err(CoreError::SecretAlreadyExists(name)) if name == "STRIPE_KEY"));
    }

    #[test]
    fn get_secret_round_trips_with_add_secret() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = InMemoryKeyStore::new();
        let vault = init_with_keystore(dir.path(), &keystore).unwrap();
        vault.add_secret("STRIPE_KEY", b"sk_live_abc123").unwrap();
        let value = vault.get_secret("STRIPE_KEY").unwrap();
        assert_eq!(value, b"sk_live_abc123");
    }

    #[test]
    fn get_secret_fails_for_missing_name() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = InMemoryKeyStore::new();
        let vault = init_with_keystore(dir.path(), &keystore).unwrap();
        let result = vault.get_secret("DOES_NOT_EXIST");
        assert!(matches!(result, Err(CoreError::SecretNotFound(name)) if name == "DOES_NOT_EXIST"));
    }

    #[cfg(unix)]
    #[test]
    fn open_fails_on_insecure_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let keystore = InMemoryKeyStore::new();
        init_with_keystore(dir.path(), &keystore).unwrap();
        let envy_dir = dir.path().join(".envy");
        std::fs::set_permissions(&envy_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let result = open_with_keystore(dir.path(), &keystore);
        assert!(matches!(result, Err(CoreError::InsecurePermissions(_))));
    }
}
