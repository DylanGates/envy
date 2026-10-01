use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::CoreError;
use crate::vault::Vault;

/// File magic header identifying an Envy encrypted backup file.
pub const BACKUP_MAGIC: &[u8; 8] = b"ENVYBK01";

/// Default Argon2 parameters for encrypted export:
/// 64 MiB memory cost (65536 KiB), 3 iterations, 4 lanes parallelism.
const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

/// Serialized payload contained inside the encrypted backup envelope.
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupPayload {
    pub schema_version: u32,
    pub created_at: String,
    pub secrets: Vec<BackupSecretItem>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupSecretItem {
    pub name: String,
    pub value: Vec<u8>,
    pub provider: Option<String>,
    pub credential_kind: Option<String>,
    pub risk: Option<String>,
}

/// JSON-serializable outer envelope holding Argon2 salt/params, nonce, and ciphertext.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedBackupFile {
    pub magic: String,
    pub version: u32,
    pub kdf: KdfParams,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub salt: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

/// Derives a 256-bit AES-GCM key from `password` and `salt` using Argon2id.
pub fn derive_backup_key(
    password: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32], CoreError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| CoreError::InvalidRequest(format!("invalid Argon2 parameters: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| CoreError::InvalidRequest(format!("Argon2 key derivation failed: {e}")))?;

    Ok(key)
}

/// Exports all secrets from `vault` into an encrypted backup JSON string protected by `password`.
pub fn export_encrypted(vault: &Vault, password: &[u8]) -> Result<String, CoreError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    let secret_metas = vault.list_secrets()?;
    let mut backup_items = Vec::with_capacity(secret_metas.len());

    for meta in secret_metas {
        let value = vault.get_secret(&meta.name)?;
        backup_items.push(BackupSecretItem {
            name: meta.name,
            value,
            provider: meta.provider,
            credential_kind: meta.credential_kind,
            risk: meta.risk,
        });
    }

    let payload = BackupPayload {
        schema_version: 1,
        created_at: format!("{:?}", std::time::SystemTime::now()),
        secrets: backup_items,
    };

    let serialized_payload = serde_json::to_vec(&payload).map_err(|e| {
        CoreError::InvalidRequest(format!("failed to serialize backup payload: {e}"))
    })?;

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_backup_key(password, &salt, ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST)?;
    let (nonce, ciphertext) = crypto::encrypt(&key, &serialized_payload);

    let backup_file = EncryptedBackupFile {
        magic: String::from_utf8_lossy(BACKUP_MAGIC).to_string(),
        version: 1,
        kdf: KdfParams {
            algorithm: "argon2id".to_string(),
            salt: B64.encode(salt),
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
        },
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    };

    serde_json::to_string_pretty(&backup_file).map_err(|e| {
        CoreError::InvalidRequest(format!("failed to serialize encrypted backup: {e}"))
    })
}

/// Result counts of importing an encrypted backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportResult {
    pub imported: usize,
    pub skipped: usize,
    pub total: usize,
}

/// Decrypts and restores an encrypted backup into `vault` using `password`.
/// Existing secrets with the same name are skipped.
pub fn import_encrypted(
    vault: &Vault,
    encrypted_json: &str,
    password: &[u8],
) -> Result<ImportResult, CoreError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    let backup_file: EncryptedBackupFile = serde_json::from_str(encrypted_json)
        .map_err(|e| CoreError::InvalidRequest(format!("invalid backup file format: {e}")))?;

    if backup_file.magic != String::from_utf8_lossy(BACKUP_MAGIC) {
        return Err(CoreError::InvalidRequest(
            "unrecognized backup file magic header".to_string(),
        ));
    }

    if backup_file.kdf.algorithm != "argon2id" {
        return Err(CoreError::InvalidRequest(format!(
            "unsupported KDF algorithm '{}'",
            backup_file.kdf.algorithm
        )));
    }

    let salt = B64
        .decode(&backup_file.kdf.salt)
        .map_err(|e| CoreError::InvalidRequest(format!("invalid salt encoding: {e}")))?;

    let nonce_raw = B64
        .decode(&backup_file.nonce)
        .map_err(|e| CoreError::InvalidRequest(format!("invalid nonce encoding: {e}")))?;

    if nonce_raw.len() != 12 {
        return Err(CoreError::InvalidRequest(
            "invalid nonce length".to_string(),
        ));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_raw);

    let ciphertext = B64
        .decode(&backup_file.ciphertext)
        .map_err(|e| CoreError::InvalidRequest(format!("invalid ciphertext encoding: {e}")))?;

    let key = derive_backup_key(
        password,
        &salt,
        backup_file.kdf.m_cost,
        backup_file.kdf.t_cost,
        backup_file.kdf.p_cost,
    )?;

    let decrypted_bytes = crypto::decrypt(&key, &nonce, &ciphertext)?;

    let payload: BackupPayload = serde_json::from_slice(&decrypted_bytes)
        .map_err(|e| CoreError::InvalidRequest(format!("invalid decrypted payload format: {e}")))?;

    let total = payload.secrets.len();
    let mut imported = 0usize;
    let mut skipped = 0usize;

    for item in payload.secrets {
        match vault.add_secret(&item.name, &item.value) {
            Ok(()) => imported += 1,
            Err(CoreError::SecretAlreadyExists(_)) => skipped += 1,
            Err(e) => return Err(e),
        }
    }

    Ok(ImportResult {
        imported,
        skipped,
        total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::InMemoryKeyStore;
    use crate::vault::init_with_keystore;

    #[test]
    fn encrypted_export_and_import_round_trips() {
        let temp_dir1 = tempfile::tempdir().unwrap();
        let store1 = InMemoryKeyStore::new();
        let vault1 = init_with_keystore(temp_dir1.path(), &store1).unwrap();

        vault1.add_secret("STRIPE_KEY", b"sk_test_12345").unwrap();
        vault1.add_secret("OPENAI_KEY", b"sk-openai-xyz").unwrap();

        let password = b"super-strong-backup-password";
        let backup_json = export_encrypted(&vault1, password).unwrap();
        assert!(backup_json.contains("ENVYBK01"));
        assert!(!backup_json.contains("sk_test_12345"));
        assert!(!backup_json.contains("sk-openai-xyz"));

        // Import into a fresh vault
        let temp_dir2 = tempfile::tempdir().unwrap();
        let store2 = InMemoryKeyStore::new();
        let vault2 = init_with_keystore(temp_dir2.path(), &store2).unwrap();

        let res = import_encrypted(&vault2, &backup_json, password).unwrap();
        assert_eq!(
            res,
            ImportResult {
                imported: 2,
                skipped: 0,
                total: 2,
            }
        );

        assert_eq!(vault2.get_secret("STRIPE_KEY").unwrap(), b"sk_test_12345");
        assert_eq!(vault2.get_secret("OPENAI_KEY").unwrap(), b"sk-openai-xyz");

        // Re-importing into the same vault skips already-existing secrets
        let res2 = import_encrypted(&vault2, &backup_json, password).unwrap();
        assert_eq!(
            res2,
            ImportResult {
                imported: 0,
                skipped: 2,
                total: 2,
            }
        );
    }

    #[test]
    fn wrong_password_fails_decryption() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = InMemoryKeyStore::new();
        let vault = init_with_keystore(temp_dir.path(), &store).unwrap();
        vault.add_secret("KEY", b"secret").unwrap();

        let backup_json = export_encrypted(&vault, b"correct-password").unwrap();

        let temp_dir2 = tempfile::tempdir().unwrap();
        let store2 = InMemoryKeyStore::new();
        let vault2 = init_with_keystore(temp_dir2.path(), &store2).unwrap();

        let err = import_encrypted(&vault2, &backup_json, b"wrong-password").unwrap_err();
        assert!(matches!(err, CoreError::DecryptionFailed));
    }
}
