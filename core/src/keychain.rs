use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::error::CoreError;

const SERVICE: &str = "envy";

/// Abstracts over "somewhere that can hold a vault's 256-bit data key
/// outside the vault directory itself". The only production
/// implementation is [`OsKeychain`]; a test-only in-memory double exists
/// so unit tests never touch the real OS keychain (see FR-03: test-only
/// fallbacks must be clearly separated from production builds).
pub trait KeyStore {
    fn store_key(&self, vault_id: &str, key: &[u8; 32]) -> Result<(), CoreError>;
    fn load_key(&self, vault_id: &str) -> Result<[u8; 32], CoreError>;
}

/// Stores the vault data key in the platform keychain (macOS Keychain,
/// Windows Credential Manager, or the Linux Secret Service), keyed by
/// vault ID so multiple vaults on one machine don't collide.
pub struct OsKeychain;

impl KeyStore for OsKeychain {
    fn store_key(&self, vault_id: &str, key: &[u8; 32]) -> Result<(), CoreError> {
        let entry = keyring::Entry::new(SERVICE, vault_id)?;
        entry.set_password(&BASE64.encode(key))?;
        Ok(())
    }

    fn load_key(&self, vault_id: &str) -> Result<[u8; 32], CoreError> {
        let entry = keyring::Entry::new(SERVICE, vault_id)?;
        let encoded = entry.get_password()?;
        let bytes = BASE64
            .decode(encoded)
            .map_err(|_| CoreError::DecryptionFailed)?;
        <[u8; 32]>::try_from(bytes).map_err(|_| CoreError::DecryptionFailed)
    }
}

#[cfg(test)]
pub struct InMemoryKeyStore {
    keys: std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>>,
}

#[cfg(test)]
impl InMemoryKeyStore {
    pub fn new() -> Self {
        Self {
            keys: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[cfg(test)]
impl KeyStore for InMemoryKeyStore {
    fn store_key(&self, vault_id: &str, key: &[u8; 32]) -> Result<(), CoreError> {
        self.keys.lock().unwrap().insert(vault_id.to_string(), *key);
        Ok(())
    }

    fn load_key(&self, vault_id: &str) -> Result<[u8; 32], CoreError> {
        self.keys
            .lock()
            .unwrap()
            .get(vault_id)
            .copied()
            .ok_or(CoreError::DecryptionFailed)
    }
}
