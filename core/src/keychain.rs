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

#[cfg(test)]
mod real_keychain_diagnostics {
    //! NOT run by default `cargo test` — these touch the real OS
    //! keychain. Run manually with `cargo test -- --ignored`.
    //!
    //! Added while diagnosing the 2026-09-15 vault-persistence bug (see
    //! `docs/LESSONS.md`): `keyring = "3"`'s `apple-native-keyring-store`
    //! backend had a real bug where a fresh `Entry::new()` couldn't see
    //! what a *different* `Entry` instance had written, even
    //! same-process — these two tests are what proved it (the first
    //! failed under `keyring = "3"`, the second passed, isolating the
    //! bug to fresh-`Entry` construction rather than the store/load
    //! logic itself). Switching to `keyring = "2"` (which uses the
    //! mature `security-framework` crate directly) fixed both. Kept as
    //! permanent manual regression tests — this is exactly the class of
    //! bug `InMemoryKeyStore`-only testing can never catch.
    use super::*;

    #[test]
    #[ignore = "touches the real OS keychain"]
    fn same_process_write_then_read_round_trips() {
        let keystore = OsKeychain;
        let vault_id = format!("diagnostic-{}", std::process::id());
        let key = crate::crypto::generate_key();

        keystore
            .store_key(&vault_id, &key)
            .expect("store_key should succeed");
        let loaded = keystore
            .load_key(&vault_id)
            .expect("load_key should succeed immediately after store_key, same process");
        assert_eq!(key, loaded, "round-tripped key must match what was stored");

        // Cleanup regardless of outcome above (panics still run this if
        // wrapped in a guard, but keep it simple: best-effort delete).
        let _ = keyring::Entry::new(SERVICE, &vault_id).and_then(|e| e.delete_password());
    }

    #[test]
    #[ignore = "touches the real OS keychain"]
    fn same_entry_instance_write_then_read_round_trips() {
        let vault_id = format!("diagnostic-single-entry-{}", std::process::id());
        let entry = keyring::Entry::new(SERVICE, &vault_id).expect("Entry::new should succeed");

        entry
            .set_password("test-value-123")
            .expect("set_password should succeed");
        let loaded = entry
            .get_password()
            .expect("get_password on the SAME Entry instance should succeed");
        assert_eq!(loaded, "test-value-123");

        let _ = entry.delete_password();
    }
}
