use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::CoreError;

/// Generates a random 256-bit vault data key.
pub fn generate_key() -> [u8; 32] {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    key.into()
}

/// Encrypts `plaintext` with AES-256-GCM under `key`, returning the random
/// nonce used and the ciphertext (which includes the authentication tag).
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> ([u8; 12], Vec<u8>) {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    // Only fails if plaintext exceeds AES-GCM's ~64GiB limit, which never
    // happens for a single credential value.
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("AES-256-GCM encryption of a credential value cannot fail");
    (nonce.into(), ciphertext)
}

/// Decrypts a ciphertext produced by [`encrypt`]. Fails if `key`/`nonce`
/// don't match or the ciphertext has been tampered with.
pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, CoreError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| CoreError::DecryptionFailed)
}

/// Derives the vault's AES-256-GCM encryption subkey from its master key.
pub fn derive_encryption_key(master: &[u8; 32]) -> [u8; 32] {
    derive_subkey(master, b"envy-v1-encryption-key")
}

/// Derives the vault's HMAC-SHA256 fingerprinting subkey from its master
/// key. Kept independent from the encryption subkey (key separation): a
/// weakness in one use can't bleed into the other.
pub fn derive_fingerprint_key(master: &[u8; 32]) -> [u8; 32] {
    derive_subkey(master, b"envy-v1-fingerprint-key")
}

fn derive_subkey(master: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// Computes a vault-scoped keyed fingerprint of `value` for duplicate
/// detection, per FR-02: this must never be a public unsalted hash, since
/// that would let anyone precompute fingerprints for known secret values
/// and look them up in a leaked vault.
pub fn fingerprint(key: &[u8; 32], value: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(value);
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = generate_key();
        let plaintext = b"sk_live_super_secret_value";
        let (nonce, ciphertext) = encrypt(&key, plaintext);
        let decrypted = decrypt(&key, &nonce, &ciphertext).expect("decrypt should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let key = generate_key();
        let (nonce, mut ciphertext) = encrypt(&key, b"sk_live_super_secret_value");
        ciphertext[0] ^= 0xFF;
        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(matches!(result, Err(CoreError::DecryptionFailed)));
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let key = generate_key();
        let other_key = generate_key();
        let (nonce, ciphertext) = encrypt(&key, b"sk_live_super_secret_value");
        let result = decrypt(&other_key, &nonce, &ciphertext);
        assert!(matches!(result, Err(CoreError::DecryptionFailed)));
    }

    #[test]
    fn derived_subkeys_differ_from_each_other_and_the_master() {
        let master = generate_key();
        let enc_key = derive_encryption_key(&master);
        let fp_key = derive_fingerprint_key(&master);
        assert_ne!(enc_key, fp_key);
        assert_ne!(enc_key, master);
        assert_ne!(fp_key, master);
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let key = generate_key();
        let value = b"sk_live_super_secret_value";
        assert_eq!(fingerprint(&key, value), fingerprint(&key, value));
    }

    #[test]
    fn fingerprint_differs_for_different_values() {
        let key = generate_key();
        assert_ne!(
            fingerprint(&key, b"sk_live_value_one"),
            fingerprint(&key, b"sk_live_value_two")
        );
    }

    #[test]
    fn fingerprint_is_vault_scoped() {
        let value = b"sk_live_super_secret_value";
        let key_a = generate_key();
        let key_b = generate_key();
        assert_ne!(fingerprint(&key_a, value), fingerprint(&key_b, value));
    }
}
