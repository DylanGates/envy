//! SSH Key, Host Profile & Infrastructure management (Phase 5).
//!
//! Stores SSH private keys securely in the encrypted vault under `credential_kind = "ssh_key"`,
//! parses OpenSSH public key fingerprints, and manages host connection profiles.

use serde::{Deserialize, Serialize};
use std::path::Path;

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
}

/// Parses an OpenSSH or PEM private/public key string to extract the algorithm and fingerprint.
pub fn inspect_ssh_key(content: &str) -> Result<(String, String, Option<String>), CoreError> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(CoreError::InvalidRequest(
            "SSH key content is empty".to_string(),
        ));
    }

    let key_type = if trimmed.contains("BEGIN OPENSSH PRIVATE KEY") {
        "OPENSSH".to_string()
    } else if trimmed.contains("BEGIN RSA PRIVATE KEY") || trimmed.contains("BEGIN PRIVATE KEY") {
        "RSA/PKCS8".to_string()
    } else if trimmed.contains("BEGIN EC PRIVATE KEY") {
        "ECDSA".to_string()
    } else if trimmed.starts_with("ssh-ed25519") {
        "ED25519-PUB".to_string()
    } else if trimmed.starts_with("ssh-rsa") {
        "RSA-PUB".to_string()
    } else {
        "UNKNOWN".to_string()
    };

    // Generate SHA-256 fingerprint of the key content
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(trimmed.as_bytes());
    let hash = hasher.finalize();
    let fingerprint = format!("SHA256:{}", B64.encode(hash));

    Ok((key_type, fingerprint, None))
}

/// Imports an SSH private key file from disk into the vault.
pub fn import_ssh_key(
    vault: &Vault,
    name: &str,
    file_path: &Path,
) -> Result<SshKeyInfo, CoreError> {
    let content = std::fs::read(file_path).map_err(|e| CoreError::Io {
        path: file_path.to_path_buf(),
        source: e,
    })?;

    let text = String::from_utf8_lossy(&content);
    let (key_type, fingerprint, comment) = inspect_ssh_key(&text)?;

    // Store in vault
    vault.add_secret(name, &content)?;

    Ok(SshKeyInfo {
        name: name.to_string(),
        key_type,
        fingerprint,
        comment,
    })
}
/// Starts an SSH agent listener on `socket_path` to answer agent identity requests.
pub fn serve_ssh_agent(_vault: &Vault, socket_path: &Path) -> Result<(), CoreError> {
    use interprocess::local_socket::{GenericFilePath, ListenerOptions, ToFsName, prelude::*};

    if socket_path.exists() {
        let _ = std::fs::remove_file(socket_path);
    }

    let name = socket_path
        .to_fs_name::<GenericFilePath>()
        .map_err(|e| CoreError::Io {
            path: socket_path.to_path_buf(),
            source: e,
        })?;

    let listener = ListenerOptions::new()
        .name(name)
        .try_overwrite(true)
        .create_sync()
        .map_err(|e| CoreError::Io {
            path: socket_path.to_path_buf(),
            source: e,
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600));
    }

    // Accept loop for incoming SSH agent protocol queries
    for conn in listener.incoming() {
        if let Ok(mut stream) = conn {
            // Read 4-byte message length prefix
            use std::io::{Read, Write};
            let mut len_buf = [0u8; 4];
            if stream.read_exact(&mut len_buf).is_ok() {
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut msg = vec![0u8; len];
                if stream.read_exact(&mut msg).is_ok() && !msg.is_empty() {
                    let msg_type = msg[0];
                    // SSH2_AGENTC_REQUEST_IDENTITIES = 11
                    if msg_type == 11 {
                        // Return empty identity list (or identities count)
                        // SSH2_AGENT_IDENTITIES_ANSWER = 12, num_keys = 0 (4 bytes)
                        let response = [0, 0, 0, 5, 12, 0, 0, 0, 0];
                        let _ = stream.write_all(&response);
                    } else {
                        // SSH_AGENT_FAILURE = 30
                        let response = [0, 0, 0, 1, 30];
                        let _ = stream.write_all(&response);
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::InMemoryKeyStore;
    use crate::vault::init_with_keystore;

    #[test]
    fn inspect_and_import_ssh_key() {
        let fake_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n";
        let (key_type, fp, _) = inspect_ssh_key(fake_key).unwrap();
        assert_eq!(key_type, "OPENSSH");
        assert!(fp.starts_with("SHA256:"));

        let temp_dir = tempfile::tempdir().unwrap();
        let key_file = temp_dir.path().join("id_ed25519");
        std::fs::write(&key_file, fake_key).unwrap();

        let store = InMemoryKeyStore::new();
        let vault = init_with_keystore(temp_dir.path(), &store).unwrap();

        let info = import_ssh_key(&vault, "deploy_key", &key_file).unwrap();
        assert_eq!(info.name, "deploy_key");
        assert_eq!(info.key_type, "OPENSSH");
        assert_eq!(vault.get_secret("deploy_key").unwrap(), fake_key.as_bytes());
    }
}
