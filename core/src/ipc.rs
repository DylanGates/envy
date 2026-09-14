use std::path::Path;

use interprocess::local_socket::{GenericFilePath, ListenerOptions, prelude::*};

use crate::error::CoreError;

/// Binds the local IPC socket for `envy mcp serve` at
/// `<project_root>/.envy/mcp.sock`. Requires the vault to already be
/// initialized (an MCP server has nothing to serve against otherwise).
///
/// This is transport only: no message framing/protocol is defined here.
/// Callers get a raw [`interprocess::local_socket::Listener`] and drive
/// `.accept()`/`.incoming()` themselves.
pub fn bind(project_root: &Path) -> Result<interprocess::local_socket::Listener, CoreError> {
    let envy_dir = project_root.join(".envy");
    if !envy_dir.exists() {
        return Err(CoreError::VaultNotFound(envy_dir));
    }

    let socket_path = envy_dir.join("mcp.sock");
    let name = socket_path
        .clone()
        .to_fs_name::<GenericFilePath>()
        .map_err(|source| CoreError::Io {
            path: socket_path.clone(),
            source,
        })?;

    let listener = ListenerOptions::new()
        .name(name)
        .try_overwrite(true)
        .create_sync()
        .map_err(|source| CoreError::Io {
            path: socket_path.clone(),
            source,
        })?;

    restrict_socket_permissions(&socket_path)?;

    Ok(listener)
}

#[cfg(unix)]
fn restrict_socket_permissions(socket_path: &Path) -> Result<(), CoreError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600)).map_err(
        |source| CoreError::Io {
            path: socket_path.to_path_buf(),
            source,
        },
    )
}

#[cfg(not(unix))]
fn restrict_socket_permissions(_socket_path: &Path) -> Result<(), CoreError> {
    // Windows named pipes use an ACL model, not chmod; not implemented
    // yet, tracked as a known gap (see vault.rs's enforce_permissions).
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use interprocess::local_socket::Stream;
    use std::thread;

    #[test]
    fn bind_fails_if_vault_not_initialized() {
        let dir = tempfile::tempdir().unwrap();
        let result = bind(dir.path());
        assert!(matches!(result, Err(CoreError::VaultNotFound(_))));
    }

    #[test]
    fn bind_then_accept_a_connection() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".envy")).unwrap();
        let listener = bind(dir.path()).unwrap();

        let socket_path = dir.path().join(".envy").join("mcp.sock");
        let client = thread::spawn(move || {
            let name = socket_path.to_fs_name::<GenericFilePath>().unwrap();
            Stream::connect(name).unwrap();
        });

        let conn = listener.accept();
        assert!(conn.is_ok());
        client.join().unwrap();
    }
}
