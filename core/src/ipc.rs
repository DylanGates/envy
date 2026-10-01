use std::path::Path;

use interprocess::local_socket::{ListenerOptions, Name};

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
    let name = socket_name(project_root, &socket_path)?;

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
pub fn socket_name<'a>(_project_root: &Path, socket_path: &'a Path) -> Result<Name<'a>, CoreError> {
    #[cfg(windows)]
    {
        use interprocess::local_socket::{GenericNamespaced, ToNsName};
        // Windows named pipes require a namespaced identifier (e.g. @/pipe/...)
        let proj_name = _project_root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("default");
        let pipe_name = format!("envy-mcp-{proj_name}");
        pipe_name
            .to_ns_name::<GenericNamespaced>()
            .map_err(|source| CoreError::Io {
                path: socket_path.to_path_buf(),
                source,
            })
    }
    #[cfg(not(windows))]
    {
        use interprocess::local_socket::{GenericFilePath, ToFsName};
        socket_path
            .to_fs_name::<GenericFilePath>()
            .map_err(|source| CoreError::Io {
                path: socket_path.to_path_buf(),
                source,
            })
    }
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
    use interprocess::local_socket::prelude::*;
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

        let proj_dir = dir.path().to_path_buf();
        let client = thread::spawn(move || {
            let socket_path = proj_dir.join(".envy").join("mcp.sock");
            let name = socket_name(&proj_dir, &socket_path).unwrap();
            Stream::connect(name).unwrap();
        });

        let conn = listener.accept();
        assert!(conn.is_ok());
        client.join().unwrap();
    }
}
