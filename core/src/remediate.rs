//! Reversible source file remediation engine (FR-08).
//!
//! Replaces plaintext secrets in source and configuration files with `envy://<name>`
//! reference handles, creating atomic backup copies (`<file>.bak`) before touching disk.

use crate::error::CoreError;
use std::path::{Path, PathBuf};

/// Remediates a single file by replacing `target_value` associated with `var_name`
/// with `envy://<var_name>`.
///
/// Always writes `<file>.bak` containing the original file contents before mutation.
pub fn remediate_file(
    path: &Path,
    var_name: &str,
    target_value: &str,
) -> Result<PathBuf, CoreError> {
    let content = std::fs::read_to_string(path).map_err(|e| CoreError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    if !content.contains(target_value) {
        return Err(CoreError::InvalidRequest(format!(
            "target value for '{}' not found in {}",
            var_name,
            path.display()
        )));
    }

    let backup_path = PathBuf::from(format!("{}.bak", path.display()));
    std::fs::write(&backup_path, &content).map_err(|e| CoreError::Io {
        path: backup_path.clone(),
        source: e,
    })?;

    let reference = format!("envy://{}", var_name);
    let updated = content.replace(target_value, &reference);

    std::fs::write(path, updated).map_err(|e| CoreError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(backup_path)
}

/// Restores a previously created backup `<file>.bak` over `<file>`.
pub fn restore_backup(path: &Path) -> Result<(), CoreError> {
    let backup_path = PathBuf::from(format!("{}.bak", path.display()));
    if !backup_path.exists() {
        return Err(CoreError::InvalidRequest(format!(
            "no backup found at {}",
            backup_path.display()
        )));
    }

    std::fs::copy(&backup_path, path).map_err(|e| CoreError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    let _ = std::fs::remove_file(&backup_path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remediate_and_restore_round_trip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join(".env");
        let initial_content = "STRIPE_KEY=sk_live_1234567890abcdef\nPORT=3000\n";
        std::fs::write(&file_path, initial_content).unwrap();

        let backup = remediate_file(&file_path, "STRIPE_KEY", "sk_live_1234567890abcdef").unwrap();
        assert!(backup.exists());

        let remediated = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(remediated, "STRIPE_KEY=envy://STRIPE_KEY\nPORT=3000\n");

        restore_backup(&file_path).unwrap();
        let restored = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(restored, initial_content);
        assert!(!backup.exists());
    }
}
