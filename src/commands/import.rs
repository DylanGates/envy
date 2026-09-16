use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use envy_core::audit::AuditEvent;

use crate::cli::GlobalArgs;

pub fn run(encrypted: Option<PathBuf>, env: Option<PathBuf>, global: &GlobalArgs) -> anyhow::Result<()> {
    match (encrypted, env) {
        (Some(_), Some(_)) => bail!("pass either --encrypted or --env, not both"),
        (None, None) => bail!(
            "pass --encrypted FILE to restore an encrypted whole-vault backup, or --env [FILE] \
             to import a plaintext .env file (defaults to \".env\")"
        ),
        (Some(_path), None) => super::not_implemented("import --encrypted", global),
        (None, Some(path)) => import_env(&path, global),
    }
}

fn import_env(path: &Path, global: &GlobalArgs) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let entries = envy_core::dotenv::parse(&text);

    if entries.is_empty() {
        if !global.quiet {
            println!("No key=value pairs found in {}.", path.display());
        }
        return Ok(());
    }

    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;

    let mut imported = 0usize;
    let mut skipped = 0usize;
    for entry in &entries {
        match vault.add_secret(&entry.key, entry.value.as_bytes()) {
            Ok(()) => {
                imported += 1;
                vault.log_event(&AuditEvent {
                    subject: Some("cli"),
                    project: Some(&cwd.to_string_lossy()),
                    provider: None,
                    operation: "import",
                    endpoint_host: None,
                    outcome: "success",
                    redaction_summary: Some(&format!(
                        "imported '{}' from {}",
                        entry.key,
                        path.display()
                    )),
                })?;
            }
            Err(e) => {
                skipped += 1;
                if !global.quiet {
                    eprintln!("envy import: skipping '{}': {e}", entry.key);
                }
            }
        }
    }

    if global.json {
        println!(r#"{{"status":"ok","imported":{imported},"skipped":{skipped}}}"#);
    } else if !global.quiet {
        println!("Imported {imported} secret(s), skipped {skipped}.");
    }
    Ok(())
}
