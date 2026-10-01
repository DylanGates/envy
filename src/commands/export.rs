use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use envy_core::audit::AuditEvent;

use crate::cli::GlobalArgs;

pub fn run(
    encrypted: Option<PathBuf>,
    env: Option<PathBuf>,
    example: Option<PathBuf>,
    force: bool,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    match (encrypted, env, example) {
        (Some(path), None, None) => export_encrypted(&path, force, global),
        (None, Some(path), None) => export_env(&path, force, global),
        (None, None, Some(path)) => export_example(&path, force, global),
        (None, None, None) => bail!(
            "pass --encrypted FILE for an encrypted whole-vault backup, --env [FILE] for a \
             plaintext .env export (defaults to \".env\"), or --example [FILE] for a \
             names-only .env.example (defaults to \".env.example\")"
        ),
        _ => bail!("pass exactly one of --encrypted, --env, or --example"),
    }
}

/// Backs up an existing destination file to `<file>.bak` if `--force` was
/// passed, or fails if the file exists and `--force` wasn't passed.
/// Shared by every export mode that writes a plain file.
fn backup_if_exists(path: &Path, force: bool) -> anyhow::Result<()> {
    if path.exists() {
        if !force {
            bail!(
                "{} already exists — pass --force to overwrite (a .bak copy is made first)",
                path.display()
            );
        }
        let backup = PathBuf::from(format!("{}.bak", path.display()));
        std::fs::copy(path, &backup)
            .with_context(|| format!("failed to back up {} to {}", path.display(), backup.display()))?;
    }
    Ok(())
}
fn export_encrypted(path: &Path, force: bool, global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    let secrets = vault.list_secrets()?;

    if secrets.is_empty() {
        if !global.quiet {
            println!("Vault is empty — nothing to export.");
        }
        return Ok(());
    }

    backup_if_exists(path, force)?;

    let password = if global.non_interactive {
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .context("failed to read backup password from stdin")?;
        let trimmed = buf.trim_end_matches(&['\r', '\n'][..]).to_string();
        if trimmed.is_empty() {
            bail!("backup password cannot be empty");
        }
        trimmed
    } else {
        let p1 = rpassword::prompt_password("Enter encryption password for backup: ")
            .context("failed to read password")?;
        if p1.is_empty() {
            bail!("backup password cannot be empty");
        }
        let p2 = rpassword::prompt_password("Confirm encryption password: ")
            .context("failed to read confirmation password")?;
        if p1 != p2 {
            bail!("passwords do not match");
        }
        p1
    };

    let encrypted_payload = envy_core::backup::export_encrypted(&vault, password.as_bytes())
        .context("failed to generate encrypted backup")?;

    std::fs::write(path, &encrypted_payload)
        .with_context(|| format!("failed to write {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    let count = secrets.len();
    vault.log_event(&AuditEvent {
        subject: Some("cli"),
        project: Some(&cwd.to_string_lossy()),
        provider: None,
        operation: "export_encrypted",
        endpoint_host: None,
        outcome: "success",
        redaction_summary: Some(&format!(
            "exported {count} encrypted secret(s) to {}",
            path.display()
        )),
    })?;

    if global.json {
        println!(r#"{{"status":"ok","exported":{count},"path":"{}"}}"#, path.display());
    } else if !global.quiet {
        println!(
            "Exported {count} encrypted secret(s) to {}",
            path.display()
        );
    }
    Ok(())
}

fn export_env(path: &Path, force: bool, global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    let secrets = vault.list_secrets()?;

    if secrets.is_empty() {
        if !global.quiet {
            println!("No secrets in vault — nothing to export.");
        }
        return Ok(());
    }

    backup_if_exists(path, force)?;

    if !global.non_interactive {
        eprintln!(
            "About to write {} secret(s) in PLAINTEXT to {}:",
            secrets.len(),
            path.display()
        );
        for secret in &secrets {
            eprintln!("  - {}", secret.name);
        }
        eprint!("Continue? [y/N] ");
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            bail!("export cancelled");
        }
    }

    let mut out = String::new();
    let mut exported = 0usize;
    for secret in &secrets {
        match vault.get_secret(&secret.name) {
            Ok(raw) => match String::from_utf8(raw) {
                Ok(value) => {
                    out.push_str(&envy_core::dotenv::format_line(&secret.name, &value));
                    out.push('\n');
                    exported += 1;
                }
                Err(_) => {
                    if !global.quiet {
                        eprintln!("envy export: skipping '{}': not valid UTF-8", secret.name);
                    }
                }
            },
            Err(e) => {
                if !global.quiet {
                    eprintln!("envy export: skipping '{}': {e}", secret.name);
                }
            }
        }
    }

    std::fs::write(path, &out).with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }

    vault.log_event(&AuditEvent {
        subject: Some("cli"),
        project: Some(&cwd.to_string_lossy()),
        provider: None,
        operation: "export",
        endpoint_host: None,
        outcome: "success",
        redaction_summary: Some(&format!(
            "wrote {exported} secret(s) in plaintext to {}",
            path.display()
        )),
    })?;

    if global.json {
        println!(
            r#"{{"status":"ok","file":"{}","count":{exported}}}"#,
            path.display()
        );
    } else if !global.quiet {
        println!("Exported {exported} secret(s) to {}", path.display());
    }
    Ok(())
}

/// Writes a names-only `.env.example`: every vault secret's name, no
/// values. Never calls `vault.get_secret` — nothing sensitive is ever
/// read, so (unlike `export_env`) no confirmation prompt is needed, and
/// the file is left at default permissions since it's meant to be safe to
/// commit/share, unlike a real `.env`.
fn export_example(path: &Path, force: bool, global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    let secrets = vault.list_secrets()?;

    if secrets.is_empty() {
        if !global.quiet {
            println!("No secrets in vault — nothing to write to an example file.");
        }
        return Ok(());
    }

    backup_if_exists(path, force)?;

    let mut out = String::from("# generated by envy export --example — names only, no values\n");
    for secret in &secrets {
        out.push_str(&secret.name);
        out.push_str("=\n");
    }

    std::fs::write(path, &out).with_context(|| format!("failed to write {}", path.display()))?;

    vault.log_event(&AuditEvent {
        subject: Some("cli"),
        project: Some(&cwd.to_string_lossy()),
        provider: None,
        operation: "export_example",
        endpoint_host: None,
        outcome: "success",
        redaction_summary: Some(&format!(
            "wrote {} variable name(s) (no values) to {}",
            secrets.len(),
            path.display()
        )),
    })?;

    if global.json {
        println!(
            r#"{{"status":"ok","file":"{}","count":{}}}"#,
            path.display(),
            secrets.len()
        );
    } else if !global.quiet {
        println!("Wrote {} variable name(s) to {}", secrets.len(), path.display());
    }
    Ok(())
}
