use anyhow::Context;
use envy_core::audit::AuditEvent;
use envy_core::ssh::{SshHostProfile, import_ssh_key};
use std::path::PathBuf;

use crate::cli::{GlobalArgs, SshAction};

pub fn run(action: SshAction, global: &GlobalArgs) -> anyhow::Result<()> {
    match action {
        SshAction::Import { path, name } => import(path, name, global),
        SshAction::Keys => keys(global),
        SshAction::Add {
            name,
            host,
            port,
            user,
            identity,
        } => add_host(name, host, port, user, identity, global),
        SshAction::List => list_hosts(global),
    }
}

fn import(path: PathBuf, name_opt: Option<String>, global: &GlobalArgs) -> anyhow::Result<()> {
    let name = match name_opt {
        Some(n) => n,
        None => path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("id_ssh")
            .to_string(),
    };

    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;

    let info = import_ssh_key(&vault, &name, &path)
        .with_context(|| format!("failed to import SSH key from {}", path.display()))?;

    vault.log_event(&AuditEvent {
        subject: Some("cli"),
        project: Some(&cwd.to_string_lossy()),
        provider: Some("ssh"),
        operation: "ssh_import_key",
        endpoint_host: None,
        outcome: "success",
        redaction_summary: Some(&format!("imported SSH key '{}' ({})", name, info.key_type)),
    })?;

    if global.json {
        println!("{}", serde_json::to_string(&info)?);
    } else if !global.quiet {
        println!(
            "Imported SSH key '{}' ({}) with fingerprint {}",
            info.name, info.key_type, info.fingerprint
        );
    }
    Ok(())
}

fn keys(global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    let secrets = vault.list_secrets()?;

    // List secrets and filter/inspect for SSH keys
    let mut key_list = Vec::new();
    for meta in &secrets {
        if let Ok(raw) = vault.get_secret(&meta.name) {
            let text = String::from_utf8_lossy(&raw);
            if let Ok((key_type, fingerprint, comment)) = envy_core::ssh::inspect_ssh_key(&text) {
                if key_type == "UNKNOWN" {
                    continue;
                }
                key_list.push(envy_core::ssh::SshKeyInfo {
                    name: meta.name.clone(),
                    key_type,
                    fingerprint,
                    comment,
                });
            }
        }
    }

    if global.json {
        println!("{}", serde_json::to_string(&key_list)?);
    } else if !global.quiet {
        if key_list.is_empty() {
            println!("No SSH keys found in vault.");
        } else {
            for k in &key_list {
                println!("{:<20}  {:<12}  {}", k.name, k.key_type, k.fingerprint);
            }
        }
    }
    Ok(())
}

fn add_host(
    name: String,
    host: String,
    port: u16,
    user: String,
    identity: String,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;

    let profile = SshHostProfile {
        name: name.clone(),
        host,
        port,
        user,
        identity,
        known_host_required: true,
    };

    vault.add_ssh_host(&profile)?;

    vault.log_event(&AuditEvent {
        subject: Some("cli"),
        project: Some(&cwd.to_string_lossy()),
        provider: Some("ssh"),
        operation: "ssh_add_host",
        endpoint_host: Some(&profile.host),
        outcome: "success",
        redaction_summary: Some(&format!("configured host profile '{}'", name)),
    })?;

    if global.json {
        println!("{}", serde_json::to_string(&profile)?);
    } else if !global.quiet {
        println!(
            "Added host profile '{}' ({}@{}:{})",
            profile.name, profile.user, profile.host, profile.port
        );
    }
    Ok(())
}

fn list_hosts(global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    let hosts = vault.list_ssh_hosts()?;

    if global.json {
        println!("{}", serde_json::to_string(&hosts)?);
    } else if !global.quiet {
        if hosts.is_empty() {
            println!("No SSH host profiles configured.");
        } else {
            for h in &hosts {
                println!(
                    "{:<18}  {}@{}:{}  identity={}",
                    h.name, h.user, h.host, h.port, h.identity
                );
            }
        }
    }
    Ok(())
}
