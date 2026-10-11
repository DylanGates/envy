use std::io::Write;

use anyhow::{Context, bail};
use envy_core::audit::AuditEvent;

use crate::cli::GlobalArgs;

pub fn run(
    name: Option<String>,
    from_env: bool,
    rotate_after_days: Option<i64>,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    // If interactive without arguments, prompt for kind: Secret vs Server
    if name.is_none() && !from_env && !global.non_interactive {
        return prompt_interactive_wizard(rotate_after_days, global);
    }

    let name = match name {
        Some(name) => name,
        None if !global.non_interactive => prompt_line("Name: ")?,
        None => bail!("NAME is required in --non-interactive mode"),
    };

    let value = if from_env {
        std::env::var(&name)
            .with_context(|| format!("environment variable '{name}' is not set or empty"))?
    } else if global.non_interactive {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("failed to read secret value from stdin")?;
        line.trim_end_matches(['\r', '\n']).to_string()
    } else {
        rpassword::prompt_password(format!("Value for {name}: "))
            .context("failed to read secret value")?
    };
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    vault.add_secret_with_rotation(&name, value.as_bytes(), rotate_after_days)?;

    vault.log_event(&AuditEvent {
        subject: Some("cli"),
        project: Some(&cwd.to_string_lossy()),
        provider: None,
        operation: "add",
        endpoint_host: None,
        outcome: "success",
        redaction_summary: Some(&format!("stored secret '{name}'")),
    })?;

    if global.json {
        println!(r#"{{"status":"ok","reference":"envy://{name}"}}"#);
    } else if !global.quiet {
        println!("Added secret '{name}' to vault (envy://{name})");
    }
    Ok(())
}

fn prompt_line(prompt: &str) -> anyhow::Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("failed to read input")?;
    let res = line.trim().to_string();
    if res.is_empty() {
        bail!("input cannot be empty");
    }
    Ok(res)
}

fn prompt_interactive_wizard(
    rotate_after_days: Option<i64>,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    println!("envy add: Select what you want to add:");
    println!("  1) API Key / Secret Token");
    println!("  2) Server (SSH Host Profile)");
    println!("  3) Server from ~/.ssh/config");

    let choice = prompt_line("Choose [1-3]: ")?;
    match choice.as_str() {
        "1" => {
            let name = prompt_line("Secret name (e.g. STRIPE_KEY): ")?;
            let value = rpassword::prompt_password(format!("Value for {name}: "))
                .context("failed to read secret value")?;
            let cwd = std::env::current_dir()?;
            let vault = envy_core::vault::open(&cwd)?;
            vault.add_secret_with_rotation(&name, value.as_bytes(), rotate_after_days)?;

            vault.log_event(&AuditEvent {
                subject: Some("cli"),
                project: Some(&cwd.to_string_lossy()),
                provider: None,
                operation: "add",
                endpoint_host: None,
                outcome: "success",
                redaction_summary: Some(&format!("stored secret '{name}'")),
            })?;
            if global.json {
                println!(r#"{{"status":"ok","reference":"envy://{name}"}}"#);
            } else {
                println!("Added secret '{name}' to vault (envy://{name})");
            }
            Ok(())
        }
        "2" => {
            let name = prompt_line("Server profile name (e.g. production): ")?;
            let host = prompt_line("Server hostname / IP: ")?;
            let user = prompt_line("SSH username (e.g. ubuntu, root): ")?;
            let port_str = prompt_line("SSH port [22]: ").unwrap_or_else(|_| "22".to_string());
            let port: u16 = port_str.parse().unwrap_or(22);
            let identity =
                prompt_line("SSH Key Identity (stored secret name or private key path): ")?;

            let cwd = std::env::current_dir()?;
            let vault = envy_core::vault::open(&cwd)?;

            // If identity is a path on disk, import it as an SSH key
            let resolved_identity = if std::path::Path::new(&identity).exists() {
                let key_name = format!("{name}_key");
                let info = envy_core::ssh::import_ssh_key(
                    &vault,
                    &key_name,
                    std::path::Path::new(&identity),
                )?;
                println!(
                    "Imported SSH key from '{identity}' as identity '{key_name}' ({})",
                    info.key_type
                );
                key_name
            } else {
                identity
            };

            let profile = envy_core::ssh::SshHostProfile {
                name: name.clone(),
                host,
                port,
                user,
                identity: resolved_identity,
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
            println!(
                "Added host profile '{}' ({}@{}:{})",
                profile.name, profile.user, profile.host, profile.port
            );
            Ok(())
        }
        "3" => {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("."));
            let ssh_config_path = home.join(".ssh").join("config");

            if !ssh_config_path.exists() {
                bail!("SSH config file not found at {}", ssh_config_path.display());
            }

            let content = std::fs::read_to_string(&ssh_config_path)?;
            let entries = envy_core::ssh::parse_ssh_config(&content);
            if entries.is_empty() {
                bail!(
                    "No valid Host entries found in {}",
                    ssh_config_path.display()
                );
            }

            println!(
                "\nFound {} host(s) in {}:",
                entries.len(),
                ssh_config_path.display()
            );
            for (i, entry) in entries.iter().enumerate() {
                let target = entry.hostname.as_deref().unwrap_or(&entry.host_alias);
                let user = entry.user.as_deref().unwrap_or("user");
                println!("  {}) {} -> {}@{}", i + 1, entry.host_alias, user, target);
            }

            let sel = prompt_line(&format!("Select host [1-{}]: ", entries.len()))?;
            let idx: usize = sel.parse().context("invalid selection")?;
            if idx == 0 || idx > entries.len() {
                bail!("selection out of range");
            }
            let chosen = &entries[idx - 1];

            let name = chosen.host_alias.clone();
            let host = chosen
                .hostname
                .clone()
                .unwrap_or_else(|| chosen.host_alias.clone());
            let user = chosen.user.clone().unwrap_or_else(|| "root".to_string());
            let port = chosen.port.unwrap_or(22);

            let cwd = std::env::current_dir()?;
            let vault = envy_core::vault::open(&cwd)?;

            let identity_name = if let Some(id_path) = &chosen.identity_file {
                let expanded = if let Some(stripped) = id_path.strip_prefix("~/") {
                    home.join(stripped)
                } else {
                    std::path::PathBuf::from(id_path)
                };
                if expanded.exists() {
                    let key_name = format!("{name}_key");
                    let info = envy_core::ssh::import_ssh_key(&vault, &key_name, &expanded)?;
                    println!(
                        "Imported SSH identity from '{}' as '{}' ({})",
                        expanded.display(),
                        key_name,
                        info.key_type
                    );
                    key_name
                } else {
                    format!("{name}_key")
                }
            } else {
                format!("{name}_key")
            };

            let profile = envy_core::ssh::SshHostProfile {
                name: name.clone(),
                host,
                port,
                user,
                identity: identity_name,
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
                redaction_summary: Some(&format!(
                    "imported host profile '{}' from ssh config",
                    name
                )),
            })?;
            println!(
                "Added host profile '{}' ({}@{}:{}) from ssh config",
                profile.name, profile.user, profile.host, profile.port
            );
            Ok(())
        }
        _ => bail!("invalid choice '{choice}'"),
    }
}
