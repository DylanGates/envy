use anyhow::Context;
use envy_core::audit::AuditEvent;
use envy_core::ssh::{SshHostProfile, import_ssh_key};
use std::path::PathBuf;

use crate::cli::{GlobalArgs, SshAction};

pub fn run(action: SshAction, global: &GlobalArgs) -> anyhow::Result<()> {
    match action {
        SshAction::Import { path, name } => import(path, name, global),
        SshAction::Generate {
            name,
            algorithm,
            comment,
        } => generate(name, algorithm, comment, global),
        SshAction::Export { name, out } => export_public(name, out, global),
        SshAction::Keys => keys(global),
        SshAction::Add {
            name,
            host,
            port,
            user,
            identity,
        } => add_host(name, host, port, user, identity, global),
        SshAction::List => list_hosts(global),
        SshAction::Connect { name } => connect(name, global),
        SshAction::Exec { name, command } => exec(name, command, global),
        SshAction::Tunnel {
            name,
            local_port,
            remote_host,
            remote_port,
        } => tunnel(name, local_port, remote_host, remote_port, global),
        SshAction::Agent { socket } => agent(socket, global),
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

fn generate(
    name: String,
    algorithm: String,
    comment: Option<String>,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;

    let (info, public_key) = envy_core::ssh::generate_ssh_key(
        &vault,
        &name,
        &algorithm,
        comment.as_deref(),
    )?;

    vault.log_event(&AuditEvent {
        subject: Some("cli"),
        project: Some(&cwd.to_string_lossy()),
        provider: Some("ssh"),
        operation: "ssh_generate_key",
        endpoint_host: None,
        outcome: "success",
        redaction_summary: Some(&format!("generated SSH key '{}' ({})", name, info.key_type)),
    })?;

    if global.json {
        println!(
            "{}",
            serde_json::json!({
                "name": info.name,
                "key_type": info.key_type,
                "fingerprint": info.fingerprint,
                "public_key": public_key,
            })
        );
    } else if !global.quiet {
        println!("Generated new SSH keypair for identity '{}':", info.name);
        println!("  Type:        {}", info.key_type);
        println!("  Fingerprint: {}", info.fingerprint);
        println!("  Public Key:  {}", public_key);
    }
    Ok(())
}

fn export_public(
    name: String,
    out: Option<PathBuf>,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;

    let public_key = envy_core::ssh::export_ssh_public_key(&vault, &name)?;

    if let Some(path) = out {
        std::fs::write(&path, format!("{public_key}\n"))?;
        if !global.quiet {
            println!("Exported public key for '{name}' to {}", path.display());
        }
    } else if global.json {
        println!(
            "{}",
            serde_json::json!({
                "name": name,
                "public_key": public_key
            })
        );
    } else {
        println!("{public_key}");
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

    let is_agent = std::env::var("ENVY_AGENT_ID").is_ok();
    if global.json {
        if is_agent {
            let redacted_profile = serde_json::json!({
                "name": profile.name,
                "host": "[REDACTED]",
                "port": profile.port,
                "user": "[REDACTED]",
                "identity": profile.identity,
                "known_host_required": profile.known_host_required
            });
            println!("{}", serde_json::to_string(&redacted_profile)?);
        } else {
            println!("{}", serde_json::to_string(&profile)?);
        }
    } else if !global.quiet {
        if is_agent {
            println!(
                "Added host profile '{}' ([REDACTED]@[REDACTED]:{})",
                profile.name, profile.port
            );
        } else {
            println!(
                "Added host profile '{}' ({}@{}:{})",
                profile.name, profile.user, profile.host, profile.port
            );
        }
    }
    Ok(())
}

fn connect(name: String, global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    let profile = vault.get_ssh_host(&name)?;

    let private_key = vault
        .get_secret(&profile.identity)
        .with_context(|| format!("identity '{}' not found in vault", profile.identity))?;

    let temp_key_file = tempfile::Builder::new()
        .prefix("envy_ssh_key_")
        .tempfile()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = temp_key_file.as_file().metadata()?.permissions();
        perms.set_mode(0o600);
        temp_key_file.as_file().set_permissions(perms)?;
    }

    std::fs::write(temp_key_file.path(), &private_key)?;

    vault.log_event(&AuditEvent {
        subject: Some("cli"),
        project: Some(&cwd.to_string_lossy()),
        provider: Some("ssh"),
        operation: "ssh_connect",
        endpoint_host: Some(&profile.host),
        outcome: "success",
        redaction_summary: Some(&format!("interactive SSH connection to '{}'", name)),
    })?;

    if !global.quiet && !global.json {
        println!(
            "Connecting to {} ({}@{}:{})...",
            profile.name, profile.user, profile.host, profile.port
        );
    }

    let status = std::process::Command::new("ssh")
        .arg("-i")
        .arg(temp_key_file.path())
        .arg("-p")
        .arg(profile.port.to_string())
        .arg(format!("{}@{}", profile.user, profile.host))
        .status()
        .with_context(|| "failed to execute ssh command")?;

    if !status.success() {
        anyhow::bail!("ssh exited with status {}", status);
    }
    Ok(())
}

fn exec(name: String, command: Vec<String>, global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let cmd_str = command.join(" ");

    // Evaluate policy on the command before loading keys or profile
    let policy = envy_core::policy::load_policy(&cwd)?;
    let agent_id = std::env::var("ENVY_AGENT_ID").ok();
    let policy_req = envy_core::policy::PolicyRequest {
        operation: "ssh_exec",
        provider: Some(&name),
        domain: Some(&name),
        agent_identity: agent_id.as_deref(),
        method: "EXEC",
        command: Some(&cmd_str),
        has_active_consent: false,
    };
    match envy_core::policy::evaluate_with_policy(&policy_req, &policy) {
        envy_core::policy::PolicyDecision::Allow => {}
        envy_core::policy::PolicyDecision::RequireConsent { reason } => {
            anyhow::bail!("policy requires human consent: {reason}");
        }
        envy_core::policy::PolicyDecision::Deny { reason } => {
            anyhow::bail!("policy denied command execution: {reason}");
        }
    }

    let vault = envy_core::vault::open(&cwd)?;
    let profile = vault.get_ssh_host(&name)?;

    let private_key = vault
        .get_secret(&profile.identity)
        .with_context(|| format!("identity '{}' not found in vault", profile.identity))?;

    let temp_dir = tempfile::tempdir()?;
    let key_path = temp_dir.path().join("id_ed25519");
    std::fs::write(&key_path, &private_key)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&key_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&key_path, perms)?;
    }

    vault.log_event(&AuditEvent {
        subject: Some("cli"),
        project: Some(&cwd.to_string_lossy()),
        provider: Some("ssh"),
        operation: "ssh_exec",
        endpoint_host: Some(&profile.host),
        outcome: "success",
        redaction_summary: Some(&format!("ran command on '{}': {}", name, cmd_str)),
    })?;

    let output = std::process::Command::new("ssh")
        .arg("-i")
        .arg(&key_path)
        .arg("-p")
        .arg(profile.port.to_string())
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg(format!("{}@{}", profile.user, profile.host))
        .args(&command)
        .output()
        .with_context(|| "failed to execute remote command via ssh")?;
    if global.json {
        println!(
            "{}",
            serde_json::json!({
                "status": if output.status.success() { "ok" } else { "error" },
                "exit_code": output.status.code(),
                "stdout": String::from_utf8_lossy(&output.stdout),
                "stderr": String::from_utf8_lossy(&output.stderr),
            })
        );
    } else {
        std::io::Write::write_all(&mut std::io::stdout(), &output.stdout)?;
        std::io::Write::write_all(&mut std::io::stderr(), &output.stderr)?;
    }

    if !output.status.success() {
        anyhow::bail!(
            "remote command failed with exit code {:?}",
            output.status.code()
        );
    }
    Ok(())
}
fn list_hosts(global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    let hosts = vault.list_ssh_hosts()?;

    let is_agent = std::env::var("ENVY_AGENT_ID").is_ok();
    if global.json {
        if is_agent {
            let redacted_hosts: Vec<serde_json::Value> = hosts
                .iter()
                .map(|h| {
                    serde_json::json!({
                        "name": h.name,
                        "host": "[REDACTED]",
                        "port": h.port,
                        "user": "[REDACTED]",
                        "identity": h.identity,
                        "known_host_required": h.known_host_required
                    })
                })
                .collect();
            println!("{}", serde_json::to_string(&redacted_hosts)?);
        } else {
            println!("{}", serde_json::to_string(&hosts)?);
        }
    } else if !global.quiet {
        if hosts.is_empty() {
            println!("No SSH host profiles configured.");
        } else {
            for h in &hosts {
                if is_agent {
                    println!(
                        "{:<18}  [REDACTED]@[REDACTED]:{}  identity={}",
                        h.name, h.port, h.identity
                    );
                } else {
                    println!(
                        "{:<18}  {}@{}:{}  identity={}",
                        h.name, h.user, h.host, h.port, h.identity
                    );
                }
            }
        }
    }
    Ok(())
}
fn tunnel(
    name: String,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    let profile = vault.get_ssh_host(&name)?;

    let private_key = vault
        .get_secret(&profile.identity)
        .with_context(|| format!("identity '{}' not found in vault", profile.identity))?;

    let temp_dir = tempfile::tempdir()?;
    let key_path = temp_dir.path().join("id_ed25519");
    std::fs::write(&key_path, &private_key)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&key_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&key_path, perms)?;
    }

    let forward_arg = format!("{local_port}:{remote_host}:{remote_port}");

    vault.log_event(&AuditEvent {
        subject: Some("cli"),
        project: Some(&cwd.to_string_lossy()),
        provider: Some("ssh"),
        operation: "ssh_tunnel",
        endpoint_host: Some(&profile.host),
        outcome: "success",
        redaction_summary: Some(&format!(
            "opened tunnel on '{}' (127.0.0.1:{} -> {}:{})",
            name, local_port, remote_host, remote_port
        )),
    })?;

    if !global.quiet && !global.json {
        println!(
            "Forwarding 127.0.0.1:{} -> {}:{} through {} ({}@{}:{})...",
            local_port,
            remote_host,
            remote_port,
            profile.name,
            profile.user,
            profile.host,
            profile.port
        );
        println!("Press Ctrl+C to close the tunnel.");
    }

    let status = std::process::Command::new("ssh")
        .arg("-i")
        .arg(&key_path)
        .arg("-p")
        .arg(profile.port.to_string())
        .arg("-N") // Do not execute a remote command (port forwarding only)
        .arg("-L")
        .arg(&forward_arg)
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg(format!("{}@{}", profile.user, profile.host))
        .status()
        .with_context(|| "failed to establish SSH tunnel")?;

    if !status.success() {
        anyhow::bail!("SSH tunnel exited with status {}", status);
    }
    Ok(())
}

fn agent(socket_opt: Option<PathBuf>, global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;

    let socket_path = match socket_opt {
        Some(s) => s,
        None => {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .map(PathBuf::from)
                .unwrap_or_else(|_| cwd.clone());
            let dot_envy = home.join(".envy");
            let _ = std::fs::create_dir_all(&dot_envy);
            dot_envy.join("ssh-agent.sock")
        }
    };

    if !global.quiet && !global.json {
        println!("Starting envy SSH agent on {}", socket_path.display());
        println!(
            "Export SSH_AUTH_SOCK=\"{}\" to use it with ssh/git.",
            socket_path.display()
        );
    }

    envy_core::ssh::serve_ssh_agent(&vault, &socket_path)?;
    Ok(())
}
