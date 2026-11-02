//! `envy ssh …` — SSH identities, host profiles, pinned host keys and the
//! envy signing agent.
//!
//! Private keys never leave `envy-core`: `connect`/`exec`/`tunnel` start a
//! short-lived in-process agent ([`envy_core::ssh_agent::EphemeralAgent`])
//! and point `ssh` at its socket. Only a public key file and a pinned
//! `known_hosts` line are written to a `0700` temp dir.

use anyhow::Context;
use envy_core::audit::{AuditEvent, subject_for};
use envy_core::policy::{PolicyDecision, PolicyRequest};
use envy_core::ssh::{SshHostProfile, import_ssh_key};
use envy_core::vault::Vault;
use std::path::{Path, PathBuf};

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
        SshAction::Trust {
            name,
            yes,
            fingerprint,
        } => trust(name, yes, fingerprint, global),
        SshAction::Connect { name } => connect(name, global),
        SshAction::Exec { name, command } => exec(name, command, global),
        SshAction::Tunnel {
            name,
            local_port,
            remote_host,
            remote_port,
        } => tunnel(name, local_port, remote_host, remote_port, global),
        SshAction::Agent {
            socket,
            identity,
            print_env,
            global: use_global,
        } => agent(socket, identity, print_env, use_global, global),
    }
}

fn agent_id() -> Option<String> {
    std::env::var("ENVY_AGENT_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

fn current_subject() -> String {
    subject_for(agent_id().as_deref())
}

fn log(
    vault: &Vault,
    operation: &str,
    endpoint_host: Option<&str>,
    outcome: &str,
    summary: &str,
) -> anyhow::Result<()> {
    let subject = current_subject();
    let project = vault.project_root().to_string_lossy().to_string();
    vault.log_event(&AuditEvent {
        subject: Some(&subject),
        project: Some(&project),
        provider: Some("ssh"),
        operation,
        endpoint_host,
        outcome,
        redaction_summary: Some(summary),
    })?;
    Ok(())
}

/// Evaluates the project policy for an SSH operation; logs and bails on deny.
fn policy_gate(
    vault: &Vault,
    operation: &str,
    profile: &str,
    command: Option<&str>,
) -> anyhow::Result<()> {
    let policy = envy_core::policy::load_policy(vault.project_root())?;
    let agent = agent_id();
    let recent = match &agent {
        Some(id) => Some(vault.count_recent_events_for_subject(&subject_for(Some(id)))?),
        None => None,
    };
    let req = PolicyRequest {
        operation,
        provider: Some(profile),
        domain: Some(profile),
        agent_identity: agent.as_deref(),
        method: "EXEC",
        command,
        has_active_consent: false,
        recent_request_count: recent,
        payload_bytes: command.map(str::len),
    };
    let reason = match envy_core::policy::evaluate_with_policy(&req, &policy) {
        PolicyDecision::Allow => return Ok(()),
        PolicyDecision::Deny { reason } => reason,
        PolicyDecision::RequireConsent { reason } => {
            format!("{reason} (consent is not supported for SSH operations)")
        }
    };
    log(vault, operation, Some(profile), "denied", &reason)?;
    anyhow::bail!("policy denied {operation} on '{profile}': {reason}");
}

/// Refuses an unpinned profile that requires a pinned host key.
fn pin_gate(vault: &Vault, operation: &str, profile: &SshHostProfile) -> anyhow::Result<()> {
    if let Err(e) = envy_core::ssh::ensure_host_pinned(profile) {
        log(
            vault,
            operation,
            Some(&profile.name),
            "denied:host_not_pinned",
            "host key not pinned",
        )?;
        return Err(e.into());
    }
    Ok(())
}

#[cfg(unix)]
struct Session {
    vault: std::sync::Arc<std::sync::Mutex<Vault>>,
    agent: envy_core::ssh_agent::EphemeralAgent,
}

/// Opens the vault, checks pinning + policy, and starts the ephemeral agent.
#[cfg(unix)]
fn start_session(
    cwd: &Path,
    operation: &str,
    name: &str,
    command: Option<&str>,
) -> anyhow::Result<(SshHostProfile, Session)> {
    use envy_core::ssh_agent::{AgentConfig, EphemeralAgent, SshAgent};
    use std::sync::{Arc, Mutex};

    let vault = envy_core::vault::open(cwd)?;
    // Policy first: a denied command never even resolves the host profile.
    policy_gate(&vault, operation, name, command)?;
    let profile = vault.get_ssh_host(name)?;
    pin_gate(&vault, operation, &profile)?;

    let known_hosts = envy_core::ssh::known_hosts_line(&profile)?;
    let expected = match &profile.host_key {
        Some(k) => Some(envy_core::ssh::host_key_blob(k)?),
        None => None,
    };
    let project = vault.project_root().to_string_lossy().to_string();
    let vault = Arc::new(Mutex::new(vault));
    let agent = SshAgent::new(
        Arc::clone(&vault),
        std::slice::from_ref(&profile.identity),
        AgentConfig {
            subject: current_subject(),
            project,
            host_profile: Some(profile.name.clone()),
            expected_host_key_blob: expected,
        },
    )
    .with_context(|| format!("identity '{}' is not usable", profile.identity))?;
    let agent = EphemeralAgent::start(agent, known_hosts.as_deref())?;
    Ok((profile, Session { vault, agent }))
}

#[cfg(unix)]
impl Session {
    fn ssh(&self, profile: &SshHostProfile) -> std::process::Command {
        let mut cmd = std::process::Command::new("ssh");
        cmd.arg("-p")
            .arg(profile.port.to_string())
            .args(self.agent.ssh_options())
            .arg("-o")
            .arg("ConnectTimeout=10");
        cmd
    }

    fn log(&self, operation: &str, profile: &str, outcome: &str, summary: &str) {
        if let Ok(v) = self.vault.lock() {
            let _ = log(&v, operation, Some(profile), outcome, summary);
        }
    }
}

#[cfg(unix)]
fn destination(profile: &SshHostProfile) -> String {
    format!("{}@{}", profile.user, profile.host)
}

#[cfg(unix)]
fn is_host_key_failure(stderr: &str) -> bool {
    stderr.contains("Host key verification failed")
        || stderr.contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
}

#[cfg(unix)]
fn host_key_mismatch_error(name: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "host key for '{name}' does not match the pinned key; connection refused. \
         If the server was legitimately re-keyed, verify the new fingerprint out of band and run `envy ssh trust {name}`"
    )
}

#[cfg(not(unix))]
fn unsupported() -> anyhow::Error {
    anyhow::anyhow!(
        "envy SSH sessions use a Unix-socket agent and are not supported on Windows yet"
    )
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

    log(
        &vault,
        "ssh_import_key",
        None,
        "success",
        &format!("imported SSH key '{}' ({})", name, info.key_type),
    )?;

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

    let (info, public_key) =
        envy_core::ssh::generate_ssh_key(&vault, &name, &algorithm, comment.as_deref())?;

    log(
        &vault,
        "ssh_generate_key",
        None,
        "success",
        &format!("generated SSH key '{}' ({})", name, info.key_type),
    )?;

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

fn export_public(name: String, out: Option<PathBuf>, global: &GlobalArgs) -> anyhow::Result<()> {
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
    let key_list = envy_core::ssh::list_ssh_keys(&vault)?;

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

fn redacted_profile_json(profile: &SshHostProfile) -> serde_json::Value {
    serde_json::json!({
        "name": profile.name,
        "host": "[REDACTED]",
        "port": profile.port,
        "user": "[REDACTED]",
        "identity": profile.identity,
        "known_host_required": profile.known_host_required,
        "host_key_pinned": profile.host_key.is_some(),
    })
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

    vault.add_ssh_host(&SshHostProfile {
        name: name.clone(),
        host,
        port,
        user,
        identity,
        known_host_required: true,
        host_key: None,
    })?;
    // Re-read: an existing pin survives when host and port are unchanged.
    let profile = vault.get_ssh_host(&name)?;

    log(
        &vault,
        "ssh_add_host",
        Some(&profile.name),
        "success",
        &format!("configured host profile '{}'", name),
    )?;

    let is_agent = agent_id().is_some();
    if global.json {
        if is_agent {
            println!(
                "{}",
                serde_json::to_string(&redacted_profile_json(&profile))?
            );
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
        if profile.host_key.is_none() {
            println!(
                "Host key not pinned yet. Run `envy ssh trust {}` before connecting.",
                profile.name
            );
        }
    }
    Ok(())
}

fn list_hosts(global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    let hosts = vault.list_ssh_hosts()?;

    let is_agent = agent_id().is_some();
    if global.json {
        if is_agent {
            let redacted: Vec<serde_json::Value> =
                hosts.iter().map(redacted_profile_json).collect();
            println!("{}", serde_json::to_string(&redacted)?);
        } else {
            println!("{}", serde_json::to_string(&hosts)?);
        }
    } else if !global.quiet {
        if hosts.is_empty() {
            println!("No SSH host profiles configured.");
        } else {
            for h in &hosts {
                let pinned = if h.host_key.is_some() {
                    "pinned"
                } else {
                    "unpinned"
                };
                if is_agent {
                    println!(
                        "{:<18}  [REDACTED]@[REDACTED]:{}  identity={}  {}",
                        h.name, h.port, h.identity, pinned
                    );
                } else {
                    println!(
                        "{:<18}  {}@{}:{}  identity={}  {}",
                        h.name, h.user, h.host, h.port, h.identity, pinned
                    );
                }
            }
        }
    }
    Ok(())
}

/// `envy ssh trust <name>`: scan the server's host key and pin it.
fn trust(
    name: String,
    yes: bool,
    expected_fingerprint: Option<String>,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    if agent_id().is_some() {
        log(
            &vault,
            "ssh_trust_host",
            Some(&name),
            "denied",
            "agents may not pin host keys",
        )?;
        anyhow::bail!("agents may not pin host keys; ask a human to run `envy ssh trust {name}`");
    }
    let profile = vault.get_ssh_host(&name)?;

    let output = std::process::Command::new("ssh-keyscan")
        .args(["-T", "5", "-p", &profile.port.to_string(), &profile.host])
        .output()
        .context("failed to run ssh-keyscan (is OpenSSH installed?)")?;
    let scanned = String::from_utf8_lossy(&output.stdout);
    let host_key = envy_core::ssh::select_preferred_host_key(&scanned).ok_or_else(|| {
        anyhow::anyhow!(
            "no host key received from {}:{}",
            profile.host,
            profile.port
        )
    })?;
    let public = envy_core::ssh::parse_host_key(&host_key)?;
    let fp = envy_core::ssh::fingerprint(&public);
    let key_type = public.algorithm().as_str().to_string();

    if let Some(expected) = &expected_fingerprint
        && expected.trim() != fp
    {
        log(
            &vault,
            "ssh_trust_host",
            Some(&name),
            "denied:fingerprint_mismatch",
            &format!("scanned {fp}"),
        )?;
        anyhow::bail!("scanned host key {fp} does not match expected fingerprint {expected}");
    }

    if !global.json && !global.quiet {
        println!(
            "Host '{}' ({}:{}) presented {} key {}",
            profile.name, profile.host, profile.port, key_type, fp
        );
        if let Some(old) = &profile.host_key
            && envy_core::ssh::normalize_host_key(old)? != host_key
        {
            println!("WARNING: this replaces a different previously pinned key.");
        }
    }

    if !yes && expected_fingerprint.is_none() {
        use std::io::{BufRead, IsTerminal, Write};
        if !std::io::stdin().is_terminal() {
            anyhow::bail!(
                "refusing to pin without confirmation; re-run with --yes or --fingerprint <SHA256:...>"
            );
        }
        print!("Pin this host key? [y/N] ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().lock().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            anyhow::bail!("host key not pinned");
        }
    }

    vault.set_ssh_host_key(&name, Some(&host_key))?;
    log(
        &vault,
        "ssh_trust_host",
        Some(&name),
        "success",
        &format!("pinned {key_type} {fp}"),
    )?;
    if global.json {
        println!(
            "{}",
            serde_json::json!({"name": name, "key_type": key_type, "fingerprint": fp})
        );
    } else if !global.quiet {
        println!("Pinned host key for '{name}'.");
    }
    Ok(())
}

fn connect(name: String, global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    policy_gate(&vault, "ssh_connect", &name, None)?;
    let profile = vault.get_ssh_host(&name)?;
    pin_gate(&vault, "ssh_connect", &profile)?;

    #[cfg(not(unix))]
    {
        let _ = (name, global);
        Err(unsupported())
    }
    #[cfg(unix)]
    {
        let cwd = std::env::current_dir()?;
        let (profile, session) = start_session(&cwd, "ssh_connect", &name, None)?;
        session.log(
            "ssh_connect",
            &profile.name,
            "started",
            "interactive SSH session",
        );
        if !global.quiet && !global.json {
            let is_agent = agent_id().is_some();
            if is_agent {
                println!(
                    "Connecting to {} ([REDACTED]@[REDACTED]:{})...",
                    profile.name, profile.port
                );
            } else {
                println!(
                    "Connecting to {} ({}@{}:{})...",
                    profile.name, profile.user, profile.host, profile.port
                );
            }
        }
        let status = session
            .ssh(&profile)
            .arg(destination(&profile))
            .status()
            .context("failed to execute ssh")?;
        let outcome = if status.success() {
            "success".to_string()
        } else {
            format!("failed:{}", status.code().unwrap_or(-1))
        };
        session.log("ssh_connect", &profile.name, &outcome, "session ended");
        if !status.success() {
            anyhow::bail!("ssh exited with status {}", status);
        }
        Ok(())
    }
}

fn exec(name: String, command: Vec<String>, global: &GlobalArgs) -> anyhow::Result<()> {
    let cmd_str = command.join(" ");
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    policy_gate(&vault, "ssh_exec", &name, Some(&cmd_str))?;
    let profile = vault.get_ssh_host(&name)?;
    pin_gate(&vault, "ssh_exec", &profile)?;

    #[cfg(not(unix))]
    {
        let _ = (name, global, cmd_str);
        Err(unsupported())
    }
    #[cfg(unix)]
    {
        let (profile, session) = start_session(&cwd, "ssh_exec", &name, Some(&cmd_str))?;
        let program = command.first().map(String::as_str).unwrap_or("");
        session.log(
            "ssh_exec",
            &profile.name,
            "started",
            &format!("running '{program}'"),
        );

        let output = session
            .ssh(&profile)
            .arg("-o")
            .arg("BatchMode=yes")
            .arg(destination(&profile))
            .arg(&cmd_str)
            .output()
            .context("failed to execute remote command via ssh")?;
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() && is_host_key_failure(&stderr) {
            session.log(
                "ssh_exec",
                &profile.name,
                "failed:host_key_mismatch",
                "server host key did not match the pinned key",
            );
            if !global.quiet {
                eprint!("{stderr}");
            }
            return Err(host_key_mismatch_error(&profile.name));
        }

        let outcome = match output.status.code() {
            Some(0) => "success".to_string(),
            Some(c) => format!("failed:{c}"),
            None => "failed:signal".to_string(),
        };
        session.log(
            "ssh_exec",
            &profile.name,
            &outcome,
            &format!("ran '{program}'"),
        );

        let is_agent = agent_id().is_some();
        let raw_stdout = String::from_utf8_lossy(&output.stdout);
        let (clean_stdout, clean_stderr) = if is_agent {
            (
                envy_core::redact::redact_server_info(&raw_stdout, &profile.host, &profile.user),
                envy_core::redact::redact_server_info(&stderr, &profile.host, &profile.user),
            )
        } else {
            (raw_stdout.into_owned(), stderr)
        };

        if global.json {
            println!(
                "{}",
                serde_json::json!({
                    "status": if output.status.success() { "ok" } else { "error" },
                    "exit_code": output.status.code(),
                    "stdout": clean_stdout,
                    "stderr": clean_stderr,
                })
            );
        } else {
            std::io::Write::write_all(&mut std::io::stdout(), clean_stdout.as_bytes())?;
            std::io::Write::write_all(&mut std::io::stderr(), clean_stderr.as_bytes())?;
        }

        if !output.status.success() {
            anyhow::bail!(
                "remote command failed with exit code {:?}",
                output.status.code()
            );
        }
        Ok(())
    }
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
    policy_gate(&vault, "ssh_tunnel", &name, None)?;
    let profile = vault.get_ssh_host(&name)?;
    pin_gate(&vault, "ssh_tunnel", &profile)?;

    #[cfg(not(unix))]
    {
        let _ = (name, local_port, remote_host, remote_port, global);
        Err(unsupported())
    }
    #[cfg(unix)]
    {
        let cwd = std::env::current_dir()?;
        let (profile, session) = start_session(&cwd, "ssh_tunnel", &name, None)?;
        let forward_arg = format!("127.0.0.1:{local_port}:{remote_host}:{remote_port}");
        session.log(
            "ssh_tunnel",
            &profile.name,
            "started",
            &format!("127.0.0.1:{local_port} -> {remote_host}:{remote_port}"),
        );

        if !global.quiet && !global.json {
            let is_agent = agent_id().is_some();
            let (u, h) = if is_agent {
                ("[REDACTED]", "[REDACTED]")
            } else {
                (profile.user.as_str(), profile.host.as_str())
            };
            println!(
                "Forwarding 127.0.0.1:{} -> {}:{} through {} ({}@{}:{})...",
                local_port, remote_host, remote_port, profile.name, u, h, profile.port
            );
            println!("Press Ctrl+C to close the tunnel.");
        }

        let status = session
            .ssh(&profile)
            .arg("-N")
            .arg("-L")
            .arg(&forward_arg)
            .arg(destination(&profile))
            .status()
            .context("failed to establish SSH tunnel")?;
        let outcome = if status.success() {
            "success".to_string()
        } else {
            format!("failed:{}", status.code().unwrap_or(-1))
        };
        session.log("ssh_tunnel", &profile.name, &outcome, "tunnel closed");
        if !status.success() {
            anyhow::bail!("SSH tunnel exited with status {}", status);
        }
        Ok(())
    }
}

/// `envy ssh agent`: long-running agent for `git`/`ssh`/`rsync`.
fn agent(
    socket_opt: Option<PathBuf>,
    identities: Vec<String>,
    print_env: bool,
    use_global: bool,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    if agent_id().is_some() {
        log(
            &vault,
            "ssh_agent_start",
            None,
            "denied",
            "agents may not start a long-running SSH agent",
        )?;
        anyhow::bail!(
            "agents may not start a long-running SSH agent; use `envy ssh exec` (policy-checked per command)"
        );
    }

    let socket_path = match socket_opt {
        Some(s) => s,
        None => {
            let base = if use_global {
                std::env::var("HOME")
                    .map(PathBuf::from)
                    .context("HOME is not set")?
            } else {
                vault.project_root().to_path_buf()
            };
            let dot_envy = base.join(".envy");
            std::fs::create_dir_all(&dot_envy)?;
            dot_envy.join("ssh-agent.sock")
        }
    };

    let identities = if identities.is_empty() {
        let mut names: Vec<String> = vault
            .list_ssh_hosts()?
            .into_iter()
            .map(|h| h.identity)
            .collect();
        names.sort();
        names.dedup();
        names
    } else {
        identities
    };
    if identities.is_empty() {
        anyhow::bail!(
            "no identities to serve: pass --identity <name> or add a host profile with `envy ssh add`"
        );
    }

    serve_agent(vault, &socket_path, identities, print_env, global)
}

#[cfg(not(unix))]
fn serve_agent(
    _vault: Vault,
    _socket_path: &Path,
    _identities: Vec<String>,
    _print_env: bool,
    _global: &GlobalArgs,
) -> anyhow::Result<()> {
    Err(unsupported())
}

#[cfg(unix)]
fn serve_agent(
    vault: Vault,
    socket_path: &Path,
    identities: Vec<String>,
    print_env: bool,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    use envy_core::ssh_agent::{AgentConfig, SshAgent, bind_agent_socket, serve_listener};
    use std::sync::{Arc, Mutex};

    let project = vault.project_root().to_string_lossy().to_string();
    let _ = log(
        &vault,
        "ssh_agent_start",
        None,
        "success",
        &format!("serving {} identities", identities.len()),
    );
    let vault = Arc::new(Mutex::new(vault));
    let agent = SshAgent::new(
        vault,
        &identities,
        AgentConfig {
            subject: current_subject(),
            project,
            host_profile: None,
            expected_host_key_blob: None,
        },
    )?;
    let listener = bind_agent_socket(socket_path)?;

    if print_env {
        println!(
            "SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;",
            socket_path.display()
        );
        use std::io::Write;
        std::io::stdout().flush()?;
    } else if !global.quiet && !global.json {
        println!("envy SSH agent listening on {}", socket_path.display());
        for id in agent.identities() {
            println!(
                "  {}  {}",
                id.name,
                envy_core::ssh::fingerprint(&id.public_key)
            );
        }
        println!("export SSH_AUTH_SOCK=\"{}\"", socket_path.display());
        use std::io::Write;
        std::io::stdout().flush()?;
    }

    serve_listener(Arc::new(agent), listener, None)?;
    Ok(())
}
