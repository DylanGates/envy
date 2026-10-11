use anyhow::{Context, bail};
use envy_core::audit::AuditEvent;
use envy_core::provider::Registry;

use crate::cli::GlobalArgs;

/// Executes an application command in a zero-exposure environment for AI agents.
///
/// Composes:
/// 1. File scanner & remediation: ensures credentials are not exposed on disk as plaintext.
/// 2. Command inspection & policy: blocks attempts to read .env files directly.
/// 3. In-memory injection: injects vault secrets into child process env without touching argv.
/// 4. Audit logging: produces a redacted audit trail of the sandboxed execution.
pub fn run(remediate: bool, command: Vec<String>, global: &GlobalArgs) -> anyhow::Result<()> {
    let full_cmd = command.join(" ");

    // 1. Policy check: block any command referencing .env
    if envy_core::policy::is_env_file_involved(&full_cmd) {
        bail!(
            "sandbox blocked: command references .env ('{full_cmd}'). \
             AI agents are prohibited from viewing raw env secrets."
        );
    }

    let cwd = std::env::current_dir()?;

    // 2. Open vault and load policy
    let vault = envy_core::vault::open(&cwd)?;
    let policy = envy_core::policy::load_policy(&cwd)?;
    let agent_id = std::env::var("ENVY_AGENT_ID").ok();

    let policy_req = envy_core::policy::PolicyRequest {
        operation: "sandbox_exec",
        provider: None,
        domain: None,
        agent_identity: agent_id.as_deref(),
        method: "EXEC",
        command: Some(&full_cmd),
        has_active_consent: false,
    };

    match envy_core::policy::evaluate_with_policy(&policy_req, &policy) {
        envy_core::policy::PolicyDecision::Allow => {}
        envy_core::policy::PolicyDecision::RequireConsent { reason } => {
            bail!("sandbox policy requires human consent: {reason}");
        }
        envy_core::policy::PolicyDecision::Deny { reason } => {
            bail!("sandbox policy denied command execution: {reason}");
        }
    }

    // 3. Pre-flight file remediation if requested
    if remediate && let Ok((registry, _)) = Registry::load() {
        let scan_res = envy_core::scanner::scan(&cwd, &registry);
        let secret_candidates: Vec<&envy_core::scanner::Candidate> = scan_res
            .candidates
            .iter()
            .filter(|c| c.looks_like_secret())
            .collect();

        if !secret_candidates.is_empty() {
            if !global.quiet && !global.json {
                eprintln!(
                    "envy sandbox: auto-remediating {} plaintext secret(s) in project files...",
                    secret_candidates.len()
                );
            }
            for candidate in secret_candidates {
                let _ = candidate.import_and_remediate(&vault);
            }
        }
    }

    // 4. In-memory secret resolution
    let secrets = vault.list_secrets()?;
    let mut env_vars: Vec<(String, String)> = Vec::new();

    for meta in &secrets {
        if let Ok(raw) = vault.get_secret(&meta.name)
            && let Ok(val) = String::from_utf8(raw)
        {
            env_vars.push((meta.name.clone(), val));
        }
    }

    let injected_count = env_vars.len();

    // 5. Audit record
    vault.log_event(&AuditEvent {
        subject: Some(agent_id.as_deref().unwrap_or("agent")),
        project: Some(&cwd.to_string_lossy()),
        provider: None,
        operation: "sandbox_exec",
        endpoint_host: None,
        outcome: "started",
        redaction_summary: Some(&format!(
            "sandboxed '{full_cmd}' with {injected_count} in-memory injected secret(s)"
        )),
    })?;

    if !global.quiet && !global.json {
        eprintln!(
            "envy sandbox: running `{full_cmd}` (injected {injected_count} secrets in-memory)"
        );
    }

    let (prog, args) = command
        .split_first()
        .expect("command is non-empty (enforced by clap `required = true`)");

    let status = std::process::Command::new(prog)
        .args(args)
        .envs(env_vars)
        .status()
        .with_context(|| format!("failed to execute `{prog}`"))?;

    if !status.success() {
        let code = status.code().unwrap_or(1);
        std::process::exit(code);
    }

    Ok(())
}
