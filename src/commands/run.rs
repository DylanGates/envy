use anyhow::Context;
use envy_core::audit::AuditEvent;

use crate::cli::GlobalArgs;

pub fn run(command: Vec<String>, global: &GlobalArgs) -> anyhow::Result<()> {
    let full_cmd = command.join(" ");
    let cwd = std::env::current_dir()?;

    // Guard classifier (same rules as PreToolUse hooks).
    {
        let mut gpol = envy_core::policy::load_policy(&cwd)
            .map(|p| p.guard)
            .unwrap_or_default();
        // `envy sandbox`/`envy run` exist specifically to inject vault secrets
        // into a child env — allow the env-dump programs that agents use to
        // verify injection (printenv/env/...). Outside of envy, PreToolUse
        // hooks still block those.
        for prog in ["printenv", "env", "export", "set", "declare", "typeset"] {
            if !gpol.allow_commands.iter().any(|c| c == prog) {
                gpol.allow_commands.push(prog.to_string());
            }
        }
        let decision = envy_core::guard::check_command(&full_cmd, &gpol);
        if !decision.allow && !gpol.is_audit_mode() {
            let reason = decision.reason.as_deref().unwrap_or("denied by envy guard");
            let suggestion = decision.suggestion.as_deref().unwrap_or("");
            anyhow::bail!(
                "execution blocked by envy guard [{rule}]: {reason}{hint}",
                rule = decision.rule.unwrap_or("-"),
                hint = if suggestion.is_empty() {
                    String::new()
                } else {
                    format!(" — {suggestion}")
                }
            );
        }
    }
    if envy_core::policy::is_env_file_involved(&full_cmd) {
        anyhow::bail!(
            "execution blocked: command references a .env file ('{full_cmd}'). \
             Governance policy prohibits tools and agents from reading or exposing raw .env secrets."
        );
    }
    let vault = envy_core::vault::open(&cwd)?;
    let secrets = vault.list_secrets()?;

    // Decrypt all vault secrets into (name, value) pairs. Plaintext exists
    // only within this process for the duration of this function — it is
    // injected into the child's environment via `envs()` (never in argv)
    // and drops when this frame returns.
    let mut env_vars: Vec<(String, String)> = Vec::new();
    let mut decrypt_failures = 0usize;

    for meta in &secrets {
        match vault.get_secret(&meta.name) {
            Ok(raw) => match String::from_utf8(raw) {
                Ok(value) => env_vars.push((meta.name.clone(), value)),
                Err(_) => {
                    // Non-UTF-8 values cannot be environment variables —
                    // skip silently. They are still safely stored in the vault.
                    decrypt_failures += 1;
                }
            },
            Err(e) => {
                // Decryption failure is non-fatal for run: report and continue
                // rather than blocking the whole command.
                if !global.quiet {
                    eprintln!("envy run: warning: could not decrypt '{}': {e}", meta.name);
                }
                decrypt_failures += 1;
            }
        }
    }

    let injected = env_vars.len();

    // Log before spawning so there is always an audit record, even if
    // spawn fails. Values are never logged — only the count.
    vault.log_event(&AuditEvent {
        subject: Some("cli"),
        project: Some(&cwd.to_string_lossy()),
        provider: None,
        operation: "run",
        endpoint_host: None,
        outcome: "started",
        redaction_summary: Some(&format!(
            "{injected} secret(s) injected into subprocess env\
             {}",
            if decrypt_failures > 0 {
                format!(", {decrypt_failures} skipped (decrypt error or non-UTF-8)")
            } else {
                String::new()
            }
        )),
    })?;

    if !global.quiet && !global.json {
        eprintln!("envy run: injecting {injected} secret(s) into environment");
    }

    let (prog, args) = command
        .split_first()
        .expect("command is non-empty (enforced by clap `required = true`)");

    let status = std::process::Command::new(prog)
        .args(args)
        .envs(env_vars) // values in env, never in argv
        .status()
        .with_context(|| format!("failed to execute `{prog}`"))?;

    // Propagate the child's exit code so callers can detect failure.
    if !status.success() {
        let code = status.code().unwrap_or(1);
        std::process::exit(code);
    }
    Ok(())
}
