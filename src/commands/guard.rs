//! `envy guard` — agent-side command/file-access governance.
//!
//! Best-effort PreToolUse / beforeShellExecution / beforeReadFile enforcement.
//! See `docs/agent-governance.md`. Not a sandbox.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, bail};
use envy_core::audit::{self, AuditEvent};
use envy_core::guard::{self, GuardDecision, GuardPolicy};
use envy_core::policy::{self, ProjectPolicy};
use serde_json::json;

use crate::cli::{GlobalArgs, GuardAction, GuardClientArg, ScopeArg};

pub fn run(action: GuardAction, global: &GlobalArgs) -> anyhow::Result<()> {
    match action {
        GuardAction::CheckCommand { command } => check_command(command, global),
        GuardAction::CheckPath { path, write } => check_path(path, write, global),
        GuardAction::Hook { client } => hook(client, global),
        GuardAction::Install {
            client,
            scope,
            force,
        } => install(client, scope, force, global),
    }
}

fn load_guard_policy(cwd: &Path) -> (ProjectPolicy, GuardPolicy) {
    let project = policy::load_policy(cwd).unwrap_or_default();
    let guard = project.guard.clone();
    (project, guard)
}

fn check_command(command: Vec<String>, global: &GlobalArgs) -> anyhow::Result<()> {
    let cmd = command.join(" ");
    let cwd = std::env::current_dir()?;
    let (_project, gpol) = load_guard_policy(&cwd);
    let decision = guard::check_command(&cmd, &gpol);
    emit_and_exit(decision, &gpol, "cli", &cwd, global)
}

fn check_path(path: String, write: bool, global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let (_project, gpol) = load_guard_policy(&cwd);
    let decision = guard::check_path(&path, write, &gpol);
    emit_and_exit(decision, &gpol, "cli", &cwd, global)
}

/// Shared allow/deny printer for the check-* subcommands.
///
/// In enforce mode a deny exits with code 2 (matching Claude Code / Cursor
/// hook conventions). In audit mode a would-deny is logged and we exit 0.
fn emit_and_exit(
    decision: GuardDecision,
    gpol: &GuardPolicy,
    subject: &str,
    cwd: &Path,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    if decision.allow {
        if global.json {
            println!(r#"{{"allow":true}}"#);
        } else if !global.quiet {
            println!("allow");
        }
        return Ok(());
    }

    let audit_mode = gpol.is_audit_mode();
    let summary = decision.audit_summary();
    let _ = audit::append_unkeyed(
        cwd,
        &AuditEvent {
            subject: Some(subject),
            project: Some(&cwd.to_string_lossy()),
            provider: None,
            operation: if audit_mode {
                "guard_would_deny"
            } else {
                "guard_deny"
            },
            endpoint_host: decision.target.as_deref(),
            outcome: if audit_mode { "would_deny" } else { "denied" },
            redaction_summary: Some(&summary),
        },
    );

    let reason = decision.reason.as_deref().unwrap_or("denied by envy guard");
    let suggestion = decision.suggestion.as_deref().unwrap_or("");
    let rule = decision.rule.unwrap_or("-");

    if global.json {
        println!(
            "{}",
            json!({
                "allow": false,
                "rule": rule,
                "reason": reason,
                "suggestion": suggestion,
                "audit_mode": audit_mode,
            })
        );
    } else if !global.quiet {
        eprintln!("deny [{rule}]: {reason}");
        if !suggestion.is_empty() {
            eprintln!("  → {suggestion}");
        }
        if audit_mode {
            eprintln!("  (audit mode: would deny; allowing)");
        }
    }

    if audit_mode {
        Ok(())
    } else {
        // Exit 2 matches Claude Code / Cursor hook deny convention.
        std::process::exit(2);
    }
}

fn hook(client: GuardClientArg, global: &GlobalArgs) -> anyhow::Result<()> {
    let mut stdin = String::new();
    io::stdin()
        .read_to_string(&mut stdin)
        .context("failed to read hook payload from stdin")?;

    let cwd = resolve_cwd_from_payload(&stdin)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let (_project, gpol) = load_guard_policy(&cwd);

    if !gpol.enabled {
        write_allow(client);
        return Ok(());
    }

    let (decision, subject) = match classify_hook_payload(client, &stdin, &gpol) {
        Ok(v) => v,
        Err(e) => {
            // Fail closed: unreadable / unexpected payload is a deny.
            let reason = format!("envy guard could not classify this tool call: {e}");
            write_deny(
                client,
                &GuardDecision {
                    allow: false,
                    rule: Some("hook-error"),
                    reason: Some(reason.clone()),
                    suggestion: Some(
                        "retry with a simpler command, or use the envy MCP tools".into(),
                    ),
                    program: None,
                    target: None,
                },
                &gpol,
                "agent:hook",
                &cwd,
            );
            let _ = global; // quiet/json unused for hook I/O (client-shaped JSON only)
            return Ok(());
        }
    };

    if decision.allow {
        write_allow(client);
        Ok(())
    } else {
        write_deny(client, &decision, &gpol, &subject, &cwd);
        Ok(())
    }
}

fn resolve_cwd_from_payload(stdin: &str) -> anyhow::Result<PathBuf> {
    let v: serde_json::Value = serde_json::from_str(stdin)?;
    if let Some(s) = v.get("cwd").and_then(|x| x.as_str()) {
        return Ok(PathBuf::from(s));
    }
    if let Some(arr) = v.get("workspace_roots").and_then(|x| x.as_array())
        && let Some(s) = arr.first().and_then(|x| x.as_str())
    {
        return Ok(PathBuf::from(s));
    }
    Ok(std::env::current_dir()?)
}

fn classify_hook_payload(
    client: GuardClientArg,
    stdin: &str,
    gpol: &GuardPolicy,
) -> anyhow::Result<(GuardDecision, String)> {
    let v: serde_json::Value = serde_json::from_str(stdin).context("hook stdin is not JSON")?;

    let subject = subject_from_payload(&v);

    match client {
        GuardClientArg::ClaudeCode => {
            // Claude Code PreToolUse: {tool_name, tool_input, cwd, ...}
            let tool_name = v.get("tool_name").and_then(|x| x.as_str()).unwrap_or("");
            let input = v.get("tool_input").cloned().unwrap_or(json!({}));
            Ok((guard::classify_tool_call(tool_name, &input, gpol), subject))
        }
        GuardClientArg::Cursor => {
            // Cursor fires distinct events. Prefer event-specific fields;
            // fall back to generic preToolUse shape.
            let event = v
                .get("hook_event_name")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            if (event == "beforeShellExecution"
                || (v.get("command").is_some() && v.get("tool_name").is_none()))
                && let Some(cmd) = v.get("command").and_then(|x| x.as_str())
            {
                return Ok((guard::check_command(cmd, gpol), subject));
            }
            if (event == "beforeReadFile"
                || (v.get("file_path").is_some() && v.get("command").is_none()))
                && let Some(path) = v.get("file_path").and_then(|x| x.as_str())
            {
                // Cursor's beforeReadFile is always a read.
                return Ok((guard::check_path(path, false, gpol), subject));
            }
            // Generic preToolUse / beforeMCPExecution
            let tool_name = v.get("tool_name").and_then(|x| x.as_str()).unwrap_or("");
            // beforeMCPExecution passes tool_input as a JSON *string*.
            let input = match v.get("tool_input") {
                Some(serde_json::Value::String(s)) => serde_json::from_str(s).unwrap_or(json!({})),
                Some(other) => other.clone(),
                None => json!({}),
            };
            // Skip envy's own MCP tools by server name when present.
            if let Some(server) = v.get("mcp_server_name").and_then(|x| x.as_str())
                && server == "envy"
            {
                return Ok((GuardDecision::allow(), subject));
            }
            Ok((guard::classify_tool_call(tool_name, &input, gpol), subject))
        }
    }
}

fn subject_from_payload(v: &serde_json::Value) -> String {
    if let Some(id) = v
        .get("agent_id")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
    {
        return format!("agent:{id}");
    }
    if let Ok(id) = std::env::var("ENVY_AGENT_ID")
        && !id.trim().is_empty()
    {
        return format!("agent:{}", id.trim());
    }
    // Fall back to the client / conversation id when available.
    if let Some(cid) = v
        .get("conversation_id")
        .or_else(|| v.get("session_id"))
        .and_then(|x| x.as_str())
    {
        return format!("agent:{}", &cid[..cid.len().min(12)]);
    }
    "agent:hook".to_string()
}

fn write_allow(client: GuardClientArg) {
    match client {
        GuardClientArg::ClaudeCode => {
            // Empty / omit permissionDecision = allow. Emit a minimal ok object
            // so the harness doesn't treat missing JSON as a soft failure.
            println!(
                "{}",
                json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow"
                    }
                })
            );
        }
        GuardClientArg::Cursor => {
            println!("{}", json!({"permission": "allow", "continue": true}));
        }
    }
}

fn write_deny(
    client: GuardClientArg,
    decision: &GuardDecision,
    gpol: &GuardPolicy,
    subject: &str,
    cwd: &Path,
) {
    let audit_mode = gpol.is_audit_mode();
    let summary = decision.audit_summary();
    let _ = audit::append_unkeyed(
        cwd,
        &AuditEvent {
            subject: Some(subject),
            project: Some(&cwd.to_string_lossy()),
            provider: None,
            operation: if audit_mode {
                "guard_would_deny"
            } else {
                "guard_deny"
            },
            endpoint_host: decision.target.as_deref(),
            outcome: if audit_mode { "would_deny" } else { "denied" },
            redaction_summary: Some(&summary),
        },
    );

    if audit_mode {
        write_allow(client);
        return;
    }

    let reason = decision.reason.as_deref().unwrap_or("denied by envy guard");
    let suggestion = decision.suggestion.as_deref().unwrap_or("");
    let msg = if suggestion.is_empty() {
        reason.to_string()
    } else {
        format!("{reason}\n→ {suggestion}")
    };

    match client {
        GuardClientArg::ClaudeCode => {
            println!(
                "{}",
                json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": msg,
                    }
                })
            );
        }
        GuardClientArg::Cursor => {
            println!(
                "{}",
                json!({
                    "permission": "deny",
                    "continue": true,
                    "user_message": format!("envy guard: {}", decision.rule.unwrap_or("deny")),
                    "agent_message": msg,
                })
            );
        }
    }
}

fn install(
    client: GuardClientArg,
    scope: Option<ScopeArg>,
    force: bool,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    let project_root = std::env::current_dir()?;
    let scope = scope.unwrap_or(ScopeArg::Project);
    let exe = std::env::current_exe().context("could not resolve envy executable path")?;
    let exe_str = exe
        .to_str()
        .context("envy executable path is not valid UTF-8")?;

    let path = match (client, scope) {
        (GuardClientArg::ClaudeCode, ScopeArg::Project) => {
            project_root.join(".claude").join("settings.json")
        }
        (GuardClientArg::ClaudeCode, ScopeArg::Global) => {
            let home = directories::BaseDirs::new()
                .context("could not determine home directory")?
                .home_dir()
                .to_path_buf();
            home.join(".claude").join("settings.json")
        }
        (GuardClientArg::Cursor, ScopeArg::Project) => {
            project_root.join(".cursor").join("hooks.json")
        }
        (GuardClientArg::Cursor, ScopeArg::Global) => {
            let home = directories::BaseDirs::new()
                .context("could not determine home directory")?
                .home_dir()
                .to_path_buf();
            home.join(".cursor").join("hooks.json")
        }
    };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    match client {
        GuardClientArg::ClaudeCode => install_claude(&path, exe_str, force)?,
        GuardClientArg::Cursor => install_cursor(&path, exe_str, force)?,
    }

    if global.json {
        println!(
            "{}",
            json!({
                "status": "ok",
                "client": client_id(client),
                "config_path": path.display().to_string(),
            })
        );
    } else if !global.quiet {
        println!(
            "Installed envy guard hooks for {} at {}\n\
             Note: hooks are best-effort, not a sandbox — see docs/agent-governance.md",
            client_id(client),
            path.display()
        );
    }
    Ok(())
}

fn client_id(c: GuardClientArg) -> &'static str {
    match c {
        GuardClientArg::ClaudeCode => "claude-code",
        GuardClientArg::Cursor => "cursor",
    }
}

fn back_up(path: &Path) -> anyhow::Result<()> {
    let backup = PathBuf::from(format!("{}.bak", path.display()));
    std::fs::copy(path, &backup).with_context(|| {
        format!(
            "failed to back up {} to {}",
            path.display(),
            backup.display()
        )
    })?;
    Ok(())
}

fn install_claude(path: &Path, exe: &str, force: bool) -> anyhow::Result<()> {
    let mut root = if path.exists() {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_str(&text)
            .with_context(|| format!("{} is not valid JSON", path.display()))?
    } else {
        json!({})
    };

    let obj = root
        .as_object_mut()
        .context("settings.json root must be a JSON object")?;

    let hooks = obj
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("\"hooks\" must be a JSON object")?;

    let pre = hooks
        .entry("PreToolUse")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("\"hooks.PreToolUse\" must be a JSON array")?;

    // Look for an existing envy-owned entry (command contains "envy guard hook").
    let already = pre.iter().any(|entry| {
        entry
            .get("hooks")
            .and_then(|h| h.as_array())
            .map(|arr| {
                arr.iter().any(|h| {
                    h.get("command")
                        .and_then(|c| c.as_str())
                        .map(|s| s.contains("envy guard hook"))
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    });
    if already && !force {
        bail!(
            "{} already has an envy guard PreToolUse entry — pass --force to overwrite \
             (backs up the whole file to <file>.bak first)",
            path.display()
        );
    }
    if already {
        back_up(path)?;
        pre.retain(|entry| {
            !entry
                .get("hooks")
                .and_then(|h| h.as_array())
                .map(|arr| {
                    arr.iter().any(|h| {
                        h.get("command")
                            .and_then(|c| c.as_str())
                            .map(|s| s.contains("envy guard hook"))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        });
    }

    let hook_cmd = format!("{exe} guard hook --client claude-code");
    pre.push(json!({
        "matcher": "Bash|Read|Edit|Write|MultiEdit|Grep|Glob|NotebookRead|NotebookEdit",
        "hooks": [{
            "type": "command",
            "command": hook_cmd,
            "timeout": 10,
            "onFailure": "block"
        }]
    }));

    let out = serde_json::to_string_pretty(&root).context("failed to serialize settings")?;
    std::fs::write(path, out + "\n")
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn install_cursor(path: &Path, exe: &str, force: bool) -> anyhow::Result<()> {
    let mut root = if path.exists() {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_str(&text)
            .with_context(|| format!("{} is not valid JSON", path.display()))?
    } else {
        json!({"version": 1, "hooks": {}})
    };

    let obj = root
        .as_object_mut()
        .context("hooks.json root must be a JSON object")?;
    obj.entry("version").or_insert(json!(1));

    let hooks = obj
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("\"hooks\" must be a JSON object")?;

    let hook_cmd = format!("{exe} guard hook --client cursor");
    let entry = json!({
        "command": hook_cmd,
        "timeout": 10,
        "failClosed": true,
    });

    let mut wrote = false;
    for key in [
        "beforeShellExecution",
        "beforeReadFile",
        "beforeMCPExecution",
        "preToolUse",
    ] {
        let arr = hooks
            .entry(key)
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .with_context(|| format!("\"hooks.{key}\" must be a JSON array"))?;
        let already = arr.iter().any(|h| {
            h.get("command")
                .and_then(|c| c.as_str())
                .map(|s| s.contains("envy guard hook"))
                .unwrap_or(false)
        });
        if already && !force {
            bail!(
                "{} already has an envy guard {key} entry — pass --force to overwrite \
                 (backs up the whole file to <file>.bak first)",
                path.display()
            );
        }
        if already {
            if !wrote {
                back_up(path)?;
                wrote = true;
            }
            arr.retain(|h| {
                !h.get("command")
                    .and_then(|c| c.as_str())
                    .map(|s| s.contains("envy guard hook"))
                    .unwrap_or(false)
            });
        }
        arr.push(entry.clone());
    }

    let out = serde_json::to_string_pretty(&root).context("failed to serialize hooks.json")?;
    std::fs::write(path, out + "\n")
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Used only so `cargo test` can assert the ExitCode shape of a deny without
/// calling `process::exit`. Not part of the public CLI surface.
#[allow(dead_code)]
pub fn deny_exit_code() -> ExitCode {
    ExitCode::from(2)
}
