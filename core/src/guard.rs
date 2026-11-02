//! Agent command/file-access governance ("guard").
//!
//! A *best-effort* enforcement layer that classifies the shell commands and
//! file-access tool calls an AI coding agent is about to run, and denies the
//! ones that would bypass envy's vault/trust boundary — raw `ssh` into a
//! server, `cat .env`, dumping `printenv`, reading `~/.ssh/id_*`, pulling a
//! credential out of the OS keychain, and so on. A deny comes with a
//! suggestion pointing the agent at the envy command/MCP tool to use instead.
//!
//! **This is not a sandbox.** It runs as agent-harness pre-tool-use hooks
//! (Claude Code, Cursor), which an agent with a real shell can bypass many
//! ways: `disableAllHooks`, base64/obfuscation, a compiled helper binary, a
//! language runtime that opens the file directly, or simply a different
//! harness with no hooks installed. See `docs/agent-governance.md`. Treat it
//! as guardrails that stop the *easy, default* path, not as containment.
//!
//! Lives in `core` (the trusted boundary): it is pure classification logic
//! over strings, with no secret material, and is reused by the `cli` crate's
//! `envy guard` command, the hook entrypoints, and `envy run`/`envy sandbox`.

use serde::{Deserialize, Serialize};

/// Declarative `[guard]` section of `.envy/policy.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardPolicy {
    /// Master switch. When false, every check allows (the guard is off).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// `"enforce"` (deny blocks) or `"audit"` (would-deny is logged, allowed).
    #[serde(default = "default_mode")]
    pub mode: String,

    /// Shell program basenames to always allow, even if a rule matches.
    #[serde(default)]
    pub allow_commands: Vec<String>,

    /// SSH destination hosts agents may reach directly (git forges by default).
    #[serde(default = "default_ssh_hosts")]
    pub allow_ssh_hosts: Vec<String>,

    /// Path prefixes/globs to always allow reading, overriding `secret-file`.
    #[serde(default)]
    pub allow_paths: Vec<String>,

    /// Extra path prefixes/globs to always deny (added to the built-ins).
    #[serde(default)]
    pub deny_paths: Vec<String>,

    /// Extra program basenames to always deny.
    #[serde(default)]
    pub deny_commands: Vec<String>,
}

impl Default for GuardPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: default_mode(),
            allow_commands: Vec::new(),
            allow_ssh_hosts: default_ssh_hosts(),
            allow_paths: Vec::new(),
            deny_paths: Vec::new(),
            deny_commands: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_mode() -> String {
    "enforce".to_string()
}

fn default_ssh_hosts() -> Vec<String> {
    vec![
        "github.com".to_string(),
        "gitlab.com".to_string(),
        "bitbucket.org".to_string(),
        "ssh.github.com".to_string(),
        "altssh.gitlab.com".to_string(),
    ]
}

impl GuardPolicy {
    pub fn is_audit_mode(&self) -> bool {
        self.mode.eq_ignore_ascii_case("audit")
    }
}

/// The outcome of classifying a command or path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardDecision {
    /// True to allow, false to deny.
    pub allow: bool,
    /// Stable rule id that matched (for a deny), e.g. `"ssh-remote"`.
    pub rule: Option<&'static str>,
    /// Human/agent-facing reason for the deny.
    pub reason: Option<String>,
    /// What to do instead — points at the envy command/MCP tool.
    pub suggestion: Option<String>,
    /// Program basename that triggered the match (for the audit summary only).
    pub program: Option<String>,
    /// Host or path basename that triggered the match (audit summary only).
    /// Never the full command — a pasted inline token must not be logged.
    pub target: Option<String>,
}

impl GuardDecision {
    pub fn allow() -> Self {
        Self {
            allow: true,
            rule: None,
            reason: None,
            suggestion: None,
            program: None,
            target: None,
        }
    }

    fn deny(rule: &'static str, reason: impl Into<String>, suggestion: impl Into<String>) -> Self {
        Self {
            allow: false,
            rule: Some(rule),
            reason: Some(reason.into()),
            suggestion: Some(suggestion.into()),
            program: None,
            target: None,
        }
    }

    fn with_program(mut self, program: impl Into<String>) -> Self {
        self.program = Some(program.into());
        self
    }

    fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// A compact, secret-free summary suitable for an audit `redaction_summary`.
    pub fn audit_summary(&self) -> String {
        let rule = self.rule.unwrap_or("-");
        let prog = self.program.as_deref().unwrap_or("-");
        match &self.target {
            Some(t) => format!("rule={rule} program={prog} target={t}"),
            None => format!("rule={rule} program={prog}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Classifies a full shell command line (as an agent's Bash/Shell tool would
/// run it). Parses chaining, substitutions, wrappers and `sh -c` recursion.
pub fn check_command(command: &str, policy: &GuardPolicy) -> GuardDecision {
    if !policy.enabled {
        return GuardDecision::allow();
    }
    check_command_inner(command, policy, 0)
}

/// Classifies a file-access tool call by path (Read/Edit/Write/Grep/Glob).
/// `write` marks a write/edit so protected-config writes are caught even for
/// paths that are fine to read.
pub fn check_path(path: &str, write: bool, policy: &GuardPolicy) -> GuardDecision {
    if !policy.enabled {
        return GuardDecision::allow();
    }
    classify_path(path, write, policy)
}

/// Classifies an arbitrary agent tool call, given the tool name and its JSON
/// input object. Known tools (Bash/Shell, Read, Edit, Write, Grep, Glob, ...)
/// are mapped to [`check_command`]/[`check_path`]; `mcp__envy__*` is always
/// allowed (that *is* the sanctioned path); other/unknown tools fall back to
/// scanning any command/path-looking fields.
pub fn classify_tool_call(
    tool_name: &str,
    input: &serde_json::Value,
    policy: &GuardPolicy,
) -> GuardDecision {
    if !policy.enabled {
        return GuardDecision::allow();
    }

    // envy's own MCP tools are the sanctioned escape hatch — never block them.
    if tool_name.starts_with("mcp__envy__") {
        return GuardDecision::allow();
    }

    let name = tool_name.rsplit("__").next().unwrap_or(tool_name);
    let lname = name.to_ascii_lowercase();

    match lname.as_str() {
        "bash" | "shell" | "run" | "runterminalcmd" | "execute" | "terminal" => {
            if let Some(cmd) = str_field(input, &["command", "cmd", "script"]) {
                return check_command(&cmd, policy);
            }
            GuardDecision::allow()
        }
        "read" | "readfile" | "cat" | "notebookread" | "view" => path_fields(
            input,
            &["file_path", "path", "notebook_path", "target_file"],
        )
        .into_iter()
        .map(|p| classify_path(&p, false, policy))
        .find(|d| !d.allow)
        .unwrap_or_else(GuardDecision::allow),
        "edit" | "write" | "multiedit" | "writefile" | "create" | "notebookedit" => path_fields(
            input,
            &["file_path", "path", "notebook_path", "target_file"],
        )
        .into_iter()
        .map(|p| classify_path(&p, true, policy))
        .find(|d| !d.allow)
        .unwrap_or_else(GuardDecision::allow),
        "grep" | "glob" | "search" | "searchfiles" | "codebase_search" | "ripgrep" => {
            // A path/glob argument is a read target; a `grep -r PATTERN .env`
            // style call is also covered by the path check.
            let mut targets = path_fields(input, &["path", "glob", "target_directory"]);
            if let Some(cmd) = str_field(input, &["command"]) {
                let d = check_command(&cmd, policy);
                if !d.allow {
                    return d;
                }
            }
            // A literal `.env` pattern is only a weak signal; classify the
            // path/glob targets, which is where a concrete file is named.
            targets.retain(|t| !t.is_empty());
            targets
                .into_iter()
                .map(|p| classify_path(&p, false, policy))
                .find(|d| !d.allow)
                .unwrap_or_else(GuardDecision::allow)
        }
        _ => {
            // Unknown / other-MCP tool: best-effort scan of common fields.
            if let Some(cmd) = str_field(input, &["command", "cmd", "script"]) {
                let d = check_command(&cmd, policy);
                if !d.allow {
                    return d;
                }
            }
            for p in path_fields(
                input,
                &["file_path", "path", "notebook_path", "target_file"],
            ) {
                let d = classify_path(&p, false, policy);
                if !d.allow {
                    return d;
                }
            }
            GuardDecision::allow()
        }
    }
}

fn str_field(input: &serde_json::Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = input.get(k).and_then(|v| v.as_str()) {
            return Some(s.to_string());
        }
    }
    None
}

fn path_fields(input: &serde_json::Value, keys: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for k in keys {
        match input.get(k) {
            Some(serde_json::Value::String(s)) => out.push(s.clone()),
            Some(serde_json::Value::Array(arr)) => {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        out.push(s.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Command classification
// ---------------------------------------------------------------------------

const MAX_RECURSION: usize = 8;

fn check_command_inner(command: &str, policy: &GuardPolicy, depth: usize) -> GuardDecision {
    if depth > MAX_RECURSION {
        // Pathologically nested — fail closed.
        return GuardDecision::deny(
            "too-deep",
            "command nests shell substitutions/`-c` too deeply to classify safely",
            "simplify the command, or use an envy command for the underlying action",
        );
    }

    // 1. Recurse into every command substitution: $(...), `...`, <(...), >(...).
    for inner in extract_substitutions(command) {
        let d = check_command_inner(&inner, policy, depth + 1);
        if !d.allow {
            return d;
        }
    }

    // 2. Split into simple commands on ; && || | & and newlines, and also
    //    pull out redirection targets as path reads/writes.
    for segment in split_simple_commands(command) {
        let d = classify_simple_command(&segment, policy, depth);
        if !d.allow {
            return d;
        }
    }

    GuardDecision::allow()
}

/// One simple command: its words, plus any redirection target paths.
struct SimpleCommand {
    words: Vec<String>,
    read_redirects: Vec<String>,
    write_redirects: Vec<String>,
}

fn classify_simple_command(
    seg: &SimpleCommand,
    policy: &GuardPolicy,
    depth: usize,
) -> GuardDecision {
    // Redirection targets are file reads/writes regardless of the program.
    for p in &seg.read_redirects {
        let d = classify_path(p, false, policy);
        if !d.allow {
            return d;
        }
    }
    for p in &seg.write_redirects {
        let d = classify_path(p, true, policy);
        if !d.allow {
            return d;
        }
    }

    let words = &seg.words;
    if words.is_empty() {
        return GuardDecision::allow();
    }

    // Strip leading `VAR=value` env assignments; inspect their values too.
    let mut idx = 0;
    while idx < words.len() {
        if let Some((_name, value)) = parse_assignment(&words[idx]) {
            if let Some(d) = scan_value_for_secret_ref(value, policy) {
                return d;
            }
            idx += 1;
        } else {
            break;
        }
    }
    if idx >= words.len() {
        return GuardDecision::allow();
    }

    let prog_raw = &words[idx];
    let prog = basename(prog_raw);
    let args = &words[idx + 1..];

    // Unwrap wrappers (sudo, env, command, exec, timeout N, xargs, ...).
    if let Some((inner_words, recurse_c)) = strip_wrapper(&prog, args) {
        if recurse_c {
            // e.g. `bash -c "<script>"`: the remaining word is a script.
            for script in &inner_words {
                let d = check_command_inner(script, policy, depth + 1);
                if !d.allow {
                    return d;
                }
            }
            return GuardDecision::allow();
        }
        let sub = SimpleCommand {
            words: inner_words,
            read_redirects: Vec::new(),
            write_redirects: Vec::new(),
        };
        return classify_simple_command(&sub, policy, depth);
    }

    // Explicit allow/deny overrides from policy.
    if policy
        .allow_commands
        .iter()
        .any(|c| c.eq_ignore_ascii_case(&prog))
    {
        return GuardDecision::allow();
    }
    if policy
        .deny_commands
        .iter()
        .any(|c| c.eq_ignore_ascii_case(&prog))
    {
        return GuardDecision::deny(
            "deny-command",
            format!("`{prog}` is denied for agents by .envy/policy.toml [guard].deny_commands"),
            "ask a human to run this, or use the equivalent envy command",
        )
        .with_program(prog.clone());
    }

    // Rule order: most specific first.
    if let Some(d) = rule_ssh_remote(&prog, args, policy) {
        return d;
    }
    if let Some(d) = rule_credential_store(&prog, args) {
        return d;
    }
    if let Some(d) = rule_env_dump(&prog, args) {
        return d;
    }
    if let Some(d) = rule_inline_credential(&prog, args) {
        return d;
    }
    if let Some(d) = rule_envy_human_only(&prog, args) {
        return d;
    }
    if let Some(d) = rule_secret_file_command(&prog, prog_raw, args, policy) {
        return d;
    }
    if let Some(d) = rule_var_expansion(args) {
        return d;
    }

    GuardDecision::allow()
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

const SSH_PROGRAMS: &[&str] = &[
    "ssh",
    "scp",
    "sftp",
    "mosh",
    "autossh",
    "sshpass",
    "ssh-copy-id",
    "sshfs",
];

fn rule_ssh_remote(prog: &str, args: &[String], policy: &GuardPolicy) -> Option<GuardDecision> {
    let is_ssh_prog = SSH_PROGRAMS.contains(&prog);
    let is_rsync_remote = prog == "rsync"
        && (args.iter().any(|a| a == "-e" || a.starts_with("--rsh"))
            || args.iter().any(|a| is_remote_target(a)));
    if !is_ssh_prog && !is_rsync_remote {
        return None;
    }

    // sshpass just wraps the real ssh; its own target is in the wrapped args.
    let host = extract_ssh_host(args);

    match host {
        Some(h) => {
            if host_is_allowed(&h, policy) {
                return None;
            }
            Some(
                GuardDecision::deny(
                    "ssh-remote",
                    format!(
                        "direct `{prog}` to '{h}' is blocked: agents must not open their own \
                         SSH session into a server (keys and host trust live in envy's vault)"
                    ),
                    format!(
                        "register the host once (human: `envy ssh add <profile>` + \
                         `envy ssh trust <profile>`), then run `envy ssh exec <profile> -- <cmd>` \
                         or the `mcp__envy__ssh_exec` tool"
                    ),
                )
                .with_program(prog.to_string())
                .with_target(h),
            )
        }
        None => Some(
            GuardDecision::deny(
                "ssh-remote",
                format!("direct `{prog}` is blocked for agents (no recognizable host parsed)"),
                "use `envy ssh exec <profile> -- <cmd>` or the `mcp__envy__ssh_exec` tool",
            )
            .with_program(prog.to_string()),
        ),
    }
}

fn rule_credential_store(prog: &str, args: &[String]) -> Option<GuardDecision> {
    let joined = args.join(" ");
    let lower = joined.to_ascii_lowercase();
    let hit = match prog {
        // macOS keychain — this is where envy's *own* vault key lives.
        "security" => args
            .iter()
            .any(|a| a.starts_with("find-") && a.contains("password")),
        "secret-tool" => args.first().map(|a| a == "lookup").unwrap_or(false),
        "gh" => lower.contains("auth") && lower.contains("token"),
        "git" => {
            (args.first().map(|a| a == "credential").unwrap_or(false))
                || (args.first().map(|a| a == "config").unwrap_or(false)
                    && (lower.contains("credential")
                        || lower.contains("token")
                        || lower.contains("password")))
        }
        "aws" => args.first().map(|a| a == "configure").unwrap_or(false) && lower.contains("get"),
        "op" => args
            .first()
            .map(|a| a == "read" || a == "get")
            .unwrap_or(false),
        "gcloud" => lower.contains("print-access-token") || lower.contains("print-identity-token"),
        "az" => lower.contains("get-access-token"),
        "pass" => !args.is_empty() && args[0] != "init",
        "cat" | "bat" | "less" | "head" | "tail" => false, // handled by secret-file
        _ => false,
    };
    if !hit {
        return None;
    }
    Some(
        GuardDecision::deny(
            "credential-store",
            format!("`{prog} {joined}` reads a secret out of a credential store/keychain"),
            "ask envy for the credential instead: `envy check`/`envy run`, or the \
             `mcp__envy__make_authenticated_request` / `mcp__envy__check_credential` tools",
        )
        .with_program(prog.to_string()),
    )
}

fn rule_env_dump(prog: &str, args: &[String]) -> Option<GuardDecision> {
    let dump = match prog {
        "printenv" => true,
        // bare `env` (no command to run after it) dumps the environment.
        "env" => args
            .iter()
            .all(|a| a.starts_with('-') || a.contains('=') || a.is_empty()),
        "export" => args.iter().any(|a| a == "-p") || args.is_empty(),
        "set" => args.is_empty(),
        "declare" => args.iter().any(|a| a == "-x" || a == "-p"),
        "typeset" => args.iter().any(|a| a == "-x" || a == "-p"),
        _ => false,
    };
    if !dump {
        return None;
    }
    Some(
        GuardDecision::deny(
            "env-dump",
            format!("`{prog}` dumps the process environment, which can expose injected secrets"),
            "read a specific, non-secret variable by name, or get credentials via \
             `envy run -- <cmd>` which injects them into the child only",
        )
        .with_program(prog.to_string()),
    )
}

fn rule_inline_credential(prog: &str, args: &[String]) -> Option<GuardDecision> {
    if !matches!(prog, "curl" | "wget" | "http" | "https" | "httpie") {
        return None;
    }
    let joined = args.join(" ");
    let lower = joined.to_ascii_lowercase();

    let has_auth_header = lower.contains("authorization:")
        || lower.contains("x-api-key:")
        || lower.contains("x-auth-token:")
        || lower.contains("proxy-authorization:");
    let has_basic = args.iter().any(|a| a == "-u" || a == "--user")
        || args
            .iter()
            .any(|a| a.contains('@') && (a.contains("://")) && a.contains(':'));
    let has_token_qs = lower.contains("access_token=")
        || lower.contains("api_key=")
        || lower.contains("apikey=")
        || lower.contains("token=");

    if !(has_auth_header || has_basic || has_token_qs) {
        return None;
    }
    Some(
        GuardDecision::deny(
            "inline-credential",
            format!(
                "`{prog}` is being given an inline credential (auth header, user:pass, or token \
                 query param) — this hard-codes/leaks a secret into argv and logs"
            ),
            "use `mcp__envy__make_authenticated_request` (or `envy check`) so envy injects the \
             credential without it touching the command line",
        )
        .with_program(prog.to_string()),
    )
}

fn rule_envy_human_only(prog: &str, args: &[String]) -> Option<GuardDecision> {
    if basename(prog) != "envy" {
        return None;
    }
    let sub = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(|s| s.as_str())
        .unwrap_or("");
    let human_only = match sub {
        "consent" => true,
        "export" => args.iter().any(|a| a == "--env" || a == "--example"),
        _ => false,
    };
    if !human_only {
        return None;
    }
    Some(
        GuardDecision::deny(
            "envy-human-only",
            format!("`envy {sub}` grants consent or writes raw secrets — human-only"),
            "a human must run this; an agent should request access via the envy MCP tools",
        )
        .with_program("envy".to_string()),
    )
}

/// Programs that only inspect metadata (not content) and are exempt from the
/// secret-file rule.
const METADATA_ONLY: &[&str] = &[
    "ls", "stat", "test", "[", "du", "realpath", "readlink", "dirname", "basename", "file", "find",
    "wc", "touch", "chmod", "chown", "mkdir",
];

fn rule_secret_file_command(
    prog: &str,
    prog_raw: &str,
    args: &[String],
    policy: &GuardPolicy,
) -> Option<GuardDecision> {
    // envy reading its own vault is fine; metadata-only tools are exempt.
    if basename(prog) == "envy" || METADATA_ONLY.contains(&prog) {
        return None;
    }
    // `cp`/`mv`/`tee`/`sed -i`/`dd` that *write* a protected config file are
    // caught as write targets below; here we focus on content reads.
    let _ = prog_raw;
    for a in args {
        if a.starts_with('-') && !a.contains('/') && !a.contains(".env") {
            continue; // flag, not a path
        }
        // Strip `--env-file=` style.
        let candidate = a.rsplit('=').next().unwrap_or(a);
        let d = classify_path(candidate, false, policy);
        if !d.allow {
            return Some(d.with_program(prog.to_string()));
        }
    }
    None
}

const SECRET_VAR_HINTS: &[&str] = &[
    "KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "DATABASE_URL",
    "DB_URL",
    "PRIVATE",
    "APIKEY",
    "API_KEY",
    "ACCESS_KEY",
];

fn rule_var_expansion(args: &[String]) -> Option<GuardDecision> {
    for a in args {
        if let Some(d) = scan_value_for_secret_ref(a, &GuardPolicy::default()) {
            // Only flag the var-expansion form here (not file refs, which the
            // secret-file rule already covers).
            if d.rule == Some("env-dump") {
                return Some(d);
            }
        }
    }
    None
}

/// Scans an assignment value / argument for `$SECRET`-style expansion of a
/// secret-looking variable, or a reference to a secret file.
fn scan_value_for_secret_ref(value: &str, policy: &GuardPolicy) -> Option<GuardDecision> {
    // $VAR or ${VAR}
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            let rest = &value[i + 1..];
            let name: String = if rest.starts_with('{') {
                rest[1..]
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect()
            } else {
                rest.chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect()
            };
            let upper = name.to_ascii_uppercase();
            if !upper.is_empty()
                && SECRET_VAR_HINTS
                    .iter()
                    .any(|h| upper == *h || upper.contains(h))
            {
                return Some(
                    GuardDecision::deny(
                        "env-dump",
                        format!("expanding `${name}` can echo an injected secret into argv/output"),
                        "don't print secret-valued variables; let envy inject them into the child \
                         process env via `envy run -- <cmd>`",
                    )
                    .with_target(name),
                );
            }
        }
        i += 1;
    }
    // A secret file referenced as a value.
    let d = classify_path(value, false, policy);
    if !d.allow {
        return Some(d);
    }
    None
}

// ---------------------------------------------------------------------------
// Path classification
// ---------------------------------------------------------------------------

fn classify_path(raw: &str, write: bool, policy: &GuardPolicy) -> GuardDecision {
    if raw.is_empty() {
        return GuardDecision::allow();
    }
    let expanded = expand_home(raw.trim_matches(|c| c == '"' || c == '\''));
    let norm = expanded.replace('\\', "/");
    let lower = norm.to_ascii_lowercase();
    let base = basename(&norm);
    let lbase = base.to_ascii_lowercase();

    // Explicit allow overrides (read side only).
    if !write && policy.allow_paths.iter().any(|p| path_matches(&norm, p)) {
        return GuardDecision::allow();
    }

    // Protected-config writes: .envy/**, .claude/settings*.json, .cursor/hooks.json.
    let is_envy_dir = lower.contains("/.envy/")
        || lower.starts_with(".envy/")
        || lbase == "policy.toml" && lower.contains(".envy")
        || lower.ends_with("/.envy")
        || norm == ".envy";
    let is_claude_settings = (lower.contains("/.claude/") || lower.starts_with(".claude/"))
        && lbase.starts_with("settings")
        && lbase.ends_with(".json");
    let is_cursor_hooks =
        (lower.contains("/.cursor/") || lower.starts_with(".cursor/")) && lbase == "hooks.json";

    if write && (is_envy_dir || is_claude_settings || is_cursor_hooks) {
        return GuardDecision::deny(
            "protected-config",
            format!(
                "writing '{base}' would tamper with envy's own vault/policy or the agent \
                     governance hooks"
            ),
            "a human must change governance config; agents must not edit .envy/, \
             .claude/settings*.json, or .cursor/hooks.json",
        )
        .with_target(base.clone());
    }
    // Reading the vault DB / policy directly (bypasses the keyed vault API).
    if !write && (lower.ends_with("/.envy/vault.db") || lbase == "vault.db") {
        return GuardDecision::deny(
            "secret-file",
            "reading the vault database directly bypasses envy's encryption/trust boundary",
            "use `envy show`/`envy list` or the envy MCP tools to access vault data",
        )
        .with_target(base.clone());
    }

    // Extra deny paths from policy.
    if policy.deny_paths.iter().any(|p| path_matches(&norm, p)) {
        return deny_secret_file(&base);
    }

    // .env family (but not .env.example/.sample/.template/.dist).
    if is_dotenv(&lbase) {
        return deny_secret_file(&base);
    }

    // SSH private material.
    let in_ssh_dir = lower.contains("/.ssh/") || lower.starts_with(".ssh/");
    if in_ssh_dir {
        let allowed = lbase.ends_with(".pub")
            || lbase == "known_hosts"
            || lbase == "known_hosts2"
            || lbase == "config"
            || lbase == "authorized_keys";
        if !allowed {
            return deny_secret_file(&base);
        }
    }
    // id_* private keys anywhere.
    if (lbase.starts_with("id_") || lbase.starts_with("identity")) && !lbase.ends_with(".pub") {
        return deny_secret_file(&base);
    }

    // Other well-known credential files.
    if is_known_credential_file(&lower, &lbase) {
        return deny_secret_file(&base);
    }

    // Cloud/env secret extensions.
    if lbase.ends_with(".pem")
        || lbase.ends_with(".key")
        || lbase.ends_with(".p12")
        || lbase.ends_with(".pfx")
        || lbase.ends_with(".keystore")
        || lbase.ends_with(".jks")
    {
        // A public .key is rare; treat as secret to be safe.
        return deny_secret_file(&base);
    }

    // /proc/*/environ dumps.
    if lower.starts_with("/proc/") && lower.ends_with("/environ") {
        return GuardDecision::deny(
            "env-dump",
            "reading /proc/<pid>/environ exposes another process's environment (secrets)",
            "don't read process environments; request credentials via the envy MCP tools",
        )
        .with_target("environ".to_string());
    }

    GuardDecision::allow()
}

fn deny_secret_file(base: &str) -> GuardDecision {
    GuardDecision::deny(
        "secret-file",
        format!(
            "reading '{base}' would expose raw credentials (envy keeps these encrypted in its vault)"
        ),
        "don't read secret files directly — use `envy run -- <cmd>` to inject secrets, or the \
         `mcp__envy__make_authenticated_request` / `mcp__envy__check_credential` tools",
    )
    .with_target(base.to_string())
}

fn is_dotenv(lbase: &str) -> bool {
    if lbase == ".env" {
        return true;
    }
    if let Some(suffix) = lbase.strip_prefix(".env.") {
        // Allow template/example variants.
        return !matches!(
            suffix,
            "example" | "sample" | "template" | "dist" | "defaults"
        );
    }
    false
}

fn is_known_credential_file(lower: &str, lbase: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        "/.aws/credentials",
        "/.aws/config",
        "/.netrc",
        "/.git-credentials",
        "/.docker/config.json",
        "/.kube/config",
        "/.config/gh/hosts.yml",
        "/.pgpass",
        "/.npmrc",
        "/.pypirc",
        "/.config/gcloud/credentials.db",
        "/.config/gcloud/application_default_credentials.json",
    ];
    if SUFFIXES.iter().any(|s| lower.ends_with(s)) {
        return true;
    }
    matches!(
        lbase,
        ".netrc" | ".git-credentials" | ".pgpass" | ".npmrc" | ".pypirc"
    ) || (lbase == "credentials" && lower.contains("/.aws/"))
}

// ---------------------------------------------------------------------------
// Shell parsing helpers
// ---------------------------------------------------------------------------

/// Extracts the inner text of every `$( )`, backtick, `<( )`, `>( )`.
fn extract_substitutions(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    let mut in_single = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' && !in_single {
            // single quotes suppress $() and backticks
            in_single = true;
            i += 1;
            continue;
        }
        if c == '\'' && in_single {
            in_single = false;
            i += 1;
            continue;
        }
        if in_single {
            i += 1;
            continue;
        }
        // $( ... )  and  <( ... )  and  >( ... )
        if (c == '$' && i + 1 < chars.len() && chars[i + 1] == '(')
            || ((c == '<' || c == '>') && i + 1 < chars.len() && chars[i + 1] == '(')
        {
            let start = if c == '$' { i + 2 } else { i + 2 };
            let mut depth = 1;
            let mut j = start;
            while j < chars.len() && depth > 0 {
                match chars[j] {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    break;
                }
                j += 1;
            }
            let inner: String = chars[start..j.min(chars.len())].iter().collect();
            if !inner.trim().is_empty() {
                out.push(inner);
            }
            i = j + 1;
            continue;
        }
        // backticks
        if c == '`' {
            let start = i + 1;
            let mut j = start;
            while j < chars.len() && chars[j] != '`' {
                j += 1;
            }
            let inner: String = chars[start..j.min(chars.len())].iter().collect();
            if !inner.trim().is_empty() {
                out.push(inner);
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    out
}

/// Splits a command line into simple commands at top-level `; && || | &`
/// and newlines, with substitutions blanked out so they don't break parsing.
/// Also records redirection targets.
fn split_simple_commands(input: &str) -> Vec<SimpleCommand> {
    let blanked = blank_substitutions(input);
    let tokens = lex(&blanked);

    let mut out = Vec::new();
    let mut cur = SimpleCommand {
        words: Vec::new(),
        read_redirects: Vec::new(),
        write_redirects: Vec::new(),
    };
    let mut pending_redirect: Option<bool> = None; // Some(write) => next word is target

    for tok in tokens {
        match tok {
            Token::Op(op) => {
                if op == ";" || op == "&&" || op == "||" || op == "|" || op == "&" || op == "\n" {
                    if !cur.words.is_empty()
                        || !cur.read_redirects.is_empty()
                        || !cur.write_redirects.is_empty()
                    {
                        out.push(std::mem::replace(
                            &mut cur,
                            SimpleCommand {
                                words: Vec::new(),
                                read_redirects: Vec::new(),
                                write_redirects: Vec::new(),
                            },
                        ));
                    }
                    pending_redirect = None;
                } else if op.starts_with('>') {
                    pending_redirect = Some(true);
                } else if op.starts_with('<') {
                    pending_redirect = Some(false);
                }
                // '(' and ')' are ignored for grouping purposes.
            }
            Token::Word(w) => {
                if let Some(write) = pending_redirect.take() {
                    if write {
                        cur.write_redirects.push(w);
                    } else {
                        cur.read_redirects.push(w);
                    }
                } else {
                    cur.words.push(w);
                }
            }
        }
    }
    if !cur.words.is_empty() || !cur.read_redirects.is_empty() || !cur.write_redirects.is_empty() {
        out.push(cur);
    }
    out
}

/// Replaces `$( )`, backticks, `<( )`, `>( )` content with spaces (keeping
/// length-ish) so the lexer doesn't choke on operators inside them. The inner
/// commands are handled separately by [`extract_substitutions`].
fn blank_substitutions(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' && !in_double {
            in_single = !in_single;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '"' && !in_single {
            in_double = !in_double;
            out.push(c);
            i += 1;
            continue;
        }
        if !in_single
            && ((c == '$' && i + 1 < chars.len() && chars[i + 1] == '(')
                || ((c == '<' || c == '>') && i + 1 < chars.len() && chars[i + 1] == '('))
        {
            let start = if c == '$' { i + 2 } else { i + 2 };
            let mut depth = 1;
            let mut j = start;
            while j < chars.len() && depth > 0 {
                match chars[j] {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    break;
                }
                j += 1;
            }
            out.push(' ');
            i = j + 1;
            continue;
        }
        if !in_single && c == '`' {
            let mut j = i + 1;
            while j < chars.len() && chars[j] != '`' {
                j += 1;
            }
            out.push(' ');
            i = j + 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    Op(String),
}

/// A pragmatic POSIX-ish lexer: honors single/double quotes and backslash,
/// and emits operator tokens for `; && || | & ( ) < > >> <<` and newlines.
fn lex(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    let mut has_word = false;

    macro_rules! flush {
        () => {
            if has_word {
                tokens.push(Token::Word(std::mem::take(&mut cur)));
                has_word = false;
            }
        };
    }

    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' => {
                has_word = true;
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    cur.push(chars[i]);
                    i += 1;
                }
                i += 1; // closing quote
            }
            '"' => {
                has_word = true;
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        cur.push(chars[i + 1]);
                        i += 2;
                    } else {
                        cur.push(chars[i]);
                        i += 1;
                    }
                }
                i += 1;
            }
            '\\' => {
                if i + 1 < chars.len() {
                    cur.push(chars[i + 1]);
                    has_word = true;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            ' ' | '\t' | '\r' => {
                flush!();
                i += 1;
            }
            '\n' => {
                flush!();
                tokens.push(Token::Op("\n".to_string()));
                i += 1;
            }
            ';' => {
                flush!();
                tokens.push(Token::Op(";".to_string()));
                i += 1;
            }
            '|' => {
                flush!();
                if i + 1 < chars.len() && chars[i + 1] == '|' {
                    tokens.push(Token::Op("||".to_string()));
                    i += 2;
                } else {
                    tokens.push(Token::Op("|".to_string()));
                    i += 1;
                }
            }
            '&' => {
                flush!();
                if i + 1 < chars.len() && chars[i + 1] == '&' {
                    tokens.push(Token::Op("&&".to_string()));
                    i += 2;
                } else {
                    tokens.push(Token::Op("&".to_string()));
                    i += 1;
                }
            }
            '>' => {
                flush!();
                if i + 1 < chars.len() && chars[i + 1] == '>' {
                    tokens.push(Token::Op(">>".to_string()));
                    i += 2;
                } else {
                    tokens.push(Token::Op(">".to_string()));
                    i += 1;
                }
            }
            '<' => {
                flush!();
                if i + 1 < chars.len() && chars[i + 1] == '<' {
                    tokens.push(Token::Op("<<".to_string()));
                    i += 2;
                } else {
                    tokens.push(Token::Op("<".to_string()));
                    i += 1;
                }
            }
            '(' => {
                flush!();
                tokens.push(Token::Op("(".to_string()));
                i += 1;
            }
            ')' => {
                flush!();
                tokens.push(Token::Op(")".to_string()));
                i += 1;
            }
            _ => {
                cur.push(c);
                has_word = true;
                i += 1;
            }
        }
    }
    if has_word {
        tokens.push(Token::Word(cur));
    }
    tokens
}

/// Wrapper programs whose *real* command is in their trailing args.
/// Returns the remaining words to re-classify, and whether the remainder is a
/// `-c` script string to recurse into as a whole command.
fn strip_wrapper(prog: &str, args: &[String]) -> Option<(Vec<String>, bool)> {
    match prog {
        "sudo" | "doas" => {
            // Skip sudo options and VAR=val, find the real command.
            let mut idx = 0;
            while idx < args.len() {
                let a = &args[idx];
                if a == "-u" || a == "-g" || a == "-U" || a == "-p" || a == "-C" {
                    idx += 2;
                } else if a.starts_with('-') || parse_assignment(a).is_some() {
                    idx += 1;
                } else {
                    break;
                }
            }
            Some((args[idx..].to_vec(), false))
        }
        "env" => {
            // `env VAR=val cmd ...` — skip options and assignments.
            let mut idx = 0;
            while idx < args.len() {
                let a = &args[idx];
                if a == "-i" || a == "--ignore-environment" || a == "-0" {
                    idx += 1;
                } else if a == "-u" || a == "-C" {
                    idx += 2;
                } else if parse_assignment(a).is_some() {
                    idx += 1;
                } else {
                    break;
                }
            }
            if idx >= args.len() {
                None // bare env dump — handled by env-dump rule
            } else {
                Some((args[idx..].to_vec(), false))
            }
        }
        "nohup" | "command" | "exec" | "stdbuf" | "nice" | "ionice" | "setsid" => {
            // Skip their own options, re-classify the rest.
            let mut idx = 0;
            while idx < args.len() && args[idx].starts_with('-') {
                idx += 1;
            }
            if idx >= args.len() {
                None
            } else {
                Some((args[idx..].to_vec(), false))
            }
        }
        "timeout" => {
            // timeout [opts] DURATION cmd...
            let mut idx = 0;
            while idx < args.len() && args[idx].starts_with('-') {
                if args[idx] == "-s" || args[idx] == "--signal" || args[idx] == "-k" {
                    idx += 2;
                } else {
                    idx += 1;
                }
            }
            idx += 1; // the DURATION
            if idx >= args.len() {
                None
            } else {
                Some((args[idx..].to_vec(), false))
            }
        }
        "xargs" => {
            // xargs [opts] cmd ... — re-classify the cmd part.
            let mut idx = 0;
            while idx < args.len() && args[idx].starts_with('-') {
                if matches!(args[idx].as_str(), "-I" | "-n" | "-P" | "-d" | "-E" | "-s") {
                    idx += 2;
                } else {
                    idx += 1;
                }
            }
            if idx >= args.len() {
                None
            } else {
                Some((args[idx..].to_vec(), false))
            }
        }
        "bash" | "sh" | "zsh" | "dash" | "ksh" | "ash" => {
            // Find a -c argument; its value is a whole script to recurse on.
            for (k, a) in args.iter().enumerate() {
                if a == "-c" {
                    if let Some(script) = args.get(k + 1) {
                        return Some((vec![script.clone()], true));
                    }
                }
            }
            None
        }
        "eval" => {
            // eval joins its args into a command string.
            Some((vec![args.join(" ")], true))
        }
        "sshpass" => {
            // sshpass [opts] <ssh-command...> — re-classify the wrapped command.
            let mut idx = 0;
            while idx < args.len() {
                let a = &args[idx];
                if a == "-p" || a == "-f" || a == "-d" || a == "-e" {
                    // -p/-f/-d take a value; -e does not.
                    if a == "-e" {
                        idx += 1;
                    } else {
                        idx += 2;
                    }
                } else if a.starts_with('-') {
                    idx += 1;
                } else {
                    break;
                }
            }
            if idx >= args.len() {
                None
            } else {
                Some((args[idx..].to_vec(), false))
            }
        }
        _ => None,
    }
}

fn parse_assignment(word: &str) -> Option<(&str, &str)> {
    let eq = word.find('=')?;
    let name = &word[..eq];
    if name.is_empty() {
        return None;
    }
    let mut chars = name.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some((name, &word[eq + 1..]))
}

fn basename(path: &str) -> String {
    let trimmed = path.trim_matches(|c| c == '"' || c == '\'');
    let p = trimmed.replace('\\', "/");
    p.rsplit('/').next().unwrap_or(&p).to_string()
}

fn expand_home(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        return format!("~HOME/{rest}");
    }
    let p = path.replace("${HOME}", "~HOME").replace("$HOME", "~HOME");
    p
}

/// Whether an rsync-style `host:path` or `user@host:path` target is remote.
fn is_remote_target(arg: &str) -> bool {
    if arg.starts_with('-') {
        return false;
    }
    // A Windows drive letter like C:\ is not a remote target.
    if let Some(colon) = arg.find(':') {
        let before = &arg[..colon];
        if before.is_empty() || before.contains('/') {
            return false;
        }
        if before.len() == 1 {
            return false; // drive letter
        }
        return true;
    }
    false
}

/// Parses the destination host from an ssh/scp/sftp-style argv.
fn extract_ssh_host(args: &[String]) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            continue;
        }
        if a.starts_with('-') {
            // Options that take a value.
            let takes_value = matches!(
                a.as_str(),
                "-p" | "-i"
                    | "-o"
                    | "-F"
                    | "-l"
                    | "-c"
                    | "-m"
                    | "-b"
                    | "-D"
                    | "-L"
                    | "-R"
                    | "-W"
                    | "-e"
                    | "-J"
                    | "-E"
                    | "-Q"
                    | "-O"
                    | "-P"
                    | "-S"
            );
            if takes_value && !a.contains('=') {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        // First non-option token is the destination (or an rsync src/dst).
        return parse_host_token(a);
    }
    None
}

fn parse_host_token(tok: &str) -> Option<String> {
    // ssh://user@host:port/...
    let t = tok.strip_prefix("ssh://").unwrap_or(tok);
    // user@host[:path]  or  host:path  (scp/rsync) or bare host (ssh)
    let after_at = t.rsplit('@').next().unwrap_or(t);
    // strip :path or :port
    let host = after_at.split(['/', ':']).next().unwrap_or(after_at);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn host_is_allowed(host: &str, policy: &GuardPolicy) -> bool {
    let h = host.to_ascii_lowercase();
    policy.allow_ssh_hosts.iter().any(|allowed| {
        let a = allowed.to_ascii_lowercase();
        h == a || h.ends_with(&format!(".{a}"))
    })
}

/// Very small glob/prefix matcher for allow_paths/deny_paths.
fn path_matches(path: &str, pattern: &str) -> bool {
    let path = path.trim_matches(|c| c == '"' || c == '\'');
    let pat = expand_home(pattern);
    let path = expand_home(path);
    if pat.contains('*') {
        glob_match(&pat, &path)
    } else {
        path == pat || path.ends_with(&pat) || path.starts_with(&pat)
    }
}

fn glob_match(pattern: &str, text: &str) -> bool {
    // Supports '*' (any run, incl. '/') only — adequate for path rules.
    fn helper(p: &[char], t: &[char]) -> bool {
        if p.is_empty() {
            return t.is_empty();
        }
        if p[0] == '*' {
            if helper(&p[1..], t) {
                return true;
            }
            if !t.is_empty() {
                return helper(p, &t[1..]);
            }
            return false;
        }
        if t.is_empty() {
            return false;
        }
        if p[0] == '?' || p[0] == t[0] {
            return helper(&p[1..], &t[1..]);
        }
        false
    }
    let pc: Vec<char> = pattern.chars().collect();
    let tc: Vec<char> = text.chars().collect();
    helper(&pc, &tc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pol() -> GuardPolicy {
        GuardPolicy::default()
    }

    fn denied(cmd: &str) -> GuardDecision {
        check_command(cmd, &pol())
    }

    #[test]
    fn allows_ordinary_commands() {
        for c in [
            "ls -la",
            "cargo build",
            "git status",
            "echo hello world",
            "grep -r TODO src/",
            "cat README.md",
            "python main.py",
            "npm install",
            "docker ps",
        ] {
            assert!(check_command(c, &pol()).allow, "should allow: {c}");
        }
    }

    #[test]
    fn blocks_raw_ssh() {
        let d = denied("ssh root@1.2.3.4");
        assert!(!d.allow);
        assert_eq!(d.rule, Some("ssh-remote"));
        assert!(denied("ssh -p 2222 user@vps.example.com uptime").allow == false);
        assert!(!denied("scp file.txt deploy@host:/tmp/").allow);
        assert!(!denied("sftp admin@server").allow);
        assert!(!denied("rsync -avz ./ user@host:/srv/").allow);
        assert!(!denied("sshpass -p pw ssh user@host").allow);
    }

    #[test]
    fn allows_ssh_to_git_forges() {
        assert!(denied("ssh -T git@github.com").allow);
        assert!(denied("ssh git@gitlab.com").allow);
        assert!(denied("git clone git@github.com:owner/repo.git").allow);
    }

    #[test]
    fn blocks_env_file_reads() {
        for c in [
            "cat .env",
            "cat ./.env",
            "head -n5 config/.env.production",
            "less .env.local",
            "cat \"/app/.env\"",
            "grep SECRET .env",
            "bat .env",
        ] {
            let d = denied(c);
            assert!(!d.allow, "should block: {c}");
            assert_eq!(d.rule, Some("secret-file"), "cmd: {c}");
        }
    }

    #[test]
    fn allows_env_example() {
        assert!(denied("cat .env.example").allow);
        assert!(denied("cat .env.sample").allow);
        assert!(denied("cp .env.example .env.local").allow == false); // writes .env.local target? no, cp args are reads here
    }

    #[test]
    fn blocks_ssh_key_reads() {
        assert!(!denied("cat ~/.ssh/id_rsa").allow);
        assert!(!denied("cat ~/.ssh/id_ed25519").allow);
        assert!(!denied("cat /home/user/.ssh/id_rsa").allow);
        assert!(denied("cat ~/.ssh/id_rsa.pub").allow);
        assert!(denied("cat ~/.ssh/known_hosts").allow);
        assert!(denied("cat ~/.ssh/config").allow);
    }

    #[test]
    fn blocks_env_dump() {
        assert!(!denied("printenv").allow);
        assert!(!denied("env").allow);
        assert!(!denied("export -p").allow);
        assert!(!denied("printenv API_KEY").allow);
        // `env cmd ...` is NOT a dump — it runs cmd.
        assert!(denied("env FOO=bar ls").allow);
    }

    #[test]
    fn blocks_credential_stores() {
        assert!(!denied("security find-generic-password -s envy").allow);
        assert!(!denied("gh auth token").allow);
        assert!(!denied("git credential fill").allow);
        assert!(!denied("aws configure get aws_secret_access_key").allow);
        assert!(!denied("gcloud auth print-access-token").allow);
        assert!(!denied("secret-tool lookup service foo").allow);
    }

    #[test]
    fn blocks_inline_credentials() {
        assert!(!denied("curl -H 'Authorization: Bearer abc' https://api.example.com").allow);
        assert!(!denied("curl -u admin:secret https://api.example.com").allow);
        assert!(!denied("curl https://api.example.com?access_token=xyz").allow);
        assert!(denied("curl https://api.example.com/health").allow);
    }

    #[test]
    fn blocks_chained_and_substituted() {
        assert!(!denied("ls && cat .env").allow);
        assert!(!denied("echo hi; ssh root@host").allow);
        assert!(!denied("cat .env | grep KEY").allow);
        assert!(!denied("echo $(cat .env)").allow);
        assert!(!denied("echo `cat ~/.ssh/id_rsa`").allow);
        assert!(!denied("bash -c 'cat .env'").allow);
        assert!(!denied("sh -c \"printenv\"").allow);
        assert!(!denied("sudo cat /root/.ssh/id_rsa").allow);
        assert!(!denied("timeout 5 ssh user@host").allow);
    }

    #[test]
    fn blocks_var_expansion_of_secrets() {
        assert!(!denied("echo $API_KEY").allow);
        assert!(!denied("echo ${DATABASE_URL}").allow);
        assert!(denied("echo $HOME").allow);
        assert!(denied("echo $PATH").allow);
    }

    #[test]
    fn blocks_envy_human_only() {
        assert!(!denied("envy consent grant stripe write").allow);
        assert!(!denied("envy export --env").allow);
        assert!(denied("envy run -- node app.js").allow);
        assert!(denied("envy check API_KEY").allow);
    }

    #[test]
    fn redirect_targets_checked() {
        assert!(!denied("cat < .env").allow);
        assert!(!denied("echo pwned > ~/.ssh/id_rsa").allow);
    }

    #[test]
    fn path_check_protected_config() {
        assert!(!check_path(".envy/policy.toml", true, &pol()).allow);
        assert!(!check_path(".claude/settings.json", true, &pol()).allow);
        assert!(!check_path(".cursor/hooks.json", true, &pol()).allow);
        // Reading vault.db directly is blocked.
        assert!(!check_path(".envy/vault.db", false, &pol()).allow);
    }

    #[test]
    fn path_check_credential_files() {
        assert!(!check_path("/home/u/.aws/credentials", false, &pol()).allow);
        assert!(!check_path("~/.netrc", false, &pol()).allow);
        assert!(!check_path("~/.git-credentials", false, &pol()).allow);
        assert!(!check_path("server.pem", false, &pol()).allow);
    }

    #[test]
    fn policy_allow_override() {
        let mut p = pol();
        p.allow_paths.push(".env".to_string());
        assert!(check_path(".env", false, &p).allow);
    }

    #[test]
    fn policy_allow_ssh_host() {
        let mut p = pol();
        p.allow_ssh_hosts.push("vps.example.com".to_string());
        assert!(check_command("ssh deploy@vps.example.com uptime", &p).allow);
    }

    #[test]
    fn disabled_allows_everything() {
        let mut p = pol();
        p.enabled = false;
        assert!(check_command("cat .env", &p).allow);
        assert!(check_command("ssh root@host", &p).allow);
    }

    #[test]
    fn classify_tool_call_maps_tools() {
        let bash = serde_json::json!({"command": "cat .env"});
        assert!(!classify_tool_call("Bash", &bash, &pol()).allow);

        let read = serde_json::json!({"file_path": "/app/.env"});
        assert!(!classify_tool_call("Read", &read, &pol()).allow);

        let ok = serde_json::json!({"file_path": "/app/src/main.rs"});
        assert!(classify_tool_call("Read", &ok, &pol()).allow);

        // envy's own MCP tools are always allowed.
        let envy = serde_json::json!({"command": "cat .env"});
        assert!(classify_tool_call("mcp__envy__make_authenticated_request", &envy, &pol()).allow);
    }

    #[test]
    fn audit_summary_has_no_full_command() {
        let d = denied("curl -H 'Authorization: Bearer supersecrettoken' https://x.com");
        assert!(!d.allow);
        let s = d.audit_summary();
        assert!(!s.contains("supersecrettoken"), "summary leaked token: {s}");
    }

    #[test]
    fn deny_command_override() {
        let mut p = pol();
        p.deny_commands.push("wget".to_string());
        assert!(!check_command("wget https://example.com/x", &p).allow);
    }
}
