//! Policy evaluation and governance rules (FR-10).
//!
//! Evaluates capability and infrastructure requests against declarative project policies
//! (`.envy/policy.toml`), agent identities, and active consent grants.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::error::CoreError;

/// Declarative project policy file loaded from `<project>/.envy/policy.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectPolicy {
    #[serde(default)]
    pub default: DefaultPolicy,
    #[serde(default)]
    pub agents: HashMap<String, AgentPolicy>,
    #[serde(default)]
    pub hosts: HashMap<String, HostPolicy>,
    /// Agent-side command/file-access governance. See `crate::guard`.
    #[serde(default)]
    pub guard: crate::guard::GuardPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultPolicy {
    #[serde(default = "default_deny")]
    pub access: String, // "allow" or "deny"
    #[serde(default = "default_true")]
    pub require_consent_for_write: bool,
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        // Fail closed (M0 / G6): with no `.envy/policy.toml`, anything that
        // consults `default.access` is denied. This matches the serde default.
        Self {
            access: "deny".to_string(),
            require_consent_for_write: true,
        }
    }
}

fn default_deny() -> String {
    "deny".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentQuotas {
    /// Maximum allowed capability requests per hour (default: unlimited).
    pub max_requests_per_hour: Option<i64>,
    /// Maximum outbound payload or response size in bytes.
    pub max_payload_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPolicy {
    #[serde(default)]
    pub allowed_providers: Vec<String>,
    #[serde(default = "default_true")]
    pub allow_read_only: bool,
    #[serde(default)]
    pub allow_write_with_consent: bool,
    #[serde(default)]
    pub quotas: Option<AgentQuotas>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostPolicy {
    #[serde(default)]
    pub allowed_commands: Vec<String>,
    #[serde(default = "default_true")]
    pub known_host_required: bool,
}

/// A capability request to evaluate against policy.
pub struct PolicyRequest<'a> {
    pub operation: &'a str,
    pub provider: Option<&'a str>,
    pub domain: Option<&'a str>,
    pub agent_identity: Option<&'a str>,
    pub method: &'a str,
    pub command: Option<&'a str>,
    /// Whether the caller already holds an active `envy consent grant`.
    pub has_active_consent: bool,
    /// Recent request count in the last hour for quota evaluation.
    pub recent_request_count: Option<i64>,
    /// Outbound payload size in bytes for quota evaluation.
    pub payload_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    RequireConsent { reason: String },
    Deny { reason: String },
}

/// Loads the project policy file from `<project_root>/.envy/policy.toml` if present.
pub fn load_policy(project_root: &Path) -> Result<ProjectPolicy, CoreError> {
    let policy_path = project_root.join(".envy").join("policy.toml");
    if !policy_path.exists() {
        return Ok(ProjectPolicy::default());
    }

    let text = std::fs::read_to_string(&policy_path).map_err(|e| CoreError::Io {
        path: policy_path.clone(),
        source: e,
    })?;

    toml::from_str(&text)
        .map_err(|e| CoreError::InvalidRequest(format!("invalid policy.toml: {e}")))
}

/// Evaluates a request against configured project policy and active consent grants.
pub fn evaluate_with_policy(request: &PolicyRequest, policy: &ProjectPolicy) -> PolicyDecision {
    // SSH entry points (exec / connect / tunnel / agent sign) have their own
    // fail-closed evaluator.
    if request.operation.starts_with("ssh_") {
        return evaluate_ssh(request, policy);
    }

    // 1. Agent-specific checks if agent_identity is provided
    if let Some(agent_id) = request.agent_identity {
        if let Some(agent_policy) = policy.agents.get(agent_id) {
            // Check provider restrictions
            if let Some(prov) = request.provider {
                if !agent_policy.allowed_providers.is_empty()
                    && !agent_policy.allowed_providers.iter().any(|p| p == prov)
                {
                    return PolicyDecision::Deny {
                        reason: format!(
                            "agent '{agent_id}' is not allowed to access provider '{prov}'"
                        ),
                    };
                }
            }

            // Check read-only vs write permissions
            let is_read = request.method == "GET"
                || request.operation.starts_with("read_")
                || request.operation == "check_credential";
            if is_read && !agent_policy.allow_read_only {
                return PolicyDecision::Deny {
                    reason: format!("agent '{agent_id}' is denied read-only operations"),
                };
            }

            if !is_read {
                if !agent_policy.allow_write_with_consent {
                    return PolicyDecision::Deny {
                        reason: format!("agent '{agent_id}' is denied write/mutating operations"),
                    };
                }
                if !request.has_active_consent {
                    return PolicyDecision::RequireConsent {
                        reason: format!(
                            "operation '{}' on provider '{}' requires human consent for agent '{}'",
                            request.operation,
                            request.provider.unwrap_or("unknown"),
                            agent_id
                        ),
                    };
                }
            }

            // Check quotas (rate limits & payload size)
            if let Some(quotas) = &agent_policy.quotas {
                if let (Some(max_reqs), Some(recent)) =
                    (quotas.max_requests_per_hour, request.recent_request_count)
                {
                    if recent >= max_reqs {
                        return PolicyDecision::Deny {
                            reason: format!(
                                "agent '{agent_id}' has exceeded its rate limit quota ({recent}/{max_reqs} requests this hour)"
                            ),
                        };
                    }
                }
                if let (Some(max_bytes), Some(payload_len)) =
                    (quotas.max_payload_bytes, request.payload_bytes)
                {
                    if payload_len > max_bytes {
                        return PolicyDecision::Deny {
                            reason: format!(
                                "agent '{agent_id}' request payload exceeds quota limit ({payload_len} > {max_bytes} bytes)"
                            ),
                        };
                    }
                }
            }
        } else if policy.default.access == "deny" {
            return PolicyDecision::Deny {
                reason: format!("unrecognized agent '{agent_id}' is denied by default policy"),
            };
        }
    }

    // 2. Command whitelist checks (for SSH exec)
    if let Some(cmd) = request.command {
        let cmd_trim = cmd.trim();

        // Block any command that references .env (e.g. grep, cat, head, tail, etc.)
        if is_env_file_involved(cmd_trim) {
            return PolicyDecision::Deny {
                reason: format!(
                    "execution blocked: command references .env file ('{cmd_trim}'). Agents are prohibited from viewing raw env secrets."
                ),
            };
        }

        // Block commands attempting to read server IP address or username when an agent is running
        if request.agent_identity.is_some() && is_ip_or_identity_discovery_command(cmd_trim) {
            return PolicyDecision::Deny {
                reason: format!(
                    "execution blocked: command attempts to discover server IP address or username ('{cmd_trim}'). AI agents are prohibited from reading server network addresses or user identities."
                ),
            };
        }
        if let Some(target) = request.domain.or(request.provider) {
            if let Some(host_policy) = policy.hosts.get(target) {
                if !host_policy.allowed_commands.is_empty() {
                    let cmd_trim = cmd.trim();
                    let matches_whitelist = host_policy.allowed_commands.iter().any(|allowed| {
                        if allowed.ends_with('*') {
                            let prefix = &allowed[..allowed.len() - 1];
                            cmd_trim.starts_with(prefix)
                        } else {
                            cmd_trim == allowed
                        }
                    });

                    if !matches_whitelist {
                        return PolicyDecision::Deny {
                            reason: format!(
                                "command '{cmd_trim}' is not in the allowed command whitelist for '{target}'"
                            ),
                        };
                    }

                    // Approved by host command whitelist
                    return PolicyDecision::Allow;
                }
            }
        }
    }
    match request.provider {
        None => PolicyDecision::Allow,
        Some(_) if request.method == "GET" => PolicyDecision::Allow,
        Some(provider) => {
            if request.has_active_consent {
                PolicyDecision::Allow
            } else {
                PolicyDecision::RequireConsent {
                    reason: format!(
                        "operation '{}' on provider '{provider}' is not a read-only request",
                        request.operation
                    ),
                }
            }
        }
    }
}

/// Shell metacharacters that let a remote shell chain, substitute, or
/// redirect. Any command containing one of these is rejected before
/// allow-list matching (M0 / G5 interim fix; M2 replaces this with argv
/// templates).
pub const SHELL_METACHARACTERS: &[char] = &[';', '&', '|', '`', '$', '>', '<', '\n', '\r', '\\'];

/// Returns the first shell metacharacter found in `command`, if any.
pub fn find_shell_metacharacter(command: &str) -> Option<char> {
    command.chars().find(|c| SHELL_METACHARACTERS.contains(c))
}

/// A "plain" token is one a trailing `*` in `allowed_commands` may match:
/// no quoting, globbing, or anything a shell would re-interpret.
fn is_plain_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=,@%+".contains(c))
}

/// Matches `command` against one `allowed_commands` entry. Exact entries
/// compare whitespace-normalised tokens. An entry ending in `*` matches when
/// the command starts with the entry's tokens and every remaining token is
/// plain (see [`is_plain_token`]).
pub fn command_matches_allowed(command: &str, allowed: &str) -> bool {
    if find_shell_metacharacter(command).is_some() {
        return false;
    }
    let cmd_tokens: Vec<&str> = command.split_whitespace().collect();
    if let Some(prefix) = allowed.strip_suffix('*') {
        let prefix_tokens: Vec<&str> = prefix.split_whitespace().collect();
        if prefix_tokens.is_empty() || cmd_tokens.len() < prefix_tokens.len() {
            return false;
        }
        cmd_tokens[..prefix_tokens.len()] == prefix_tokens[..]
            && cmd_tokens[prefix_tokens.len()..]
                .iter()
                .all(|t| is_plain_token(t))
    } else {
        let allowed_tokens: Vec<&str> = allowed.split_whitespace().collect();
        !cmd_tokens.is_empty() && cmd_tokens == allowed_tokens
    }
}

/// Fail-closed evaluator for SSH operations (`ssh_exec`, `ssh_connect`,
/// `ssh_tunnel`, `ssh_agent_sign`).
///
/// Order: command safety (.env, metacharacters) → agent identity → host
/// policy → `default.access`. With no `[hosts.<name>]` table and the default
/// `access = "deny"`, every SSH operation is denied.
fn evaluate_ssh(request: &PolicyRequest, policy: &ProjectPolicy) -> PolicyDecision {
    let host = request.domain.or(request.provider).unwrap_or("unknown");

    // 1. Command safety, before anything else.
    if let Some(cmd) = request.command {
        let cmd_trim = cmd.trim();
        if cmd_trim.is_empty() {
            return PolicyDecision::Deny {
                reason: "empty command".to_string(),
            };
        }
        if is_env_file_involved(cmd_trim) {
            return PolicyDecision::Deny {
                reason: format!(
                    "execution blocked: command references .env file ('{cmd_trim}'). Agents are prohibited from viewing raw env secrets."
                ),
            };
        }
        if request.agent_identity.is_some() && is_ip_or_identity_discovery_command(cmd_trim) {
            return PolicyDecision::Deny {
                reason: format!(
                    "execution blocked: command attempts to discover server IP address or username ('{cmd_trim}'). AI agents are prohibited from reading server network addresses or user identities."
                ),
            };
        }
        if let Some(c) = find_shell_metacharacter(cmd_trim) {
            return PolicyDecision::Deny {
                reason: format!(
                    "command rejected: contains shell metacharacter {:?}; chaining, substitution and redirection are not allowed",
                    c
                ),
            };
        }
    }

    // 2. Agent identity.
    if let Some(agent_id) = request.agent_identity {
        match policy.agents.get(agent_id) {
            Some(agent_policy) => {
                if let Some(quotas) = &agent_policy.quotas
                    && let (Some(max_reqs), Some(recent)) =
                        (quotas.max_requests_per_hour, request.recent_request_count)
                    && recent >= max_reqs
                {
                    return PolicyDecision::Deny {
                        reason: format!(
                            "agent '{agent_id}' has exceeded its rate limit quota ({recent}/{max_reqs} requests this hour)"
                        ),
                    };
                }
            }
            None if policy.default.access == "deny" => {
                return PolicyDecision::Deny {
                    reason: format!("unrecognized agent '{agent_id}' is denied by default policy"),
                };
            }
            None => {}
        }
        if matches!(request.operation, "ssh_connect" | "ssh_tunnel") {
            return PolicyDecision::Deny {
                reason: format!(
                    "agents may not open interactive SSH sessions or tunnels ('{}' requested by agent '{agent_id}')",
                    request.operation
                ),
            };
        }
    }

    // 3. Host policy.
    if let Some(host_policy) = policy.hosts.get(host) {
        if let Some(cmd) = request.command {
            let cmd_trim = cmd.trim();
            if host_policy.allowed_commands.is_empty() {
                if request.agent_identity.is_some() {
                    return PolicyDecision::Deny {
                        reason: format!(
                            "host '{host}' has no allowed_commands; agents may not run commands there"
                        ),
                    };
                }
                return PolicyDecision::Allow;
            }
            if host_policy
                .allowed_commands
                .iter()
                .any(|allowed| command_matches_allowed(cmd_trim, allowed))
            {
                return PolicyDecision::Allow;
            }
            return PolicyDecision::Deny {
                reason: format!(
                    "command '{cmd_trim}' is not in the allowed command whitelist for '{host}'"
                ),
            };
        }
        return PolicyDecision::Allow;
    }

    // 4. No host table: fall back to the project default (deny unless the
    //    project explicitly opts in with `access = "allow"`).
    if policy.default.access == "allow" {
        PolicyDecision::Allow
    } else {
        PolicyDecision::Deny {
            reason: format!(
                "default deny: no [hosts.{host}] policy in .envy/policy.toml and default access is \"deny\""
            ),
        }
    }
}

/// Checks if a command references `.env` files (e.g. `.env`, `.env.local`, `path/.env`, etc.)
pub fn is_env_file_involved(command: &str) -> bool {
    // Look for occurrences of .env
    for token in command.split_whitespace() {
        let clean =
            token.trim_matches(|c: char| c == '"' || c == '\'' || c == ';' || c == '|' || c == '&');
        if clean == ".env"
            || clean.starts_with(".env.")
            || clean.ends_with("/.env")
            || clean.contains("/.env.")
            || clean.contains("/.env")
        {
            return true;
        }
    }
    // Also catch command-line args like --env-file=.env or <.env or >.env
    if command.contains(".env") {
        let lower = command.to_lowercase();
        for part in lower.split(|c: char| {
            c.is_whitespace()
                || c == '='
                || c == '<'
                || c == '>'
                || c == ';'
                || c == '|'
                || c == '&'
                || c == '"'
                || c == '\''
        }) {
            if part == ".env"
                || part.starts_with(".env.")
                || part.ends_with("/.env")
                || part.contains("/.env.")
            {
                return true;
            }
        }
    }
    false
}

/// Checks if a command attempts to read the server's IP address or host user identity.
pub fn is_ip_or_identity_discovery_command(command: &str) -> bool {
    let lower = command.to_lowercase();
    let tokens: Vec<&str> = lower.split_whitespace().collect();
    if tokens.is_empty() {
        return false;
    }

    let first =
        tokens[0].trim_matches(|c: char| c == '"' || c == '\'' || c == ';' || c == '|' || c == '&');

    if first == "whoami" || first == "ifconfig" || first == "route" || first == "arp" {
        return true;
    }

    if first == "id" {
        return true;
    }

    if first == "hostname" {
        return true;
    }

    if first == "ip"
        && (tokens.len() == 1
            || tokens.iter().any(|&t| {
                matches!(
                    t,
                    "addr" | "a" | "route" | "r" | "link" | "l" | "neighbor" | "neigh" | "n"
                )
            }))
    {
        return true;
    }

    if first == "netstat" && tokens.iter().any(|&t| t.contains('r') || t.contains('i')) {
        return true;
    }

    if (first == "curl" || first == "wget")
        && (lower.contains("ifconfig.me")
            || lower.contains("icanhazip")
            || lower.contains("ipinfo.io")
            || lower.contains("api.ipify.org")
            || lower.contains("checkip.amazonaws.com")
            || lower.contains("ident.me")
            || lower.contains("whatismyip")
            || lower.contains("dnsomatic"))
    {
        return true;
    }

    if lower.contains("/etc/hosts")
        || lower.contains("/etc/resolv.conf")
        || lower.contains("/etc/hostname")
        || lower.contains("/etc/network")
    {
        return true;
    }

    false
}

/// Compatibility wrapper for evaluating requests without explicit policy file.
pub fn evaluate(request: &PolicyRequest) -> PolicyDecision {
    evaluate_with_policy(request, &ProjectPolicy::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_operation_is_allowed() {
        let req = PolicyRequest {
            operation: "init",
            provider: None,
            domain: None,
            agent_identity: None,
            method: "LOCAL",
            command: None,
            has_active_consent: false,
            recent_request_count: None,
            payload_bytes: None,
        };
        assert_eq!(evaluate(&req), PolicyDecision::Allow);
    }

    #[test]
    fn provider_facing_get_is_allowed() {
        let req = PolicyRequest {
            operation: "check_credential",
            provider: Some("stripe"),
            domain: Some("api.stripe.com"),
            agent_identity: None,
            method: "GET",
            command: None,
            has_active_consent: false,
            recent_request_count: None,
            payload_bytes: None,
        };
        assert_eq!(evaluate(&req), PolicyDecision::Allow);
    }

    #[test]
    fn provider_facing_non_get_requires_consent() {
        let req = PolicyRequest {
            operation: "make_authenticated_request",
            provider: Some("stripe"),
            domain: Some("api.stripe.com"),
            agent_identity: None,
            method: "POST",
            command: None,
            has_active_consent: false,
            recent_request_count: None,
            payload_bytes: None,
        };
        assert!(matches!(
            evaluate(&req),
            PolicyDecision::RequireConsent { .. }
        ));
    }

    #[test]
    fn agent_policy_blocks_unauthorized_provider() {
        let mut policy = ProjectPolicy::default();
        policy.agents.insert(
            "codex".to_string(),
            AgentPolicy {
                allowed_providers: vec!["context7".to_string()],
                allow_read_only: true,
                allow_write_with_consent: true,
                quotas: None,
            },
        );

        let req = PolicyRequest {
            operation: "check_credential",
            provider: Some("stripe"),
            domain: Some("api.stripe.com"),
            agent_identity: Some("codex"),
            method: "GET",
            command: None,
            has_active_consent: false,
            recent_request_count: None,
            payload_bytes: None,
        };
        assert!(matches!(
            evaluate_with_policy(&req, &policy),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn command_whitelist_blocks_unapproved_command() {
        let mut policy = ProjectPolicy::default();
        // Default access is now "deny" (M0), so the agent must be registered.
        policy.agents.insert(
            "claude_code".to_string(),
            AgentPolicy {
                allowed_providers: vec![],
                allow_read_only: true,
                allow_write_with_consent: false,
                quotas: None,
            },
        );
        policy.hosts.insert(
            "production".to_string(),
            HostPolicy {
                allowed_commands: vec!["uptime".to_string(), "df -h".to_string()],
                known_host_required: true,
            },
        );

        let req = PolicyRequest {
            operation: "ssh_exec",
            provider: Some("production"),
            domain: Some("production"),
            agent_identity: Some("claude_code"),
            method: "EXEC",
            command: Some("rm -rf /"),
            has_active_consent: false,
            recent_request_count: None,
            payload_bytes: None,
        };
        assert!(matches!(
            evaluate_with_policy(&req, &policy),
            PolicyDecision::Deny { .. }
        ));

        let approved_req = PolicyRequest {
            operation: "ssh_exec",
            provider: Some("production"),
            domain: Some("production"),
            agent_identity: Some("claude_code"),
            method: "EXEC",
            command: Some("uptime"),
            has_active_consent: false,
            recent_request_count: None,
            payload_bytes: None,
        };
        assert_eq!(
            evaluate_with_policy(&approved_req, &policy),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn is_env_file_involved_detects_env_access() {
        assert!(is_env_file_involved("cat .env"));
        assert!(is_env_file_involved("grep SECRET .env"));
        assert!(is_env_file_involved("grep -i key .env.production"));
        assert!(is_env_file_involved("head -n 10 ./config/.env"));
        assert!(is_env_file_involved("python script.py --env-file=.env"));
        assert!(!is_env_file_involved("ls -la"));
        assert!(!is_env_file_involved("echo environment"));
        assert!(!is_env_file_involved("uptime"));
    }

    #[test]
    fn command_referencing_env_is_blocked_by_policy() {
        let policy = ProjectPolicy::default();
        let req = PolicyRequest {
            operation: "ssh_exec",
            provider: Some("production"),
            domain: Some("production"),
            agent_identity: Some("claude_code"),
            method: "EXEC",
            command: Some("cat .env"),
            has_active_consent: false,
            recent_request_count: None,
            payload_bytes: None,
        };
        let decision = evaluate_with_policy(&req, &policy);
        assert!(matches!(decision, PolicyDecision::Deny { reason } if reason.contains(".env")));
    }

    #[test]
    fn agent_quota_rate_limit_blocks_excessive_requests() {
        let mut policy = ProjectPolicy::default();
        policy.agents.insert(
            "ci_agent".to_string(),
            AgentPolicy {
                allowed_providers: vec![],
                allow_read_only: true,
                allow_write_with_consent: true,
                quotas: Some(AgentQuotas {
                    max_requests_per_hour: Some(10),
                    max_payload_bytes: Some(1024),
                }),
            },
        );

        let req = PolicyRequest {
            operation: "check_credential",
            provider: Some("stripe"),
            domain: Some("api.stripe.com"),
            agent_identity: Some("ci_agent"),
            method: "GET",
            command: None,
            has_active_consent: false,
            recent_request_count: Some(10), // at limit
            payload_bytes: Some(100),
        };
        let decision = evaluate_with_policy(&req, &policy);
        assert!(
            matches!(decision, PolicyDecision::Deny { reason } if reason.contains("rate limit quota"))
        );

        let payload_req = PolicyRequest {
            operation: "check_credential",
            provider: Some("stripe"),
            domain: Some("api.stripe.com"),
            agent_identity: Some("ci_agent"),
            method: "GET",
            command: None,
            has_active_consent: false,
            recent_request_count: Some(5),
            payload_bytes: Some(2048), // exceeds 1024
        };
        let payload_decision = evaluate_with_policy(&payload_req, &policy);
        assert!(
            matches!(payload_decision, PolicyDecision::Deny { reason } if reason.contains("payload exceeds quota"))
        );
    }

    fn ssh_exec_req<'a>(host: &'a str, agent: Option<&'a str>, cmd: &'a str) -> PolicyRequest<'a> {
        PolicyRequest {
            operation: "ssh_exec",
            provider: Some(host),
            domain: Some(host),
            agent_identity: agent,
            method: "EXEC",
            command: Some(cmd),
            has_active_consent: false,
            recent_request_count: None,
            payload_bytes: None,
        }
    }

    fn policy_with_host(host: &str, allowed: &[&str]) -> ProjectPolicy {
        let mut policy = ProjectPolicy::default();
        policy.hosts.insert(
            host.to_string(),
            HostPolicy {
                allowed_commands: allowed.iter().map(|s| s.to_string()).collect(),
                known_host_required: true,
            },
        );
        policy
    }

    #[test]
    fn default_policy_is_deny() {
        assert_eq!(DefaultPolicy::default().access, "deny");
        assert_eq!(ProjectPolicy::default().default.access, "deny");
    }

    #[test]
    fn ssh_exec_is_default_denied_without_host_policy() {
        let policy = ProjectPolicy::default();
        let decision = evaluate_with_policy(&ssh_exec_req("prod", None, "uptime"), &policy);
        assert!(
            matches!(&decision, PolicyDecision::Deny { reason } if reason.contains("default deny")),
            "{decision:?}"
        );
        for op in ["ssh_connect", "ssh_tunnel"] {
            let req = PolicyRequest {
                operation: op,
                command: None,
                ..ssh_exec_req("prod", None, "")
            };
            assert!(matches!(
                evaluate_with_policy(&req, &policy),
                PolicyDecision::Deny { .. }
            ));
        }
    }

    #[test]
    fn unknown_agent_denied_even_when_agents_table_is_empty() {
        let policy = ProjectPolicy::default();
        assert!(policy.agents.is_empty());
        let req = PolicyRequest {
            operation: "check_credential",
            provider: Some("stripe"),
            domain: Some("api.stripe.com"),
            agent_identity: Some("rogue"),
            method: "GET",
            command: None,
            has_active_consent: false,
            recent_request_count: None,
            payload_bytes: None,
        };
        assert!(matches!(
            evaluate_with_policy(&req, &policy),
            PolicyDecision::Deny { reason } if reason.contains("unrecognized agent")
        ));
        // And on the SSH path, even with an allow-listed command.
        let policy = policy_with_host("prod", &["uptime"]);
        assert!(matches!(
            evaluate_with_policy(&ssh_exec_req("prod", Some("rogue"), "uptime"), &policy),
            PolicyDecision::Deny { reason } if reason.contains("unrecognized agent")
        ));
    }

    #[test]
    fn every_shell_metacharacter_is_rejected() {
        let policy = policy_with_host("prod", &["echo *"]);
        for meta in [";", "&", "|", "`", "$", ">", "<", "\n", "\\"] {
            let cmd = format!("echo a{meta}b");
            let decision = evaluate_with_policy(&ssh_exec_req("prod", None, &cmd), &policy);
            assert!(
                matches!(&decision, PolicyDecision::Deny { reason } if reason.contains("metacharacter")),
                "metacharacter {meta:?} was not rejected: {decision:?}"
            );
        }
        assert_eq!(
            evaluate_with_policy(&ssh_exec_req("prod", None, "echo hello"), &policy),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn wildcard_allowlist_rejects_chained_command() {
        // Regression for G5: a trailing `*` used to admit `...; rm -rf ~`.
        let policy = policy_with_host("prod", &["journalctl -u api --since *", "uptime"]);
        for chained in [
            "journalctl -u api --since x; rm -rf ~",
            "journalctl -u api --since x && rm -rf ~",
            "journalctl -u api --since x | sh",
            "journalctl -u api --since $(rm -rf ~)",
            "journalctl -u api --since `rm -rf ~`",
            "uptime; rm -rf ~",
        ] {
            assert!(
                matches!(
                    evaluate_with_policy(&ssh_exec_req("prod", None, chained), &policy),
                    PolicyDecision::Deny { .. }
                ),
                "chained command allowed: {chained}"
            );
            assert!(!command_matches_allowed(
                chained,
                "journalctl -u api --since *"
            ));
        }
        // Trailing `*` only matches plain tokens.
        assert!(!command_matches_allowed(
            "journalctl -u api --since 'x y'",
            "journalctl -u api --since *"
        ));
        assert!(!command_matches_allowed(
            "journalctl -u apix",
            "journalctl -u api *"
        ));
        assert_eq!(
            evaluate_with_policy(
                &ssh_exec_req("prod", None, "journalctl -u api --since 2026-10-28"),
                &policy
            ),
            PolicyDecision::Allow
        );
        assert_eq!(
            evaluate_with_policy(&ssh_exec_req("prod", None, "uptime"), &policy),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn agents_cannot_open_ssh_connect_or_tunnel() {
        let mut policy = policy_with_host("prod", &["uptime"]);
        policy.agents.insert(
            "codex".to_string(),
            AgentPolicy {
                allowed_providers: vec![],
                allow_read_only: true,
                allow_write_with_consent: false,
                quotas: None,
            },
        );
        let req = PolicyRequest {
            operation: "ssh_connect",
            command: None,
            ..ssh_exec_req("prod", Some("codex"), "")
        };
        assert!(matches!(
            evaluate_with_policy(&req, &policy),
            PolicyDecision::Deny { .. }
        ));
        assert_eq!(
            evaluate_with_policy(&ssh_exec_req("prod", Some("codex"), "uptime"), &policy),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn agent_ip_and_identity_discovery_commands_are_denied() {
        assert!(is_ip_or_identity_discovery_command("whoami"));
        assert!(is_ip_or_identity_discovery_command("id -un"));
        assert!(is_ip_or_identity_discovery_command("hostname -I"));
        assert!(is_ip_or_identity_discovery_command("ip addr"));
        assert!(is_ip_or_identity_discovery_command("ip a"));
        assert!(is_ip_or_identity_discovery_command("ifconfig"));
        assert!(is_ip_or_identity_discovery_command("curl ifconfig.me"));
        assert!(is_ip_or_identity_discovery_command("cat /etc/hosts"));
        assert!(!is_ip_or_identity_discovery_command("uptime"));
        assert!(!is_ip_or_identity_discovery_command("df -h"));
        assert!(!is_ip_or_identity_discovery_command("docker ps"));

        let policy = policy_with_host("prod", &["whoami", "uptime", "hostname -I"]);
        let req = ssh_exec_req("prod", Some("claude_code"), "whoami");
        let decision = evaluate_with_policy(&req, &policy);
        assert!(
            matches!(decision, PolicyDecision::Deny { reason } if reason.contains("prohibited"))
        );

        let req_ip = ssh_exec_req("prod", Some("claude_code"), "hostname -I");
        let decision_ip = evaluate_with_policy(&req_ip, &policy);
        assert!(
            matches!(decision_ip, PolicyDecision::Deny { reason } if reason.contains("prohibited"))
        );
    }
}
