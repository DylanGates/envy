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
        Self {
            access: "allow".to_string(),
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
pub struct AgentPolicy {
    #[serde(default)]
    pub allowed_providers: Vec<String>,
    #[serde(default = "default_true")]
    pub allow_read_only: bool,
    #[serde(default)]
    pub allow_write_with_consent: bool,
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
        } else if policy.default.access == "deny" && !policy.agents.is_empty() {
            return PolicyDecision::Deny {
                reason: format!("unrecognized agent '{agent_id}' is denied by default policy"),
            };
        }
    }

    // 2. Command whitelist checks (for SSH exec)
    if let Some(cmd) = request.command {
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
        };
        assert!(matches!(
            evaluate_with_policy(&req, &policy),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn command_whitelist_blocks_unapproved_command() {
        let mut policy = ProjectPolicy::default();
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
        };
        assert_eq!(
            evaluate_with_policy(&approved_req, &policy),
            PolicyDecision::Allow
        );
    }
}
