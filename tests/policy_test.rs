use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_cli_policy_inspection() {
    let temp_dir = TempDir::new().unwrap();
    let project_dir = temp_dir.path();
    let envy_bin = env!("CARGO_BIN_EXE_envy");

    // 1. Initialize vault
    let init = Command::new(envy_bin)
        .arg("init")
        .current_dir(project_dir)
        .output()
        .expect("init failed");
    assert!(init.status.success());

    // 2. Write a sample policy.toml
    let policy_toml = r#"
[default]
access = "deny"
require_consent_for_write = true

[agents.claude_code]
allowed_providers = ["stripe", "github"]
allow_read_only = true
allow_write_with_consent = true

[hosts.production]
known_host_required = true
allowed_commands = ["uptime", "df -h"]
"#;
    std::fs::write(project_dir.join(".envy/policy.toml"), policy_toml).unwrap();

    // 3. Inspect policy via CLI
    let policy_output = Command::new(envy_bin)
        .args(["policy", "--json"])
        .current_dir(project_dir)
        .output()
        .expect("policy failed");
    assert!(policy_output.status.success());
    let out = String::from_utf8_lossy(&policy_output.stdout);
    assert!(out.contains("claude_code"));
    assert!(out.contains("stripe"));
    assert!(out.contains("production"));
    assert!(out.contains("uptime"));
}
