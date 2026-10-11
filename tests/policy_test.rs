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

    // 4. Test .env file blocking in ssh exec
    let exec_env_output = Command::new(envy_bin)
        .args(["ssh", "exec", "production", "--", "cat", ".env"])
        .current_dir(project_dir)
        .output()
        .expect("ssh exec failed");
    assert!(!exec_env_output.status.success());
    let stderr = String::from_utf8_lossy(&exec_env_output.stderr);
    assert!(stderr.contains(".env") || stderr.contains("blocked") || stderr.contains("denied"));

    // 5. Test envy ssh list with ENVY_AGENT_ID set redacts user and host IP
    // Add host first
    let mut add_key = Command::new(envy_bin)
        .args(["add", "prod_key", "--non-interactive"])
        .current_dir(project_dir)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let mut stdin = add_key.stdin.take().unwrap();
        stdin.write_all(b"fake_key_content\n").unwrap();
    }
    assert!(add_key.wait().unwrap().success());

    let add_host = Command::new(envy_bin)
        .args(["ssh", "add", "prod_server", "--host", "192.168.1.100", "--user", "admin", "--identity", "prod_key"])
        .current_dir(project_dir)
        .output()
        .expect("add host failed");
    assert!(add_host.status.success());

    let list_agent = Command::new(envy_bin)
        .args(["ssh", "list", "--json"])
        .env("ENVY_AGENT_ID", "claude_code")
        .current_dir(project_dir)
        .output()
        .expect("ssh list agent failed");
    assert!(list_agent.status.success());
    let agent_json = String::from_utf8_lossy(&list_agent.stdout);
    assert!(agent_json.contains("[REDACTED]"));
    assert!(!agent_json.contains("192.168.1.100"));
    assert!(!agent_json.contains("\"user\":\"admin\""));
}
