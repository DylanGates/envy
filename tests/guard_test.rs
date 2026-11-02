//! End-to-end tests for `envy guard` — check-command / check-path / hook /
//! install. Uses a throwaway tempdir and the real OS keychain (via the
//! dbus+gnome-keyring CI wrapper) only when a vault is needed for audit
//! append; most checks run without one.

use std::io::Write;
use std::process::{Command, Stdio};

fn envy() -> Command {
    Command::new(env!("CARGO_BIN_EXE_envy"))
}

fn deny_code(status: &std::process::ExitStatus) -> bool {
    status.code() == Some(2)
}

#[test]
fn check_command_denies_ssh_and_env() {
    let dir = tempfile::tempdir().unwrap();

    let out = envy()
        .current_dir(dir.path())
        .args(["guard", "check-command", "--", "ssh", "root@1.2.3.4"])
        .output()
        .unwrap();
    assert!(
        deny_code(&out.status),
        "ssh should exit 2, got {:?}; stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("ssh-remote") || err.contains("deny"),
        "stderr={err}"
    );

    let out = envy()
        .current_dir(dir.path())
        .args(["guard", "check-command", "--", "cat", ".env"])
        .output()
        .unwrap();
    assert!(deny_code(&out.status), "cat .env should exit 2");

    let out = envy()
        .current_dir(dir.path())
        .args(["guard", "check-command", "--", "ls", "-la"])
        .output()
        .unwrap();
    assert!(out.status.success(), "ls should allow");
    assert!(String::from_utf8_lossy(&out.stdout).contains("allow"));
}

#[test]
fn check_command_json_shape() {
    let dir = tempfile::tempdir().unwrap();
    let out = envy()
        .current_dir(dir.path())
        .args(["--json", "guard", "check-command", "--", "printenv"])
        .output()
        .unwrap();
    assert!(deny_code(&out.status));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["allow"], false);
    assert_eq!(v["rule"], "env-dump");
    assert!(v["suggestion"].as_str().unwrap().contains("envy"));
}

#[test]
fn check_path_blocks_secret_files() {
    let dir = tempfile::tempdir().unwrap();
    let out = envy()
        .current_dir(dir.path())
        .args(["guard", "check-path", "~/.ssh/id_ed25519"])
        .output()
        .unwrap();
    assert!(deny_code(&out.status));

    let out = envy()
        .current_dir(dir.path())
        .args(["guard", "check-path", "src/main.rs"])
        .output()
        .unwrap();
    assert!(out.status.success());

    let out = envy()
        .current_dir(dir.path())
        .args(["guard", "check-path", "--write", ".envy/policy.toml"])
        .output()
        .unwrap();
    assert!(deny_code(&out.status));
}

#[test]
fn hook_claude_code_denies_bash_cat_env() {
    let dir = tempfile::tempdir().unwrap();
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {"command": "cat .env"},
        "cwd": dir.path().to_string_lossy(),
    });
    let mut child = envy()
        .current_dir(dir.path())
        .args(["guard", "hook", "--client", "claude-code"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(payload.to_string().as_bytes()).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "hook must exit 0 with JSON deny");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(
        reason.contains("secret-file") || reason.contains(".env") || reason.contains("credential")
    );
}

#[test]
fn hook_cursor_denies_shell_ssh() {
    let dir = tempfile::tempdir().unwrap();
    let payload = serde_json::json!({
        "hook_event_name": "beforeShellExecution",
        "command": "ssh root@vps.example.com uptime",
        "cwd": dir.path().to_string_lossy(),
    });
    let mut child = envy()
        .current_dir(dir.path())
        .args(["guard", "hook", "--client", "cursor"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(payload.to_string().as_bytes()).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["permission"], "deny");
    assert!(v["agent_message"].as_str().unwrap().contains("ssh"));
}

#[test]
fn hook_allows_ordinary_read() {
    let dir = tempfile::tempdir().unwrap();
    let payload = serde_json::json!({
        "hook_event_name": "beforeReadFile",
        "file_path": dir.path().join("README.md").to_string_lossy(),
        "cwd": dir.path().to_string_lossy(),
    });
    let mut child = envy()
        .current_dir(dir.path())
        .args(["guard", "hook", "--client", "cursor"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(payload.to_string().as_bytes()).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["permission"], "allow");
}

#[test]
fn install_writes_claude_and_cursor_hooks() {
    let dir = tempfile::tempdir().unwrap();

    let out = envy()
        .current_dir(dir.path())
        .args([
            "guard",
            "install",
            "--client",
            "claude-code",
            "--scope",
            "project",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let settings = std::fs::read_to_string(dir.path().join(".claude/settings.json")).unwrap();
    assert!(settings.contains("guard hook --client claude-code"));
    assert!(settings.contains("onFailure"));
    assert!(settings.contains("Bash|Read"));

    let out = envy()
        .current_dir(dir.path())
        .args([
            "guard", "install", "--client", "cursor", "--scope", "project",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let hooks = std::fs::read_to_string(dir.path().join(".cursor/hooks.json")).unwrap();
    assert!(hooks.contains("guard hook --client cursor"));
    assert!(hooks.contains("beforeShellExecution"));
    assert!(hooks.contains("beforeReadFile"));
    assert!(hooks.contains("failClosed"));

    // Re-install without --force must refuse.
    let out = envy()
        .current_dir(dir.path())
        .args([
            "guard", "install", "--client", "cursor", "--scope", "project",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn policy_allow_ssh_hosts_override() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".envy")).unwrap();
    std::fs::write(
        dir.path().join(".envy/policy.toml"),
        r#"
[guard]
allow_ssh_hosts = ["github.com", "vps.example.com"]
"#,
    )
    .unwrap();

    let out = envy()
        .current_dir(dir.path())
        .args([
            "guard",
            "check-command",
            "--",
            "ssh",
            "deploy@vps.example.com",
            "uptime",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "allowed host should pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = envy()
        .current_dir(dir.path())
        .args(["guard", "check-command", "--", "ssh", "root@evil.example"])
        .output()
        .unwrap();
    assert!(deny_code(&out.status));
}

#[test]
fn audit_mode_allows_but_still_reports() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".envy")).unwrap();
    std::fs::write(
        dir.path().join(".envy/policy.toml"),
        r#"
[guard]
mode = "audit"
"#,
    )
    .unwrap();

    let out = envy()
        .current_dir(dir.path())
        .args(["guard", "check-command", "--", "cat", ".env"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "audit mode must allow: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
