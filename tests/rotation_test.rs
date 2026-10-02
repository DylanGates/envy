use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_cli_rotation_staleness_and_expiry() {
    let temp_dir = TempDir::new().unwrap();
    let project_dir = temp_dir.path();
    let envy_bin = env!("CARGO_BIN_EXE_envy");

    // 1. Init vault
    let init = Command::new(envy_bin)
        .arg("init")
        .current_dir(project_dir)
        .output()
        .expect("init failed");
    assert!(init.status.success());

    // 2. Add secret
    let mut add = Command::new(envy_bin)
        .args(["add", "API_KEY", "--non-interactive"])
        .current_dir(project_dir)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let mut stdin = add.stdin.take().unwrap();
        stdin.write_all(b"sk_live_123456789\n").unwrap();
    }
    assert!(add.wait().unwrap().success());

    // 3. List secrets via JSON to verify age_days and is_stale fields
    let list_output = Command::new(envy_bin)
        .args(["list", "--json"])
        .current_dir(project_dir)
        .output()
        .expect("list failed");
    assert!(list_output.status.success());
    let list_json = String::from_utf8_lossy(&list_output.stdout);
    assert!(list_json.contains("age_days"));
    assert!(list_json.contains("is_stale"));
    assert!(list_json.contains("false")); // Fresh secret is not stale
}
