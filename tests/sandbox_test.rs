use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_cli_sandbox_composite_workflow() {
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
        stdin.write_all(b"secret_sandbox_val\n").unwrap();
    }
    assert!(add.wait().unwrap().success());

    // 3. Write a plaintext .env file with a secret
    let env_file = project_dir.join(".env");
    std::fs::write(&env_file, "API_KEY=secret_sandbox_val\n").unwrap();

    // 4. Test sandbox blocking command referencing .env
    let blocked_res = Command::new(envy_bin)
        .args(["sandbox", "--", "cat", ".env"])
        .current_dir(project_dir)
        .output()
        .expect("sandbox failed");
    assert!(!blocked_res.status.success());
    let err_str = String::from_utf8_lossy(&blocked_res.stderr);
    assert!(err_str.contains(".env") || err_str.contains("blocked"));

    // 5. Test sandbox execution running printenv (injected in-memory)
    let run_res = Command::new(envy_bin)
        .args(["sandbox", "--", "printenv", "API_KEY"])
        .current_dir(project_dir)
        .output()
        .expect("sandbox run failed");
    assert!(run_res.status.success());
    let out_str = String::from_utf8_lossy(&run_res.stdout);
    assert!(out_str.contains("secret_sandbox_val"));
}
