use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::TempDir;

#[test]
fn test_cli_encrypted_export_import_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let project_dir = temp_dir.path();

    let envy_bin = env!("CARGO_BIN_EXE_envy");

    // 1. Initialize vault
    let init_output = Command::new(envy_bin)
        .arg("init")
        .current_dir(project_dir)
        .output()
        .expect("failed to run envy init");
    assert!(init_output.status.success());

    // 2. Add secret via stdin
    let mut add_child = Command::new(envy_bin)
        .args(["add", "API_TOKEN", "--non-interactive"])
        .current_dir(project_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn envy add");

    {
        let mut stdin = add_child.stdin.take().expect("failed to open stdin");
        stdin.write_all(b"super_secret_token_12345\n").unwrap();
    }
    let add_res = add_child.wait_with_output().unwrap();
    assert!(add_res.status.success());

    // 3. Export encrypted backup via stdin password
    let backup_file = project_dir.join("vault.backup.enc");
    let mut export_child = Command::new(envy_bin)
        .args(["export", "--encrypted", backup_file.to_str().unwrap(), "--non-interactive"])
        .current_dir(project_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn envy export");

    {
        let mut stdin = export_child.stdin.take().expect("failed to open stdin");
        stdin.write_all(b"my-backup-password\n").unwrap();
    }
    let export_res = export_child.wait_with_output().unwrap();
    assert!(export_res.status.success(), "export failed: {}", String::from_utf8_lossy(&export_res.stderr));
    assert!(backup_file.exists());

    let backup_content = std::fs::read_to_string(&backup_file).unwrap();
    assert!(backup_content.contains("ENVYBK01"));
    assert!(!backup_content.contains("super_secret_token_12345"));

    // 4. Create second project and restore
    let temp_dir2 = TempDir::new().unwrap();
    let project_dir2 = temp_dir2.path();

    let init2_output = Command::new(envy_bin)
        .arg("init")
        .current_dir(project_dir2)
        .output()
        .expect("failed to run envy init on dir 2");
    assert!(init2_output.status.success());

    let mut import_child = Command::new(envy_bin)
        .args(["import", "--encrypted", backup_file.to_str().unwrap(), "--non-interactive"])
        .current_dir(project_dir2)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn envy import");

    {
        let mut stdin = import_child.stdin.take().expect("failed to open stdin");
        stdin.write_all(b"my-backup-password\n").unwrap();
    }
    let import_res = import_child.wait_with_output().unwrap();
    assert!(import_res.status.success(), "import failed: {}", String::from_utf8_lossy(&import_res.stderr));

    // 5. Verify list in project 2
    let list_output = Command::new(envy_bin)
        .args(["list", "--json"])
        .current_dir(project_dir2)
        .output()
        .expect("failed to run envy list");
    assert!(list_output.status.success());
    let stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(stdout.contains("API_TOKEN"));
}
