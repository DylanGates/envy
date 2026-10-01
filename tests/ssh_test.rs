use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_cli_ssh_key_import_and_host_profile() {
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

    // 2. Create a fake Ed25519 key file
    let fake_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n";
    let key_path = project_dir.join("id_ed25519");
    std::fs::write(&key_path, fake_key).unwrap();

    // 3. Import SSH key
    let import = Command::new(envy_bin)
        .args([
            "ssh",
            "import",
            key_path.to_str().unwrap(),
            "--name",
            "prod-key",
            "--json",
        ])
        .current_dir(project_dir)
        .output()
        .expect("import failed");
    assert!(
        import.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&import.stderr)
    );
    let import_out = String::from_utf8_lossy(&import.stdout);
    assert!(import_out.contains("prod-key"));
    assert!(import_out.contains("OPENSSH"));

    // 4. List SSH keys
    let keys = Command::new(envy_bin)
        .args(["ssh", "keys", "--json"])
        .current_dir(project_dir)
        .output()
        .expect("keys failed");
    assert!(keys.status.success());
    let keys_out = String::from_utf8_lossy(&keys.stdout);
    assert!(keys_out.contains("prod-key"));

    // 5. Add host profile
    let add_host = Command::new(envy_bin)
        .args([
            "ssh",
            "add",
            "prod-server",
            "--host",
            "203.0.113.10",
            "--user",
            "deploy",
            "--identity",
            "prod-key",
            "--port",
            "2222",
            "--json",
        ])
        .current_dir(project_dir)
        .output()
        .expect("add host failed");
    assert!(add_host.status.success());

    // 6. List host profiles
    let list_hosts = Command::new(envy_bin)
        .args(["ssh", "list", "--json"])
        .current_dir(project_dir)
        .output()
        .expect("list hosts failed");
    assert!(list_hosts.status.success());
    let list_out = String::from_utf8_lossy(&list_hosts.stdout);
    assert!(list_out.contains("prod-server"));
    assert!(list_out.contains("203.0.113.10"));
    assert!(list_out.contains("deploy"));
}
