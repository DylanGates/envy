use std::process::Command;
use tempfile::TempDir;

/// Test-only key created with `ssh-keygen -t ed25519 -N "" -C envy-fixture`.
/// It protects nothing. `ssh-keygen -lf` printed FIXTURE_FINGERPRINT.
const FIXTURE_ED25519: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAenIL+RyilLKurnRJXE0KIPe0Ox/uaZ5QvQ6l8h9sLiAAAAJBI6aR/SOmk
fwAAAAtzc2gtZWQyNTUxOQAAACAenIL+RyilLKurnRJXE0KIPe0Ox/uaZ5QvQ6l8h9sLiA
AAAEDEA83Xh9ytVBfEx8HqnW3uSYGbgyzxw+85Dte3o9rSdh6cgv5HKKUsq6udElcTQog9
7Q7H+5pnlC9DqXyH2wuIAAAADGVudnktZml4dHVyZQE=
-----END OPENSSH PRIVATE KEY-----
";
const FIXTURE_FINGERPRINT: &str = "SHA256:oRt4xK5cQVYqNgXayeIVs70ccdbXSVxIxDQGqDTOSkQ";

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

    // 2. Write the test-only Ed25519 fixture key
    let key_path = project_dir.join("id_ed25519");
    std::fs::write(&key_path, FIXTURE_ED25519).unwrap();

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
    assert!(import_out.contains("ssh-ed25519"));
    assert!(import_out.contains(FIXTURE_FINGERPRINT));

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

    // 7. Generate a new SSH keypair directly inside envy vault
    let gen_key = Command::new(envy_bin)
        .args([
            "ssh",
            "generate",
            "staging-key",
            "--algorithm",
            "ed25519",
            "--json",
        ])
        .current_dir(project_dir)
        .output()
        .expect("ssh generate failed");
    assert!(gen_key.status.success());
    let gen_out = String::from_utf8_lossy(&gen_key.stdout);
    assert!(gen_out.contains("staging-key"));
    assert!(gen_out.contains("ssh-ed25519"));

    // 8. Export the public key from the vault
    let export_pub = Command::new(envy_bin)
        .args(["ssh", "export", "staging-key"])
        .current_dir(project_dir)
        .output()
        .expect("ssh export failed");
    assert!(export_pub.status.success());
    let pub_out = String::from_utf8_lossy(&export_pub.stdout);
    assert!(pub_out.starts_with("ssh-ed25519"));
}

/// M0: a host with `known_host_required = true` and no pinned key is refused
/// before `ssh` is spawned (203.0.113.10 is TEST-NET-3; nothing is contacted).
#[test]
fn test_cli_ssh_refuses_unpinned_host_without_network() {
    let temp_dir = TempDir::new().unwrap();
    let project_dir = temp_dir.path();
    let envy_bin = env!("CARGO_BIN_EXE_envy");
    let run = |args: &[&str], agent: Option<&str>| {
        let mut cmd = Command::new(envy_bin);
        cmd.args(args).current_dir(project_dir);
        match agent {
            Some(a) => cmd.env("ENVY_AGENT_ID", a),
            None => cmd.env_remove("ENVY_AGENT_ID"),
        };
        cmd.output().unwrap()
    };

    assert!(run(&["init"], None).status.success());
    let key_path = project_dir.join("id_ed25519");
    std::fs::write(&key_path, FIXTURE_ED25519).unwrap();
    assert!(
        run(
            &["ssh", "import", key_path.to_str().unwrap(), "--name", "k"],
            None
        )
        .status
        .success()
    );
    assert!(
        run(
            &[
                "ssh",
                "add",
                "prod",
                "--host",
                "203.0.113.10",
                "--user",
                "deploy",
                "--identity",
                "k"
            ],
            None
        )
        .status
        .success()
    );
    // Even an explicit allow policy does not bypass pinning.
    std::fs::write(
        project_dir.join(".envy/policy.toml"),
        "[hosts.prod]\nallowed_commands = [\"uptime\"]\n[agents.codex]\n",
    )
    .unwrap();

    for args in [
        vec!["ssh", "exec", "prod", "--", "uptime"],
        vec!["ssh", "connect", "prod"],
        vec![
            "ssh",
            "tunnel",
            "prod",
            "--local-port",
            "15432",
            "--remote-port",
            "5432",
        ],
    ] {
        let out = run(&args, None);
        assert!(!out.status.success(), "{args:?} should be refused");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("requires a pinned host key"),
            "{args:?}: {stderr}"
        );
    }

    // The refusal is audited with the real subject.
    let out = run(&["ssh", "exec", "prod", "--", "uptime"], Some("codex"));
    assert!(!out.status.success());
    assert_eq!(
        audit_count(project_dir, "agent:codex", "denied:host_not_pinned"),
        1
    );
}

/// Counts audit events with this subject and outcome via `envy log --json`.
fn audit_count(project_dir: &std::path::Path, subject: &str, outcome: &str) -> usize {
    let out = Command::new(env!("CARGO_BIN_EXE_envy"))
        .args(["log", "--json"])
        .current_dir(project_dir)
        .output()
        .unwrap();
    let events: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
    events
        .iter()
        .filter(|e| e["subject"] == subject && e["outcome"] == outcome)
        .count()
}
