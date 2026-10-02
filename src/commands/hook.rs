use crate::cli::{GlobalArgs, HookAction};
use anyhow::{Context, bail};
const PRE_COMMIT_SCRIPT: &str = r#"#!/usr/bin/env bash
# envy-pre-commit: Blocks committing plaintext credentials in staged files
# Installed via `envy hook install`

set -e

if ! command -v envy &> /dev/null; then
    echo "⚠️  envy CLI not found on PATH. Skipping credential pre-commit check."
    exit 0
fi

# Run envy scan on the git working tree / staged files
SCAN_OUTPUT=$(envy scan . --json 2>/dev/null || true)

if echo "$SCAN_OUTPUT" | grep -q '"findings":\s*\[[^]]'; then
    echo ""
    echo "❌ [envy] PRE-COMMIT BLOCKED: Plaintext credential(s) detected in repository!"
    echo "-------------------------------------------------------------------------------"
    echo "$SCAN_OUTPUT" | grep -o '"var_name":"[^"]*"' | tr -d '"' | sed 's/var_name:/  • Plaintext variable: /'
    echo ""
    echo "👉 Run 'envy scan --remediate' to replace secrets with safe envy:// references."
    echo "👉 Or run 'envy import --env .env' and add '.env' to your .gitignore."
    echo "-------------------------------------------------------------------------------"
    exit 1
fi

exit 0
"#;

pub fn run(action: HookAction, global: &GlobalArgs) -> anyhow::Result<()> {
    match action {
        HookAction::Install => install(global),
    }
}

fn install(global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let git_dir = cwd.join(".git");
    if !git_dir.exists() {
        bail!(
            "not a git repository (no .git directory found at {})",
            cwd.display()
        );
    }

    let hooks_dir = git_dir.join("hooks");
    std::fs::create_dir_all(&hooks_dir).with_context(|| {
        format!(
            "failed to create hooks directory at {}",
            hooks_dir.display()
        )
    })?;

    let hook_file = hooks_dir.join("pre-commit");
    std::fs::write(&hook_file, PRE_COMMIT_SCRIPT)
        .with_context(|| format!("failed to write pre-commit hook to {}", hook_file.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&hook_file)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&hook_file, perms)?;
    }

    if global.json {
        println!(r#"{{"status":"ok","hook_path":"{}"}}"#, hook_file.display());
    } else if !global.quiet {
        println!("Installed envy pre-commit hook at {}", hook_file.display());
        println!("Git commits will now be automatically scanned for leaked credentials.");
    }
    Ok(())
}
