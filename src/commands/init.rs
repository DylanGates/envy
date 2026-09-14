use envy_core::audit::AuditEvent;

use crate::cli::GlobalArgs;

pub fn run(global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::init(&cwd)?;

    vault.log_event(&AuditEvent {
        subject: Some("cli"),
        project: Some(&cwd.to_string_lossy()),
        provider: None,
        operation: "init",
        endpoint_host: None,
        outcome: "success",
        redaction_summary: None,
    })?;

    if global.json {
        println!(r#"{{"status":"ok","vault_id":"{}"}}"#, vault.vault_id);
    } else if !global.quiet {
        println!("Initialized envy vault in {}", cwd.join(".envy").display());
    }
    Ok(())
}
