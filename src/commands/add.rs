use std::io::Write;

use anyhow::{Context, bail};
use envy_core::audit::AuditEvent;

use crate::cli::GlobalArgs;

pub fn run(name: Option<String>, from_env: bool, global: &GlobalArgs) -> anyhow::Result<()> {
    let name = match name {
        Some(name) => name,
        None if !global.non_interactive => prompt_name()?,
        None => bail!("NAME is required in --non-interactive mode"),
    };

    let value = if from_env {
        std::env::var(&name).with_context(|| {
            format!("environment variable '{name}' is not set or empty")
        })?
    } else if global.non_interactive {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("failed to read secret value from stdin")?;
        line.trim_end_matches(['\r', '\n']).to_string()
    } else {
        rpassword::prompt_password(format!("Value for {name}: "))
            .context("failed to read secret value")?
    };

    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    vault.add_secret(&name, value.as_bytes())?;

    vault.log_event(&AuditEvent {
        subject: Some("cli"),
        project: Some(&cwd.to_string_lossy()),
        provider: None,
        operation: "add",
        endpoint_host: None,
        outcome: "success",
        redaction_summary: Some(&format!("stored secret '{name}'")),
    })?;

    if global.json {
        println!(r#"{{"status":"ok","reference":"envy://{name}"}}"#);
    } else if !global.quiet {
        println!("Added secret '{name}' to vault (envy://{name})");
    }
    Ok(())
}

fn prompt_name() -> anyhow::Result<String> {
    print!("Name: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("failed to read name")?;
    let name = line.trim().to_string();
    if name.is_empty() {
        bail!("NAME cannot be empty");
    }
    Ok(name)
}
