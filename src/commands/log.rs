use std::path::PathBuf;

use crate::cli::GlobalArgs;

pub fn run(project: Option<PathBuf>, global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;

    let filter = project.map(|p| p.to_string_lossy().into_owned());
    let events = vault.list_events(filter.as_deref())?;

    if global.json {
        println!("{}", serde_json::to_string(&events)?);
    } else if !global.quiet {
        if events.is_empty() {
            println!("No audit events.");
        }
        for event in &events {
            println!(
                "{}  {}  {}  provider={}  host={}",
                event.timestamp,
                event.operation,
                event.outcome,
                event.provider.as_deref().unwrap_or("-"),
                event.endpoint_host.as_deref().unwrap_or("-"),
            );
        }
    }
    Ok(())
}
