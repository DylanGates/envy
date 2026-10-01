use std::path::PathBuf;

use crate::cli::GlobalArgs;

pub fn run(project: Option<PathBuf>, follow: bool, global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;

    let filter = project.map(|p| p.to_string_lossy().into_owned());

    if follow {
        let mut last_seen_id = 0i64;
        let mut initial_events = vault.list_events(filter.as_deref())?;
        // list_events returns most recent first; reverse for chronological streaming
        initial_events.reverse();
        for event in initial_events {
            if event.id > last_seen_id {
                last_seen_id = event.id;
            }
            print_event(&event, global)?;
        }

        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let mut recent = vault.list_events(filter.as_deref())?;
            recent.reverse();
            for event in recent {
                if event.id > last_seen_id {
                    last_seen_id = event.id;
                    print_event(&event, global)?;
                }
            }
        }
    } else {
        let events = vault.list_events(filter.as_deref())?;
        if global.json {
            println!("{}", serde_json::to_string(&events)?);
        } else if !global.quiet {
            if events.is_empty() {
                println!("No audit events.");
            }
            for event in &events {
                print_event(event, global)?;
            }
        }
    }
    Ok(())
}

fn print_event(event: &envy_core::audit::AuditEventRecord, global: &GlobalArgs) -> anyhow::Result<()> {
    if global.json {
        println!("{}", serde_json::to_string(event)?);
    } else if !global.quiet {
        println!(
            "{}  {}  {}  provider={}  host={}",
            event.timestamp,
            event.operation,
            event.outcome,
            event.provider.as_deref().unwrap_or("-"),
            event.endpoint_host.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}
