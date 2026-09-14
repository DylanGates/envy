use std::sync::{Arc, Mutex};

use envy_core::provider::Registry;
use envy_core::rpc::RpcContext;
use interprocess::local_socket::prelude::*;

use crate::cli::{GlobalArgs, McpAction};

pub fn run(action: McpAction, global: &GlobalArgs) -> anyhow::Result<()> {
    match action {
        McpAction::Serve => serve(global),
    }
}

fn serve(global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    let listener = envy_core::ipc::bind(&cwd)?;

    let (registry, warnings) = Registry::load()?;
    for warning in &warnings {
        eprintln!(
            "envy mcp: ignoring invalid provider descriptor at {}: {}",
            warning.path.display(),
            warning.message
        );
    }

    let ctx = RpcContext {
        vault: Arc::new(Mutex::new(vault)),
        registry: Arc::new(registry),
    };

    if !global.quiet {
        println!(
            "envy mcp: listening on {}",
            cwd.join(".envy").join("mcp.sock").display()
        );
    }

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if !global.quiet {
                    println!("envy mcp: connection accepted");
                }
                let quiet = global.quiet;
                let ctx = ctx.clone();
                std::thread::spawn(move || {
                    if let Err(e) = envy_core::rpc::serve_connection(stream, &ctx) {
                        if !quiet {
                            eprintln!("envy mcp: connection error: {e}");
                        }
                    }
                });
            }
            Err(e) => eprintln!("envy mcp: accept error: {e}"),
        }
    }
    Ok(())
}
