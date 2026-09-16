use crate::cli::{ExposeAction, GlobalArgs};
use crate::mcp_clients::{self, McpClient, Scope};

pub fn run(action: ExposeAction, global: &GlobalArgs) -> anyhow::Result<()> {
    match action {
        ExposeAction::Install { client, scope, mcp_entry, force } => {
            install(client.into(), scope.map(Scope::from), mcp_entry, force, global)
        }
    }
}

fn install(
    client: McpClient,
    scope: Option<Scope>,
    mcp_entry: Option<std::path::PathBuf>,
    force: bool,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    let project_root = std::env::current_dir()?;
    let entry = mcp_clients::resolve_mcp_entry(mcp_entry)?;

    let path = mcp_clients::install(client, scope, &project_root, &entry, force)?;

    if global.json {
        println!(
            r#"{{"status":"ok","client":"{}","config_path":"{}"}}"#,
            client.id(),
            path.display()
        );
    } else if !global.quiet {
        println!("Installed envy's MCP server for {} at {}", client.id(), path.display());
    }
    Ok(())
}
