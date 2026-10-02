mod add;
mod check;
mod consent;
mod doctor;
mod export;
mod expose;
mod import;
mod init;
mod list;
mod log;
mod mcp;
mod policy;
mod provider;
mod run;
mod scan;
mod show;
mod ssh;

use anyhow::bail;

use crate::cli::{Cli, Commands, GlobalArgs};

pub fn dispatch(cli: Cli) -> anyhow::Result<()> {
    let global = &cli.global;
    match cli.command {
        Commands::Init => init::run(global),
        Commands::Scan {
            path,
            remediate,
            restore,
        } => scan::run(path, remediate, restore, global),
        Commands::Add { name, from_env } => add::run(name, from_env, global),
        Commands::List => list::run(global),
        Commands::Show {
            reference,
            metadata_only,
        } => show::run(reference, metadata_only, global),
        Commands::Check {
            reference,
            project,
            url,
            auth_style,
            header_name,
            provider,
        } => check::run(
            reference,
            project,
            url,
            auth_style,
            header_name,
            provider,
            global,
        ),
        Commands::Run { command } => run::run(command, global),
        Commands::Expose { action } => expose::run(action, global),
        Commands::Log { project, follow } => log::run(project, follow, global),
        Commands::Export {
            encrypted,
            env,
            example,
            force,
        } => export::run(encrypted, env, example, force, global),
        Commands::Import { encrypted, env } => import::run(encrypted, env, global),
        Commands::Provider { action } => provider::run(action, global),
        Commands::Mcp { action } => mcp::run(action, global),
        Commands::Consent { action } => consent::run(action, global),
        Commands::Doctor => doctor::run(global),
        Commands::Ssh { action } => ssh::run(action, global),
        Commands::Policy => policy::run(global),
    }
}

/// Shared stub for commands that don't have a real implementation yet.
///
/// Prints a JSON-shaped message if `--json` is set, a plain message to
/// stderr otherwise (suppressed by `--quiet`), then fails — there's no
/// vault yet, so nothing can honestly report success.
fn not_implemented(command: &str, global: &GlobalArgs) -> anyhow::Result<()> {
    if global.json {
        println!(r#"{{"error":"not_implemented","command":"{command}"}}"#);
    }
    // Plain-text case: `main()` prints this bail! message to stderr for
    // every command's error, not just this one — no need to also
    // eprintln here.
    bail!("`envy {command}` is not implemented yet");
}
