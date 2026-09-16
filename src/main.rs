mod cli;
mod commands;
mod mcp_clients;

use std::process::ExitCode;

use clap::Parser;
use cli::Cli;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match commands::dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
