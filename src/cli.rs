use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "envy", version, about = "Local-first secrets manager and credential gateway")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[command(flatten)]
    pub global: GlobalArgs,
}

#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long, global = true)]
    pub json: bool,

    /// Suppress non-essential output.
    #[arg(long, global = true)]
    pub quiet: bool,

    /// Show what would change without applying it.
    ///
    /// Accepted now; not yet read by any command — real mutating commands
    /// (import, remediation, export/import) will consult this once they
    /// exist.
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Never prompt; fail instead of asking for interactive confirmation.
    ///
    /// Accepted now; not yet read by any command — real interactive
    /// commands will consult this once they exist.
    #[arg(long, global = true)]
    pub non_interactive: bool,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Create and open the local encrypted vault.
    Init,

    /// Discover credential candidates in a project.
    Scan {
        /// Directory to scan (defaults to the current directory).
        path: Option<PathBuf>,
    },

    /// Import a specific candidate into the vault.
    Add {
        /// Name of the candidate to import.
        name: Option<String>,
    },

    /// List secrets currently held in the vault.
    List,

    /// Show metadata for a single vault entry.
    Show {
        /// The envy:// reference to show.
        reference: String,

        /// Only show metadata; never resolve or print the value.
        #[arg(long)]
        metadata_only: bool,
    },

    /// Run a provider health check against a stored credential.
    Check {
        /// The envy:// reference (vault secret name) to check.
        reference: Option<String>,

        /// Check every credential used by a project instead of one reference.
        #[arg(long)]
        project: Option<PathBuf>,

        /// Ad-hoc mode: the URL to call for this check (no cataloged
        /// provider needed — this URL is your explicit approval for the
        /// one call it makes).
        #[arg(long)]
        url: Option<String>,

        /// Ad-hoc mode: how to inject the credential ("bearer" or
        /// "header").
        #[arg(long = "auth-style", default_value = "bearer")]
        auth_style: String,

        /// Ad-hoc mode: header name to use when --auth-style=header.
        #[arg(long = "header-name")]
        header_name: Option<String>,
    },

    /// Run a command with resolved credentials injected into its environment.
    Run {
        /// The command to run, e.g. `envy run -- npm start`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Manage the local capability gateway.
    Expose {
        #[command(subcommand)]
        action: ExposeAction,
    },

    /// Show recent audit events.
    Log {
        /// Restrict log output to a single project.
        #[arg(long)]
        project: Option<PathBuf>,
    },

    /// Export the vault as an encrypted backup file.
    Export {
        /// Destination file for the encrypted export.
        #[arg(long)]
        encrypted: PathBuf,
    },

    /// Restore the vault from an encrypted backup file.
    Import {
        /// Source file to restore from.
        #[arg(long)]
        encrypted: PathBuf,
    },

    /// Run the local MCP adapter for AI agents.
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum ExposeAction {
    /// Install the capability gateway for the current environment.
    Install,
}

#[derive(Debug, Subcommand)]
pub enum McpAction {
    /// Start the MCP server so agents can request capabilities.
    Serve,
}
