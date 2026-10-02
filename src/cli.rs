use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

pub use provider::ProviderAction;

#[derive(Debug, Parser)]
#[command(
    name = "envy",
    version,
    about = "Local-first secrets manager and credential gateway"
)]
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

        /// Automatically replace discovered plaintext credentials with envy:// references in source files.
        #[arg(long)]
        remediate: bool,

        /// Restore .bak backup files created during a previous remediation pass.
        #[arg(long)]
        restore: bool,
    },

    /// Import a specific candidate into the vault.
    Add {
        /// Name of the candidate to import.
        name: Option<String>,

        /// Read the secret value directly from an environment variable of the same name.
        #[arg(long = "from-env")]
        from_env: bool,
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

        /// Ad-hoc mode (level 4): the URL to call for this check (no
        /// cataloged provider needed — this URL is your explicit approval
        /// for the one call it makes). Mutually exclusive with --provider.
        #[arg(long)]
        url: Option<String>,

        /// Ad-hoc mode: how to inject the credential ("bearer" or
        /// "header").
        #[arg(long = "auth-style", default_value = "bearer")]
        auth_style: String,

        /// Ad-hoc mode: header name to use when --auth-style=header.
        #[arg(long = "header-name")]
        header_name: Option<String>,

        /// Cataloged mode (level 1): an installed provider id (see `envy
        /// provider list`) — runs that provider's own verified health
        /// check instead of a caller-supplied URL. Mutually exclusive
        /// with --url.
        #[arg(long)]
        provider: Option<String>,
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

        /// Follow / poll audit log live in real time.
        #[arg(short = 'f', long = "follow")]
        follow: bool,
    },

    /// Export the vault as an encrypted backup file, write a plaintext
    /// .env file's worth of secrets, or write a names-only .env.example.
    Export {
        /// Destination file for an encrypted whole-vault backup.
        #[arg(long)]
        encrypted: Option<PathBuf>,

        /// Write vault secrets as a plaintext .env file instead of an
        /// encrypted backup. Optional value: defaults to ".env" if given
        /// with no filename.
        #[arg(long, num_args = 0..=1, default_missing_value = ".env")]
        env: Option<PathBuf>,

        /// Write a names-only .env.example (every vault secret's name,
        /// no values) so agents/humans can see what variables a project
        /// expects without ever exposing a value. Optional value:
        /// defaults to ".env.example" if given with no filename.
        #[arg(long, num_args = 0..=1, default_missing_value = ".env.example")]
        example: Option<PathBuf>,

        /// Overwrite an existing destination file (backs it up to
        /// `<file>.bak` first). Applies to `--env` and `--example`.
        #[arg(long)]
        force: bool,
    },

    /// Restore the vault from an encrypted backup file, or import a
    /// plaintext .env file's key=value pairs into the vault.
    Import {
        /// Source file to restore from (encrypted whole-vault backup).
        #[arg(long)]
        encrypted: Option<PathBuf>,

        /// Read a plaintext .env file and import its key=value pairs
        /// into the vault instead of restoring an encrypted backup.
        /// Optional value: defaults to ".env" if given with no filename.
        #[arg(long, num_args = 0..=1, default_missing_value = ".env")]
        env: Option<PathBuf>,
    },

    /// Manage and validate provider descriptors.
    Provider {
        #[command(subcommand)]
        action: ProviderAction,
    },

    /// Run the local MCP adapter for AI agents.
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },

    /// Grant, revoke, or list time-boxed consent for provider-facing
    /// operations that aren't plain reads (e.g. a non-GET
    /// `make_authenticated_request`). CLI-only — never exposed to agents,
    /// since consent only means something if an agent can't grant it to
    /// itself.
    Consent {
        #[command(subcommand)]
        action: ConsentAction,
    },

    /// Run local diagnostics: vault init, keychain round-trip, schema
    /// check. Uses a throwaway vault and keychain entry — never touches a
    /// real project's vault.
    Doctor,

    /// Manage SSH keys, host profiles, and infrastructure access.
    Ssh {
        #[command(subcommand)]
        action: SshAction,
    },

    /// Inspect and validate active project governance and agent policies.
    Policy,

    /// Install or manage Git pre-commit hooks to block plaintext credential leaks.
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum HookAction {
    /// Install an envy pre-commit hook in .git/hooks/pre-commit.
    Install,
}

#[derive(Debug, Subcommand)]
pub enum SshAction {
    /// Import an SSH private key into the vault.
    Import {
        /// Path to the private key file on disk (e.g. ~/.ssh/id_ed25519).
        path: PathBuf,

        /// Name for the stored identity (defaults to the key filename).
        #[arg(long)]
        name: Option<String>,
    },

    /// List stored SSH key identities and fingerprints.
    Keys,

    /// Add or update a server/host profile.
    Add {
        /// Profile name (e.g. production, staging).
        name: String,

        /// Server hostname or IP address.
        #[arg(long)]
        host: String,

        /// SSH port.
        #[arg(long, default_value_t = 22)]
        port: u16,

        /// SSH username (e.g. deploy, root).
        #[arg(long)]
        user: String,

        /// Name of the stored SSH key identity to use.
        #[arg(long)]
        identity: String,
    },

    /// List configured SSH host profiles.
    List,

    /// Connect interactively to a configured SSH host profile.
    Connect {
        /// Name of the configured host profile.
        name: String,
    },

    /// Run a command on a configured SSH host profile.
    Exec {
        /// Name of the configured host profile.
        name: String,

        /// Command to execute on the remote host.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Establish an ephemeral SSH local port-forwarding tunnel for agents or local tools.
    Tunnel {
        /// Name of the configured host profile.
        name: String,

        /// Local port to bind.
        #[arg(long)]
        local_port: u16,

        /// Remote target host (e.g. 127.0.0.1).
        #[arg(long, default_value = "127.0.0.1")]
        remote_host: String,

        /// Remote target port (e.g. 5432, 8080).
        #[arg(long)]
        remote_port: u16,
    },

    /// Run the background SSH Agent daemon answering signing requests over socket.
    Agent {
        /// Socket path to bind (defaults to ~/.envy/ssh-agent.sock).
        #[arg(long)]
        socket: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConsentAction {
    /// Grant time-boxed consent for a provider + operation.
    Grant {
        /// The provider id (e.g. "stripe").
        provider: String,

        /// The operation being consented to (e.g.
        /// "make_authenticated_request").
        operation: String,

        /// How long the grant stays active, e.g. "30s", "5m", "1h", "2d".
        #[arg(long, default_value = "5m")]
        ttl: String,
    },

    /// Revoke any active consent for a provider + operation.
    Revoke {
        /// The provider id (e.g. "stripe").
        provider: String,

        /// The operation to revoke consent for.
        operation: String,
    },

    /// List consent grants (active, expired, and revoked).
    List,
}

mod provider {
    use clap::Subcommand;
    use std::path::PathBuf;

    #[derive(Debug, Subcommand)]
    pub enum ProviderAction {
        /// Validate a provider descriptor file before installing it.
        Validate {
            /// Path to the .toml descriptor to validate.
            path: PathBuf,
        },

        /// Validate and install a provider descriptor into envy's provider
        /// directory, so `envy scan`/`check`/`make_authenticated_request`
        /// pick it up without a recompile.
        Install {
            /// Path to the .toml descriptor to install.
            path: PathBuf,

            /// Overwrite an already-installed descriptor with the same id
            /// (backs it up to `<file>.bak` first).
            #[arg(long)]
            force: bool,
        },

        /// List installed provider descriptors.
        List,
    }
}

#[derive(Debug, Subcommand)]
pub enum ExposeAction {
    /// Write envy's MCP server into an AI client's config so it can
    /// connect without hand-editing JSON/TOML.
    Install {
        /// Which client to install for.
        #[arg(long, value_enum)]
        client: McpClientArg,

        /// Where to write the config: this project only, or the client's
        /// global config. Defaults to project where the client supports it.
        #[arg(long, value_enum)]
        scope: Option<ScopeArg>,

        /// Path to the MCP adapter's compiled entry point (cli/mcp/dist/index.js).
        /// Overrides envy's own auto-resolution, which only works in a
        /// dev/source checkout today (no packaged distribution exists yet).
        #[arg(long)]
        mcp_entry: Option<PathBuf>,

        /// Overwrite an existing "envy" entry in the client's config
        /// (backs up the whole config file to `<file>.bak` first).
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum McpClientArg {
    ClaudeCode,
    ClaudeDesktop,
    Cursor,
    Codex,
    Pi,
    Agy,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ScopeArg {
    Project,
    Global,
}

#[derive(Debug, Subcommand)]
pub enum McpAction {
    /// Start the MCP server so agents can request capabilities.
    Serve,
}
