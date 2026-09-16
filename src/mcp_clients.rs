//! `envy expose install` — writes envy's MCP server into an AI client's
//! config, so an agent can connect without a human hand-editing JSON/TOML.
//!
//! Lives entirely in the `cli` crate, not `core`: writing another tool's
//! config file has no relationship to the vault/secrets/trust boundary
//! (unlike `envy doctor`, which lives in `core` because it exercises
//! `Vault`/`KeyStore` directly). The closer precedent is
//! `commands/provider.rs`'s descriptor validation, which is also pure
//! host-side file logic that stayed CLI-side.
//!
//! Confidence note (see `docs/context.md` for the full disclosure): Claude
//! Code, Claude Desktop, Cursor, and Codex are backed by official/
//! consistently-documented config formats. Pi and Agy are lower
//! confidence — based on secondary/community sources, not a single
//! authoritative doc — and are flagged as such wherever relevant. A wrong
//! guess here just means a harmless write to the wrong file, easily
//! corrected; it never touches a secret.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

use crate::cli::{McpClientArg, ScopeArg};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpClient {
    ClaudeCode,
    ClaudeDesktop,
    Cursor,
    Codex,
    Pi,
    Agy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Project,
    Global,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigFormat {
    Json,
    Toml,
}

impl From<McpClientArg> for McpClient {
    fn from(arg: McpClientArg) -> Self {
        match arg {
            McpClientArg::ClaudeCode => McpClient::ClaudeCode,
            McpClientArg::ClaudeDesktop => McpClient::ClaudeDesktop,
            McpClientArg::Cursor => McpClient::Cursor,
            McpClientArg::Codex => McpClient::Codex,
            McpClientArg::Pi => McpClient::Pi,
            McpClientArg::Agy => McpClient::Agy,
        }
    }
}

impl From<ScopeArg> for Scope {
    fn from(arg: ScopeArg) -> Self {
        match arg {
            ScopeArg::Project => Scope::Project,
            ScopeArg::Global => Scope::Global,
        }
    }
}

impl McpClient {
    pub fn id(&self) -> &'static str {
        match self {
            McpClient::ClaudeCode => "claude-code",
            McpClient::ClaudeDesktop => "claude-desktop",
            McpClient::Cursor => "cursor",
            McpClient::Codex => "codex",
            McpClient::Pi => "pi",
            McpClient::Agy => "agy",
        }
    }

    fn format(&self) -> ConfigFormat {
        match self {
            McpClient::Codex => ConfigFormat::Toml,
            _ => ConfigFormat::Json,
        }
    }

    fn supports(&self, scope: Scope) -> bool {
        match (self, scope) {
            (McpClient::ClaudeDesktop, Scope::Project) => false,
            (McpClient::Pi, Scope::Project) => false,
            _ => true,
        }
    }

    /// Default scope when `--scope` isn't passed.
    fn default_scope(&self) -> Scope {
        if self.supports(Scope::Project) {
            Scope::Project
        } else {
            Scope::Global
        }
    }

    /// Resolves the config file this client reads, for the given scope.
    /// `project_root` is only used for `Scope::Project`.
    fn config_path(&self, scope: Scope, project_root: &Path) -> anyhow::Result<PathBuf> {
        if !self.supports(scope) {
            bail!(
                "{} does not support {:?} scope",
                self.id(),
                scope
            );
        }

        let base_dirs = directories::BaseDirs::new()
            .context("could not determine the current user's home directory")?;

        Ok(match (self, scope) {
            (McpClient::ClaudeCode, Scope::Project) => project_root.join(".mcp.json"),
            (McpClient::ClaudeDesktop, Scope::Global) => base_dirs
                .config_dir()
                .join("Claude")
                .join("claude_desktop_config.json"),
            (McpClient::Cursor, Scope::Project) => project_root.join(".cursor").join("mcp.json"),
            (McpClient::Cursor, Scope::Global) => {
                base_dirs.home_dir().join(".cursor").join("mcp.json")
            }
            (McpClient::Codex, Scope::Project) => {
                project_root.join(".codex").join("config.toml")
            }
            (McpClient::Codex, Scope::Global) => {
                base_dirs.home_dir().join(".codex").join("config.toml")
            }
            (McpClient::Pi, Scope::Global) => {
                base_dirs.home_dir().join(".pi").join("agent").join("mcp.json")
            }
            (McpClient::Agy, Scope::Project) => {
                project_root.join(".agents").join("mcp_config.json")
            }
            (McpClient::Agy, Scope::Global) => base_dirs
                .home_dir()
                .join(".gemini")
                .join("config")
                .join("mcp_config.json"),
            // Every other (client, scope) pair is excluded by `supports`
            // above and already returned early.
            _ => unreachable!("unsupported (client, scope) combination reached config_path"),
        })
    }
}

/// Resolves the MCP adapter's compiled entry point (`cli/mcp/dist/index.js`).
/// Only auto-resolves the dev/source-checkout layout (no packaged
/// distribution exists yet) — checks the sibling location relative to the
/// running `envy` binary, mirroring `cli/mcp/src/coreProcess.ts`'s
/// `resolveEnvyBinary()` in reverse. Never guesses beyond that; fails with
/// the path(s) it checked so the caller knows to pass `--mcp-entry`.
pub fn resolve_mcp_entry(override_path: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(path) = override_path {
        if !path.is_file() {
            bail!("--mcp-entry {} does not exist", path.display());
        }
        return Ok(path);
    }

    let exe = std::env::current_exe().context("could not determine envy's own executable path")?;
    let exe_dir = exe
        .parent()
        .context("envy's executable path has no parent directory")?;

    resolve_relative_to(exe_dir)
}

/// The testable half of [`resolve_mcp_entry`]'s auto-resolution: checks
/// the dev-layout sibling location relative to a given directory (in
/// production, always the running binary's own directory). Separated out
/// so tests can point it at a constructed fake layout instead of this
/// process's real (test-binary) executable path.
fn resolve_relative_to(exe_dir: &Path) -> anyhow::Result<PathBuf> {
    // Dev layout: cli/target/{debug,release}/envy -> cli/mcp/dist/index.js
    // Two levels up from target/{debug,release}, not one: target/debug/../.. == cli/.
    let candidate = exe_dir.join("..").join("..").join("mcp").join("dist").join("index.js");
    if candidate.is_file() {
        return Ok(candidate.canonicalize().unwrap_or(candidate));
    }

    bail!(
        "could not find the MCP adapter's entry point (checked {}) — envy has no packaged \
         distribution yet, so this only auto-resolves in a source checkout; pass \
         --mcp-entry <path-to-cli/mcp/dist/index.js> explicitly",
        candidate.display()
    );
}

/// Installs envy into `client`'s config at `scope`. Returns the config
/// path written to.
pub fn install(
    client: McpClient,
    scope: Option<Scope>,
    project_root: &Path,
    mcp_entry: &Path,
    force: bool,
) -> anyhow::Result<PathBuf> {
    let scope = scope.unwrap_or_else(|| client.default_scope());
    let path = client.config_path(scope, project_root)?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let entry_str = mcp_entry
        .to_str()
        .context("--mcp-entry path is not valid UTF-8")?;
    let project_str = project_root
        .to_str()
        .context("project path is not valid UTF-8")?;

    match client.format() {
        ConfigFormat::Json => install_json(client, &path, entry_str, project_str, force)?,
        ConfigFormat::Toml => install_toml(&path, entry_str, project_str, force)?,
    }

    Ok(path)
}

/// Backs up `path` to `<path>.bak`. Called only once the caller has
/// already confirmed an overwrite is actually happening (an existing
/// "envy" entry, with `--force` passed) — unlike
/// `src/commands/export.rs`'s `backup_if_exists`, a *new* entry merged
/// into an existing multi-tool config file needs no backup or `--force`
/// at all, since nothing is being destroyed.
fn back_up(path: &Path) -> anyhow::Result<()> {
    let backup = PathBuf::from(format!("{}.bak", path.display()));
    std::fs::copy(path, &backup)
        .with_context(|| format!("failed to back up {} to {}", path.display(), backup.display()))?;
    Ok(())
}

fn install_json(
    client: McpClient,
    path: &Path,
    mcp_entry: &str,
    project_root: &str,
    force: bool,
) -> anyhow::Result<()> {
    let existing = if path.exists() {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_str(&text)
            .with_context(|| format!("{} does not contain valid JSON", path.display()))?
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };

    let serde_json::Value::Object(mut root) = existing else {
        bail!("{} does not contain a JSON object at its root", path.display());
    };

    let servers_key = "mcpServers";
    let servers = root
        .entry(servers_key)
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let serde_json::Value::Object(servers_map) = servers else {
        bail!("{} — \"{servers_key}\" is not a JSON object", path.display());
    };

    if servers_map.contains_key("envy") {
        if !force {
            bail!(
                "{} already has an \"envy\" entry — pass --force to overwrite (backs up the \
                 whole file to <file>.bak first)",
                path.display()
            );
        }
        back_up(path)?;
    }

    let mut entry = serde_json::Map::new();
    if client == McpClient::ClaudeCode {
        entry.insert("type".to_string(), serde_json::Value::String("stdio".to_string()));
    }
    if client == McpClient::Agy {
        entry.insert("transport".to_string(), serde_json::Value::String("stdio".to_string()));
    }
    entry.insert("command".to_string(), serde_json::Value::String("node".to_string()));
    entry.insert(
        "args".to_string(),
        serde_json::Value::Array(vec![
            serde_json::Value::String(mcp_entry.to_string()),
            serde_json::Value::String(project_root.to_string()),
        ]),
    );

    servers_map.insert("envy".to_string(), serde_json::Value::Object(entry));

    let out = serde_json::to_string_pretty(&serde_json::Value::Object(root))
        .context("failed to serialize config")?;
    std::fs::write(path, out + "\n").with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn install_toml(path: &Path, mcp_entry: &str, project_root: &str, force: bool) -> anyhow::Result<()> {
    let mut doc = if path.exists() {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        text.parse::<toml_edit::DocumentMut>()
            .with_context(|| format!("{} does not contain valid TOML", path.display()))?
    } else {
        toml_edit::DocumentMut::new()
    };

    let servers = doc
        .entry("mcp_servers")
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
    let Some(servers_table) = servers.as_table_mut() else {
        bail!("{} — \"mcp_servers\" is not a TOML table", path.display());
    };

    if servers_table.contains_key("envy") {
        if !force {
            bail!(
                "{} already has an [mcp_servers.envy] entry — pass --force to overwrite (backs \
                 up the whole file to <file>.bak first)",
                path.display()
            );
        }
        back_up(path)?;
    }

    let mut entry = toml_edit::Table::new();
    entry["command"] = toml_edit::value("node");
    let mut args = toml_edit::Array::new();
    args.push(mcp_entry);
    args.push(project_root);
    entry["args"] = toml_edit::Item::Value(toml_edit::Value::Array(args));

    servers_table.insert("envy", toml_edit::Item::Table(entry));

    std::fs::write(path, doc.to_string()).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_json_creates_new_file_with_envy_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");

        install_json(McpClient::ClaudeDesktop, &path, "/opt/envy/mcp/dist/index.js", "/proj", false).unwrap();

        let value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let entry = &value["mcpServers"]["envy"];
        assert_eq!(entry["command"], "node");
        assert_eq!(entry["args"][0], "/opt/envy/mcp/dist/index.js");
        assert_eq!(entry["args"][1], "/proj");
        assert!(entry.get("type").is_none(), "only Claude Code needs \"type\"");
    }

    #[test]
    fn install_json_claude_code_includes_type_stdio() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".mcp.json");
        install_json(McpClient::ClaudeCode, &path, "entry.js", "/proj", false).unwrap();
        let value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["mcpServers"]["envy"]["type"], "stdio");
    }

    #[test]
    fn install_json_agy_includes_transport_stdio_not_type() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp_config.json");
        install_json(McpClient::Agy, &path, "entry.js", "/proj", false).unwrap();
        let value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["mcpServers"]["envy"]["transport"], "stdio");
        assert!(value["mcpServers"]["envy"].get("type").is_none());
    }

    #[test]
    fn install_json_preserves_unrelated_existing_keys_and_servers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(
            &path,
            r#"{"theme":"dark","mcpServers":{"other":{"command":"foo"}}}"#,
        )
        .unwrap();

        install_json(McpClient::Cursor, &path, "entry.js", "/proj", false).unwrap();

        let value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["theme"], "dark");
        assert_eq!(value["mcpServers"]["other"]["command"], "foo");
        assert_eq!(value["mcpServers"]["envy"]["command"], "node");
    }

    #[test]
    fn install_json_refuses_to_clobber_a_malformed_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, "[1,2,3]").unwrap();

        let result = install_json(McpClient::Cursor, &path, "entry.js", "/proj", false);
        assert!(result.is_err());
        // Original content untouched.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[1,2,3]");
    }

    #[test]
    fn install_json_requires_force_to_overwrite_existing_envy_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        install_json(McpClient::Cursor, &path, "old-entry.js", "/proj", false).unwrap();

        let without_force = install_json(McpClient::Cursor, &path, "new-entry.js", "/proj", false);
        assert!(without_force.is_err());
        let value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["mcpServers"]["envy"]["args"][0], "old-entry.js");

        install_json(McpClient::Cursor, &path, "new-entry.js", "/proj", true).unwrap();
        let value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["mcpServers"]["envy"]["args"][0], "new-entry.js");
        let backup = PathBuf::from(format!("{}.bak", path.display()));
        assert!(backup.exists(), "expected a .bak backup before overwriting");
    }

    #[test]
    fn install_toml_creates_new_file_with_envy_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        install_toml(&path, "entry.js", "/proj", false).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let doc = text.parse::<toml_edit::DocumentMut>().unwrap();
        assert_eq!(doc["mcp_servers"]["envy"]["command"].as_str(), Some("node"));
        assert_eq!(doc["mcp_servers"]["envy"]["args"][0].as_str(), Some("entry.js"));
    }

    #[test]
    fn install_toml_preserves_existing_tables_and_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "# a hand-written comment\n[mcp_servers.other]\ncommand = \"foo\"\n",
        )
        .unwrap();

        install_toml(&path, "entry.js", "/proj", false).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# a hand-written comment"), "comment should survive the merge");
        assert!(text.contains("[mcp_servers.other]"));
        let doc = text.parse::<toml_edit::DocumentMut>().unwrap();
        assert_eq!(doc["mcp_servers"]["other"]["command"].as_str(), Some("foo"));
        assert_eq!(doc["mcp_servers"]["envy"]["command"].as_str(), Some("node"));
    }

    #[test]
    fn install_toml_requires_force_to_overwrite_existing_envy_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        install_toml(&path, "old-entry.js", "/proj", false).unwrap();

        assert!(install_toml(&path, "new-entry.js", "/proj", false).is_err());
        install_toml(&path, "new-entry.js", "/proj", true).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let doc = text.parse::<toml_edit::DocumentMut>().unwrap();
        assert_eq!(doc["mcp_servers"]["envy"]["args"][0].as_str(), Some("new-entry.js"));
        let backup = PathBuf::from(format!("{}.bak", path.display()));
        assert!(backup.exists());
    }

    #[test]
    fn resolve_relative_to_finds_a_real_sibling_entry_point() {
        // Mirrors the real repo layout exactly: cli/target/debug/envy is
        // two directories below cli/, same as cli/mcp/dist/index.js.
        let dir = tempfile::tempdir().unwrap();
        let cli_root = dir.path().join("cli");
        let exe_dir = cli_root.join("target").join("debug");
        std::fs::create_dir_all(&exe_dir).unwrap();
        let entry_dir = cli_root.join("mcp").join("dist");
        std::fs::create_dir_all(&entry_dir).unwrap();
        std::fs::write(entry_dir.join("index.js"), "// fake entry").unwrap();

        let resolved = resolve_relative_to(&exe_dir).unwrap();
        assert!(resolved.ends_with("mcp/dist/index.js") || resolved.ends_with("mcp\\dist\\index.js"));
    }

    #[test]
    fn resolve_relative_to_fails_clearly_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let exe_dir = dir.path().join("target").join("debug");
        std::fs::create_dir_all(&exe_dir).unwrap();

        let result = resolve_relative_to(&exe_dir);
        assert!(result.is_err());
        let message = result.unwrap_err().to_string();
        assert!(message.contains("--mcp-entry"), "error should point at the override flag");
    }
}
