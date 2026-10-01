use std::path::PathBuf;

use anyhow::Context;
use envy_core::provider::descriptor::ProviderDescriptor;

use crate::cli::{GlobalArgs, ProviderAction};

pub fn run(action: ProviderAction, global: &GlobalArgs) -> anyhow::Result<()> {
    match action {
        ProviderAction::Validate { path } => validate(path, global),
        ProviderAction::Install { path, force } => install(path, force, global),
        ProviderAction::List => list(global),
    }
}

fn parse_descriptor(path: &std::path::Path) -> anyhow::Result<ProviderDescriptor> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("could not read {}: {e}", path.display()))?;
    toml::from_str(&source)
        .map_err(|e| anyhow::anyhow!("TOML parse error in {}: {e}", path.display()))
}

/// Checks a parsed descriptor's shape. Shared by `validate` and `install`
/// so installing always applies the exact same checks — `install` fails
/// closed on any error, same as `validate` does.
fn check_descriptor(descriptor: &ProviderDescriptor) -> (Vec<String>, Vec<String>) {
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // ── id ───────────────────────────────────────────────────────────────────
    if descriptor.id.is_empty() {
        errors.push("`id` must not be empty".to_string());
    } else if !descriptor
        .id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        errors.push(format!(
            "`id` \"{}\" must contain only lowercase letters, digits, and hyphens",
            descriptor.id
        ));
    }

    // ── name ─────────────────────────────────────────────────────────────────
    if descriptor.name.is_empty() {
        errors.push("`name` must not be empty".to_string());
    }

    // ── domains ──────────────────────────────────────────────────────────────
    if descriptor.domains.is_empty() {
        errors.push("`domains` must contain at least one entry".to_string());
    } else {
        for domain in &descriptor.domains {
            if domain.contains("://") {
                errors.push(format!(
                    "domain \"{domain}\" must be a bare hostname (no scheme prefix like https://)"
                ));
            } else if domain.contains('/') {
                errors.push(format!(
                    "domain \"{domain}\" must be a bare hostname (no path)"
                ));
            } else if domain.is_empty() {
                errors.push("domains list contains an empty string".to_string());
            }
        }
    }

    // ── credentials ──────────────────────────────────────────────────────────
    if descriptor.credentials.is_empty() {
        errors.push("`[[credentials]]` must contain at least one entry".to_string());
    }

    for cred in &descriptor.credentials {
        let label = format!("credential \"{}\"", cred.name);

        if cred.name.is_empty() {
            errors.push("a credential entry has an empty `name`".to_string());
        }

        match cred.auth_style.as_str() {
            "bearer" => {}
            "header" => {
                if cred.header_name.as_deref().unwrap_or("").is_empty() {
                    errors.push(format!(
                        "{label}: `auth_style = \"header\"` requires `header_name` to be set"
                    ));
                }
            }
            other => {
                errors.push(format!(
                    "{label}: unknown `auth_style` \"{other}\" — must be \"bearer\" or \"header\""
                ));
            }
        }

        if cred.aliases.is_empty() && cred.prefixes.is_empty() {
            warnings.push(format!(
                "{label}: no `aliases` and no `prefixes` — \
                 envy cannot detect this credential during a scan; \
                 add at least one alias or prefix"
            ));
        }
    }

    // ── health checks ────────────────────────────────────────────────────────
    for hc in &descriptor.health_checks {
        let label = format!("health_check \"{}\"", hc.id);

        if hc.id.is_empty() {
            errors.push("a health_check entry has an empty `id`".to_string());
        }

        if !hc.method.eq_ignore_ascii_case("GET") {
            errors.push(format!(
                "{label}: only `method = \"GET\"` is allowed for health checks \
                 (envy never uses write operations to validate a credential)"
            ));
        }

        if !hc.path.starts_with('/') {
            errors.push(format!(
                "{label}: `path` must start with \"/\" (got \"{}\")",
                hc.path
            ));
        }

        if !hc.safe {
            warnings.push(format!(
                "{label}: `safe = false` — this health check will require \
                 explicit user consent before envy executes it"
            ));
        }

        for status in &hc.success_statuses {
            if !(200..300).contains(status) {
                warnings.push(format!(
                    "{label}: success_status {status} is outside the 2xx range"
                ));
            }
        }
    }

    (errors, warnings)
}

fn validate(path: PathBuf, global: &GlobalArgs) -> anyhow::Result<()> {
    let descriptor = parse_descriptor(&path)?;
    let (errors, warnings) = check_descriptor(&descriptor);
    let ok = errors.is_empty();

    if global.json {
        let result = serde_json::json!({
            "path": path.display().to_string(),
            "id": descriptor.id,
            "valid": ok,
            "errors": errors,
            "warnings": warnings,
        });
        println!("{}", serde_json::to_string(&result)?);
    } else if !global.quiet {
        println!("Validating {}...", path.display());
        for w in &warnings {
            println!("  ⚠  {w}");
        }
        for e in &errors {
            println!("  ✗  {e}");
        }
        if ok {
            if warnings.is_empty() {
                println!("  ✓  Descriptor is valid.");
            } else {
                println!("  ✓  Descriptor is valid (with warnings above).");
            }
        } else {
            println!("\nDescriptor has errors — fix them before installing.");
        }
    }

    if !ok {
        anyhow::bail!("descriptor validation failed");
    }
    Ok(())
}

fn install(path: PathBuf, force: bool, global: &GlobalArgs) -> anyhow::Result<()> {
    let descriptor = parse_descriptor(&path)?;
    let (errors, warnings) = check_descriptor(&descriptor);

    if !global.quiet {
        for w in &warnings {
            println!("  ⚠  {w}");
        }
    }
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("  ✗  {e}");
        }
        anyhow::bail!("descriptor validation failed — fix the errors above before installing");
    }

    let dir = envy_core::provider::user_provider_dir()
        .context("could not determine envy's provider directory (no home directory found)")?;
    std::fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;

    let dest = dir.join(format!("{}.toml", descriptor.id));
    if dest.exists() {
        if !force {
            anyhow::bail!(
                "{} is already installed at {} — pass --force to overwrite (backs it up to \
                 <file>.bak first)",
                descriptor.id,
                dest.display()
            );
        }
        let backup = PathBuf::from(format!("{}.bak", dest.display()));
        std::fs::copy(&dest, &backup).with_context(|| {
            format!(
                "failed to back up {} to {}",
                dest.display(),
                backup.display()
            )
        })?;
    }

    std::fs::copy(&path, &dest)
        .with_context(|| format!("failed to copy {} to {}", path.display(), dest.display()))?;

    if global.json {
        println!(
            r#"{{"status":"ok","id":"{}","installed_at":"{}"}}"#,
            descriptor.id,
            dest.display()
        );
    } else if !global.quiet {
        println!(
            "Installed provider '{}' at {}",
            descriptor.id,
            dest.display()
        );
    }
    Ok(())
}

fn list(global: &GlobalArgs) -> anyhow::Result<()> {
    let (registry, warnings) = envy_core::provider::Registry::load()?;
    let descriptors = registry.descriptors();

    if global.json {
        let providers: Vec<_> = descriptors
            .iter()
            .map(|d| {
                serde_json::json!({
                    "id": d.id,
                    "name": d.name,
                    "domains": d.domains,
                    "credentials": d.credentials.iter().map(|c| &c.name).collect::<Vec<_>>(),
                })
            })
            .collect();
        let warnings_json: Vec<_> = warnings
            .iter()
            .map(
                |w| serde_json::json!({"path": w.path.display().to_string(), "message": w.message}),
            )
            .collect();
        println!(
            "{}",
            serde_json::to_string(
                &serde_json::json!({"providers": providers, "warnings": warnings_json})
            )?
        );
        return Ok(());
    }

    if !global.quiet {
        if let Some(dir) = envy_core::provider::user_provider_dir() {
            println!("Provider directory: {}\n", dir.display());
        }
        for w in &warnings {
            println!(
                "  ⚠  ignoring invalid descriptor at {}: {}",
                w.path.display(),
                w.message
            );
        }
        if descriptors.is_empty() {
            println!("No providers installed.");
        }
        for d in descriptors {
            println!(
                "{}  ({})  domains={}  credentials={}",
                d.id,
                d.name,
                d.domains.join(","),
                d.credentials
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
    }
    Ok(())
}
