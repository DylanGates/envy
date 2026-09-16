use std::path::PathBuf;

use envy_core::provider::descriptor::ProviderDescriptor;

use crate::cli::{GlobalArgs, ProviderAction};

pub fn run(action: ProviderAction, global: &GlobalArgs) -> anyhow::Result<()> {
    match action {
        ProviderAction::Validate { path } => validate(path, global),
    }
}

fn validate(path: PathBuf, global: &GlobalArgs) -> anyhow::Result<()> {
    let source = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("could not read {}: {e}", path.display()))?;

    let descriptor: ProviderDescriptor = toml::from_str(&source)
        .map_err(|e| anyhow::anyhow!("TOML parse error in {}: {e}", path.display()))?;

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

    // ── output ───────────────────────────────────────────────────────────────
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
