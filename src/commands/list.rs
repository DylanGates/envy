use crate::cli::GlobalArgs;

pub fn run(global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    let secrets = vault.list_secrets()?;

    if global.json {
        println!("{}", serde_json::to_string(&secrets)?);
    } else if !global.quiet {
        if secrets.is_empty() {
            println!("No secrets in vault.");
        }
        for secret in &secrets {
            let stale_tag = if secret.is_stale {
                format!(
                    " \x1b[33m[STALE: {}d old - rotation recommended]\x1b[0m",
                    secret.age_days
                )
            } else {
                format!(" ({}d old)", secret.age_days)
            };
            println!(
                "{:<24} provider={:<12} kind={:<12} risk={:<6}{}",
                secret.name,
                secret.provider.as_deref().unwrap_or("-"),
                secret.credential_kind.as_deref().unwrap_or("-"),
                secret.risk.as_deref().unwrap_or("-"),
                stale_tag
            );
        }
    }
    Ok(())
}
