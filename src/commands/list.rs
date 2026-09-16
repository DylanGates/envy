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
            println!(
                "{}  provider={}  kind={}  risk={}",
                secret.name,
                secret.provider.as_deref().unwrap_or("-"),
                secret.credential_kind.as_deref().unwrap_or("-"),
                secret.risk.as_deref().unwrap_or("-"),
            );
        }
    }
    Ok(())
}
