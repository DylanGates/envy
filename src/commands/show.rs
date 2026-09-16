use anyhow::bail;

use crate::cli::GlobalArgs;

pub fn run(reference: String, metadata_only: bool, global: &GlobalArgs) -> anyhow::Result<()> {
    if !metadata_only {
        bail!(
            "revealing a secret's value isn't implemented yet (needs a consent flow) — \
             pass --metadata-only to see {reference}'s metadata"
        );
    }

    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    let meta = vault.get_secret_metadata(&reference)?;

    if global.json {
        println!("{}", serde_json::to_string(&meta)?);
    } else if !global.quiet {
        println!("name:            {}", meta.name);
        println!("reference:       envy://{}", meta.name);
        println!("provider:        {}", meta.provider.as_deref().unwrap_or("-"));
        println!("credential_kind: {}", meta.credential_kind.as_deref().unwrap_or("-"));
        println!("risk:            {}", meta.risk.as_deref().unwrap_or("-"));
        println!("created_at:      {}", meta.created_at);
        println!("updated_at:      {}", meta.updated_at);
    }
    Ok(())
}
