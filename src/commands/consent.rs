use envy_core::audit::AuditEvent;

use crate::cli::{ConsentAction, GlobalArgs};

pub fn run(action: ConsentAction, global: &GlobalArgs) -> anyhow::Result<()> {
    match action {
        ConsentAction::Grant {
            provider,
            operation,
            ttl,
        } => grant(provider, operation, ttl, global),
        ConsentAction::Revoke {
            provider,
            operation,
        } => revoke(provider, operation, global),
        ConsentAction::List => list(global),
    }
}

fn grant(
    provider: String,
    operation: String,
    ttl: String,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    let ttl_duration = envy_core::consent::parse_ttl(&ttl)?;

    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    let grant = vault.grant_consent(&provider, &operation, ttl_duration, Some("cli"))?;

    vault.log_event(&AuditEvent {
        subject: Some("cli"),
        project: Some(&cwd.to_string_lossy()),
        provider: Some(&provider),
        operation: "consent_grant",
        endpoint_host: None,
        outcome: "success",
        redaction_summary: Some(&format!(
            "granted consent for '{operation}' until {}",
            grant.expires_at
        )),
    })?;

    if global.json {
        println!("{}", serde_json::to_string(&grant)?);
    } else if !global.quiet {
        println!(
            "Granted consent: {provider} / {operation}, expires {} (UTC)",
            grant.expires_at
        );
    }
    Ok(())
}

fn revoke(provider: String, operation: String, global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    let revoked = vault.revoke_consent(&provider, &operation)?;

    if revoked > 0 {
        vault.log_event(&AuditEvent {
            subject: Some("cli"),
            project: Some(&cwd.to_string_lossy()),
            provider: Some(&provider),
            operation: "consent_revoke",
            endpoint_host: None,
            outcome: "success",
            redaction_summary: Some(&format!("revoked consent for '{operation}'")),
        })?;
    }

    if global.json {
        println!(r#"{{"revoked":{revoked}}}"#);
    } else if !global.quiet {
        if revoked > 0 {
            println!("Revoked consent: {provider} / {operation}");
        } else {
            println!("No active consent grant found for {provider} / {operation}.");
        }
    }
    Ok(())
}

fn list(global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;
    let grants = vault.list_consents()?;

    if global.json {
        println!("{}", serde_json::to_string(&grants)?);
    } else if !global.quiet {
        if grants.is_empty() {
            println!("No consent grants recorded.");
        }
        for grant in &grants {
            let status = if grant.is_active {
                "active"
            } else if grant.revoked_at.is_some() {
                "revoked"
            } else {
                "expired"
            };
            println!(
                "{}  {}  {}  granted={}  expires={}  ({status})",
                grant.provider,
                grant.operation,
                grant.subject.as_deref().unwrap_or("-"),
                grant.granted_at,
                grant.expires_at,
            );
        }
    }
    Ok(())
}
