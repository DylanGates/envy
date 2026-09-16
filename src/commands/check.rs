use std::path::PathBuf;

use anyhow::bail;
use envy_core::check::{AdHocCheckRequest, CatalogedCheckRequest};

use crate::cli::GlobalArgs;

pub fn run(
    reference: Option<String>,
    project: Option<PathBuf>,
    url: Option<String>,
    auth_style: String,
    header_name: Option<String>,
    provider: Option<String>,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    if project.is_some() {
        return super::not_implemented("check --project", global);
    }

    let Some(reference) = reference else {
        bail!("REFERENCE (the vault secret name to check) is required");
    };

    if url.is_some() && provider.is_some() {
        bail!("pass either --url (ad-hoc) or --provider (cataloged), not both");
    }

    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;

    let result = match (provider, url) {
        (Some(provider_id), None) => {
            let (registry, warnings) = envy_core::provider::Registry::load()?;
            for w in &warnings {
                if !global.quiet {
                    eprintln!(
                        "envy check: ignoring invalid provider descriptor at {}: {}",
                        w.path.display(),
                        w.message
                    );
                }
            }
            let req = CatalogedCheckRequest {
                subject: "cli",
                secret_name: &reference,
                provider_id: &provider_id,
            };
            envy_core::check::check_cataloged(&vault, &registry, &req)?
        }
        (None, Some(url)) => {
            let req = AdHocCheckRequest {
                subject: "cli",
                secret_name: &reference,
                url: &url,
                auth_style: &auth_style,
                header_name: header_name.as_deref(),
            };
            envy_core::check::check_adhoc(&vault, &req)?
        }
        (None, None) => {
            bail!(
                "checking a credential needs either --url (ad-hoc testing, e.g. `envy check \
                 {reference} --url https://api.example.com/me`) or --provider (cataloged \
                 testing against an installed descriptor, e.g. `envy check {reference} \
                 --provider stripe` — see `envy provider list`)"
            );
        }
        (Some(_), Some(_)) => unreachable!("rejected above"),
    };

    if global.json {
        let json = serde_json::json!({
            "status": result.status.as_str(),
            "httpStatus": result.http_status,
            "detail": result.detail,
        });
        println!("{}", serde_json::to_string(&json)?);
    } else if !global.quiet {
        match (&result.detail, result.http_status) {
            (Some(detail), _) => println!("{}: {} — {}", reference, result.status.as_str(), detail),
            (None, Some(code)) => println!("{}: {} (HTTP {code})", reference, result.status.as_str()),
            (None, None) => println!("{}: {} (no response)", reference, result.status.as_str()),
        }
    }
    Ok(())
}
