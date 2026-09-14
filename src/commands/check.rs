use std::path::PathBuf;

use anyhow::bail;
use envy_core::check::AdHocCheckRequest;

use crate::cli::GlobalArgs;

pub fn run(
    reference: Option<String>,
    project: Option<PathBuf>,
    url: Option<String>,
    auth_style: String,
    header_name: Option<String>,
    global: &GlobalArgs,
) -> anyhow::Result<()> {
    if project.is_some() {
        return super::not_implemented("check --project", global);
    }

    let Some(reference) = reference else {
        bail!("REFERENCE (the vault secret name to check) is required");
    };

    let Some(url) = url else {
        bail!(
            "checking a credential without --url isn't implemented yet (that needs a cataloged \
             provider descriptor — see docs/provider-testing-vision.md). Pass --url for ad-hoc \
             testing, e.g. `envy check {reference} --url https://api.example.com/me`"
        );
    };

    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;

    let req = AdHocCheckRequest {
        subject: "cli",
        secret_name: &reference,
        url: &url,
        auth_style: &auth_style,
        header_name: header_name.as_deref(),
    };
    let result = envy_core::check::check_adhoc(&vault, &req)?;

    if global.json {
        let http_status = result
            .http_status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "null".to_string());
        println!(
            r#"{{"status":"{}","httpStatus":{}}}"#,
            result.status.as_str(),
            http_status
        );
    } else if !global.quiet {
        match result.http_status {
            Some(code) => println!("{}: {} (HTTP {code})", reference, result.status.as_str()),
            None => println!("{}: {} (no response)", reference, result.status.as_str()),
        }
    }
    Ok(())
}
