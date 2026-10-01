use std::io::Write;
use std::path::PathBuf;

use envy_core::provider::Registry;

use crate::cli::GlobalArgs;

pub fn run(path: Option<PathBuf>, global: &GlobalArgs) -> anyhow::Result<()> {
    let root = match path {
        Some(p) => p,
        None => std::env::current_dir()?,
    };

    let cwd = std::env::current_dir()?;
    let vault = envy_core::vault::open(&cwd)?;

    let (registry, warnings) = Registry::load()?;
    for w in &warnings {
        if !global.quiet {
            eprintln!(
                "envy scan: ignoring invalid provider descriptor at {}: {}",
                w.path.display(),
                w.message
            );
        }
    }

    if !global.quiet && !global.json {
        eprintln!("Scanning {}...", root.display());
    }

    let result = envy_core::scanner::scan(&root, &registry);

    // Report read errors as warnings, not failures.
    for (path, err) in &result.read_errors {
        if !global.quiet {
            eprintln!("  ⚠  could not read {}: {err}", path.display());
        }
    }

    let findings: Vec<&envy_core::scanner::Candidate> = result
        .candidates
        .iter()
        .filter(|c| c.looks_like_secret())
        .collect();

    // Group findings by variable name to spot the same name defined in
    // more than one .env-family file — envy used to silently drop every
    // occurrence but the first, so this was previously invisible.
    let cross_file_duplicates: Vec<(&str, Vec<&std::path::Path>)> = {
        let mut by_name: std::collections::BTreeMap<&str, Vec<&std::path::Path>> =
            std::collections::BTreeMap::new();
        for c in &findings {
            let paths = by_name.entry(c.var_name.as_str()).or_default();
            if !paths.contains(&c.path.as_path()) {
                paths.push(c.path.as_path());
            }
        }
        by_name
            .into_iter()
            .filter(|(_, paths)| paths.len() > 1)
            .collect()
    };

    if global.json {
        let findings_json: Vec<_> = findings
            .iter()
            .map(|c| {
                serde_json::json!({
                    "path": c.path.display().to_string(),
                    "line": c.line,
                    "var_name": c.var_name,
                    "masked_value": c.masked_value,
                    "entropy": c.entropy,
                    "provider": c.findings.first().map(|f| &f.provider_id),
                    "credential_name": c.findings.first().map(|f| &f.credential_name),
                    "confidence": c.findings.first().map(|f| format!("{:?}", f.confidence)),
                    "risk": c.findings.first().map(|f| &f.risk),
                })
            })
            .collect();
        let env_files_json: Vec<String> = result
            .env_files
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let cross_file_duplicates_json: Vec<_> = cross_file_duplicates
            .iter()
            .map(|(var_name, paths)| {
                serde_json::json!({
                    "var_name": var_name,
                    "paths": paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "findings": findings_json,
                "env_files": env_files_json,
                "cross_file_duplicates": cross_file_duplicates_json,
            }))?
        );
        return Ok(());
    }

    if result.env_files.len() > 1 && !global.quiet {
        let names: Vec<String> = result
            .env_files
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        println!(
            "⚠  {} .env-family files found: {} — envy can't tell which one your app \
             actually loads; review this before assuming secrets are only in one place.\n",
            result.env_files.len(),
            names.join(", ")
        );
    }

    if !cross_file_duplicates.is_empty() && !global.quiet {
        for (var_name, paths) in &cross_file_duplicates {
            let names: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
            println!(
                "⚠  '{var_name}' is defined in more than one file: {} — values may differ; \
                 envy imports each one under the same vault name, so only the first import \
                 wins.\n",
                names.join(", ")
            );
        }
    }

    if findings.is_empty() {
        if !global.quiet {
            println!("No credential candidates found.");
        }
        return Ok(());
    }

    if !global.quiet {
        println!("\nFound {} candidate(s):\n", findings.len());
        for (i, c) in findings.iter().enumerate() {
            let provider_label = c
                .findings
                .first()
                .map(|f| {
                    format!(
                        "{}  {}  confidence:{:?}",
                        f.provider_name, f.credential_name, f.confidence
                    )
                })
                .unwrap_or_else(|| format!("unknown provider  entropy:{:.2}", c.entropy));
            println!(
                "  [{:>2}]  {}:{}  {}  =  {}",
                i + 1,
                c.path.display(),
                c.line,
                c.var_name,
                c.masked_value
            );
            println!("         {provider_label}");
            println!();
        }
    }

    // Interactive import prompt (skipped in --non-interactive or --dry-run).
    if global.non_interactive || global.dry_run {
        if !global.quiet {
            if global.dry_run {
                println!("Dry run — no secrets imported.");
            } else {
                println!("Non-interactive mode — run without --non-interactive to import.");
            }
        }
        return Ok(());
    }

    print!("Import which? (comma-separated numbers, or Enter to skip): ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim();

    if input.is_empty() {
        if !global.quiet {
            println!("Nothing imported.");
        }
        return Ok(());
    }

    let mut imported = 0usize;
    let mut skipped = 0usize;

    for token in input.split(',') {
        let token = token.trim();
        let Ok(n) = token.parse::<usize>() else {
            eprintln!("  Skipping invalid selection '{token}'");
            continue;
        };
        if n == 0 || n > findings.len() {
            eprintln!("  Skipping out-of-range selection {n}");
            continue;
        }
        let candidate = findings[n - 1];
        match candidate.import_into(&vault) {
            Ok(()) => {
                if !global.quiet {
                    println!(
                        "  ✓  Imported '{}' (envy://{})",
                        candidate.var_name, candidate.var_name
                    );
                }
                imported += 1;
            }
            Err(envy_core::CoreError::SecretAlreadyExists(_)) => {
                if !global.quiet {
                    println!(
                        "  –  '{}' already exists in vault, skipped",
                        candidate.var_name
                    );
                }
                skipped += 1;
            }
            Err(e) => {
                eprintln!("  ✗  Failed to import '{}': {e}", candidate.var_name);
            }
        }
    }

    if !global.quiet {
        println!("\nImported {imported}, skipped {skipped}.");
    }
    Ok(())
}
