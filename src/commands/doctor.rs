use anyhow::bail;

use crate::cli::GlobalArgs;

pub fn run(global: &GlobalArgs) -> anyhow::Result<()> {
    let report = envy_core::doctor::run();
    let all_passed = report.all_passed();

    if global.json {
        let steps: Vec<_> = report
            .steps
            .iter()
            .map(|step| match &step.outcome {
                Ok(detail) => serde_json::json!({"step": step.name, "ok": true, "detail": detail}),
                Err(message) => serde_json::json!({"step": step.name, "ok": false, "detail": message}),
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({"passed": all_passed, "steps": steps}))?
        );
    } else if !global.quiet {
        for step in &report.steps {
            match &step.outcome {
                Ok(detail) => println!("✓ {}: {detail}", step.name),
                Err(message) => println!("✗ {}: {message}", step.name),
            }
        }
    }

    if !all_passed {
        bail!("envy doctor found a problem — see the failed step(s) above");
    }
    Ok(())
}
