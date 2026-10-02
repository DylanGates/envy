use crate::cli::GlobalArgs;

pub fn run(global: &GlobalArgs) -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let policy = envy_core::policy::load_policy(&cwd)?;

    if global.json {
        println!("{}", serde_json::to_string_pretty(&policy)?);
    } else if !global.quiet {
        println!("Project Governance & Policy Grid (.envy/policy.toml)\n");
        println!("Default Access:                {}", policy.default.access);
        println!(
            "Require Consent For Writes:    {}",
            policy.default.require_consent_for_write
        );
        println!();

        if policy.agents.is_empty() {
            println!("No agent-specific policies configured (using default).");
        } else {
            println!("Configured Agent Profiles ({}):", policy.agents.len());
            for (name, agent) in &policy.agents {
                let providers = if agent.allowed_providers.is_empty() {
                    "all".to_string()
                } else {
                    agent.allowed_providers.join(", ")
                };
                println!(
                    "  [{name}]  providers: [{providers}]  read_only: {}  writes_with_consent: {}",
                    agent.allow_read_only, agent.allow_write_with_consent
                );
            }
        }
        println!();

        if policy.hosts.is_empty() {
            println!("No host-specific command whitelists configured.");
        } else {
            println!("Configured Host Policies ({}):", policy.hosts.len());
            for (host, h_policy) in &policy.hosts {
                let cmds = if h_policy.allowed_commands.is_empty() {
                    "unrestricted".to_string()
                } else {
                    h_policy.allowed_commands.join(", ")
                };
                println!(
                    "  [{host}]  known_host_required: {}  allowed_commands: [{cmds}]",
                    h_policy.known_host_required
                );
            }
        }
    }
    Ok(())
}
