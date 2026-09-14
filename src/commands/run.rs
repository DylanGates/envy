use crate::cli::GlobalArgs;

pub fn run(_command: Vec<String>, global: &GlobalArgs) -> anyhow::Result<()> {
    super::not_implemented("run", global)
}
