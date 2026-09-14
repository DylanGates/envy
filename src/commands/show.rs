use crate::cli::GlobalArgs;

pub fn run(_reference: String, _metadata_only: bool, global: &GlobalArgs) -> anyhow::Result<()> {
    super::not_implemented("show", global)
}
