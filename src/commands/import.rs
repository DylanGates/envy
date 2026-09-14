use std::path::PathBuf;

use crate::cli::GlobalArgs;

pub fn run(_encrypted: PathBuf, global: &GlobalArgs) -> anyhow::Result<()> {
    super::not_implemented("import", global)
}
