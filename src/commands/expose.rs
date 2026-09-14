use crate::cli::{ExposeAction, GlobalArgs};

pub fn run(action: ExposeAction, global: &GlobalArgs) -> anyhow::Result<()> {
    match action {
        ExposeAction::Install => super::not_implemented("expose install", global),
    }
}
