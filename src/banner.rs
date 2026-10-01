#![allow(dead_code)]
//! Terminal presentation, ASCII wordmark banner, and styling helpers for interactive envy flows.
pub const ENVY_BANNER: &str = r#"
 ▄████▄   ███▄    █  ██▒   █▓▓██   ██▓
▒██▀ ▀█   ██ ▀█   █ ▓██░   █▒ ▒██  ██▒
▒▓█    ▄ ▓██  ▀█ ██▒ ▓██  █▒░  ▒██ ██░
▒▓▓▄ ▄██▒▓██▒  ▐▌██▒  ▒██ █░░  ░ ▐██▓░
▒ ▓███▀ ░▒██░   ▓██░   ▒▀█░    ░ ██▒▓░
░ ░▒ ▒  ░░ ▒░   ▒ ▒    ░ ▐░     ██▒▒▒ 
  ░  ▒   ░ ░░   ░ ▒░   ░ ░░   ▓██ ░▒░ 
░           ░   ░ ░      ░░   ▒ ▒ ░░  
░ ░               ░       ░   ░ ░     
░                        ░    ░ ░     
"#;

pub const ENVY_OUTLINE_BANNER: &str = r#"
  ___ _ ____   ____  _ 
 / _ \ '_ \ \ / / || |
|  __/ | | \ V / \_, |
 \___|_| |_|\_/  |__/ 
"#;

pub const ENVY_CORNER_BANNER: &str = r#"
┌─┐┌┐┌┬  ┬┬ ┬
├┤ │││└┐┌┘└┬┘
└─┘┘└┘ └┘  ┴ 
"#;

/// Prints the canonical `envy` ASCII banner in bright green.
pub fn print_banner() {
    println!("\x1b[1;32m{}\x1b[0m", ENVY_CORNER_BANNER.trim_matches('\n'));
}
