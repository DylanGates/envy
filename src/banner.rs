#![allow(dead_code)]
//! Terminal presentation, Pixel & ASCII wordmark banners for envy.

/// Precision Clean Block Matrix Font
pub const ENVY_PIXEL_BANNER: &str = r#"
███████╗███╗   ██╗██╗   ██╗██╗   ██╗
██╔════╝████╗  ██║██║   ██║╚██╗ ██╔╝
█████╗  ██╔██╗ ██║██║   ██║ ╚████╔╝ 
██╔══╝  ██║╚██╗██║╚██╗ ██╔╝  ╚██╔╝  
███████╗██║ ╚████║ ╚████╔╝    ██║   
╚══════╝╚═╝  ╚═══╝  ╚═══╝     ╚═╝   
"#;

/// Modern Compact Slant Pixel Font
pub const ENVY_SLANT_BANNER: &str = r#"
   ______ ____  _    ____  __
  / ____// __ \| |  / /\ \/ /
 / __/  / / / /| | / /  \  / 
/ /___ / /_/ / | |/ /   / /  
\____//_____/  |___/   /_/   
"#;

/// Futuristic Cyber Grid Font
pub const ENVY_CYBER_BANNER: &str = r#"
┌─┐┬─┐┬  ┬┬ ┬
├┤ │ │└┐┌┘└┬┘
└─┘┴ ┴ └┘  ┴ 
"#;

/// Minimalist Outline Font
pub const ENVY_MINIMAL_BANNER: &str = r#"
 █▀▀ █▄ █ █ █ █ █
 █▀▀ █ ▀█ ▀▄▀ ▀█▀
 ▀▀▀ ▀  ▀  ▀   ▀ 
"#;

/// High-tech Braille / Micro Pixel Font
pub const ENVY_MICRO_BANNER: &str = r#"
⢰⣶⣶⣶⡆⢸⣶⣶⡆⠀⢰⣶⠀⣶⡆⢰⣶⠀⣶⡆
⢸⣿⣤⣤⠀⢸⣿⢹⣿⠀⢸⣿⠀⣿⡇⠀⢿⣶⡿⠀
⢸⣿⠛⠛⠀⢸⣿⠀⣿⡇⢸⣿⠀⣿⡇⠀⠈⣿⡇⠀
⠸⠿⠿⠿⠇⠸⠿⠀⠿⠇⠀⠿⠿⠿⠃⠀⠀⠿⠇⠀
"#;

/// Prints the canonical `envy` Pixel banner in bright cyberpunk green.
pub fn print_banner() {
    println!(
        "\x1b[1;38;2;0;255;136m{}\x1b[0m",
        ENVY_PIXEL_BANNER.trim_matches('\n')
    );
}
