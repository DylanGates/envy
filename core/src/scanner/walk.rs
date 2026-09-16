//! Gitignore-aware file walker for the scanner (FR-04).
//!
//! Uses the `ignore` crate (from the ripgrep family) so `.gitignore`,
//! `.ignore`, and standard ignore rules are respected automatically.
//! Also hard-skips directories that are never interesting for secrets
//! and files that are too large or appear binary.

use std::path::PathBuf;

/// Hard-skip these directory names regardless of ignore rules.
const SKIP_DIRS: &[&str] = &[
    "target",
    "node_modules",
    ".git",
    "dist",
    ".envy",
    "__pycache__",
    ".next",
    ".nuxt",
    "vendor",
];

/// Files larger than this are skipped (secrets are never in huge files).
const MAX_FILE_BYTES: u64 = 1024 * 1024; // 1 MiB

/// Returns an iterator of file paths to scan under `root`.
/// Directories in `SKIP_DIRS` are pruned; binary files and oversized
/// files are excluded.
pub(super) fn walk(root: &std::path::Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    let walker = ignore::WalkBuilder::new(root)
        .hidden(false) // include dotfiles (e.g. .env)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .filter_entry(|entry| {
            // Prune hard-skip directories early (before recursing into them).
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                if let Some(name) = entry.file_name().to_str() {
                    if SKIP_DIRS.contains(&name) {
                        return false;
                    }
                }
            }
            true
        })
        .build();

    for result in walker {
        let entry = match result {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Only regular files.
        if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            continue;
        }

        let path = entry.into_path();

        // Skip oversized files.
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.len() > MAX_FILE_BYTES {
                continue;
            }
        }

        // Skip files whose extension suggests binary content.
        if is_binary_extension(&path) {
            continue;
        }

        paths.push(path);
    }

    paths
}

fn is_binary_extension(path: &std::path::Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => matches!(
            ext,
            "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "webp"
                | "ico"
                | "svg"
                | "pdf"
                | "zip"
                | "tar"
                | "gz"
                | "bz2"
                | "xz"
                | "7z"
                | "rar"
                | "exe"
                | "dll"
                | "so"
                | "dylib"
                | "a"
                | "lib"
                | "wasm"
                | "class"
                | "pyc"
                | "pyo"
                | "mp4"
                | "mp3"
                | "wav"
                | "ogg"
                | "flac"
                | "ttf"
                | "otf"
                | "woff"
                | "woff2"
                | "db"
                | "sqlite"
                | "sqlite3"
                | "lock" // Cargo.lock, package-lock.json have no secrets
        ),
        None => false,
    }
}
