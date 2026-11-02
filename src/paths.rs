//! Path canonicalisation for `path_under` argument constraints.
//!
//! A path is only compared against the allowed roots after every `..` and
//! symlink has been resolved by the filesystem, so `root/../etc/passwd` and
//! `root/link-to-etc/passwd` are judged by where they really point.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

/// Resolves an allowed root from the policy file: `~/` expands to the home
/// directory, relative paths are taken relative to the policy file, and the
/// root must exist.
pub fn resolve_root(raw: &str, base_dir: &Path) -> io::Result<PathBuf> {
    let expanded = match raw.strip_prefix("~/") {
        Some(rest) => std::env::home_dir()
            .ok_or_else(|| io::Error::other("cannot expand `~`: no home directory"))?
            .join(rest),
        None => base_dir.join(raw),
    };
    fs::canonicalize(&expanded)
}

/// Resolves a path argument the way the server will see it: relative to the
/// shared working directory, with symlinks and `..` resolved. Paths that do
/// not exist yet (a file about to be written) are accepted as long as their
/// deepest existing ancestor resolves cleanly.
pub fn resolve_argument(raw: &str) -> Result<PathBuf, String> {
    if raw.is_empty() {
        return Err("path is empty".into());
    }
    if raw.contains('\0') {
        return Err("path contains a NUL byte".into());
    }
    // Many servers expand `~` themselves; the firewall cannot know which home
    // they would use, so refuse rather than guess.
    if raw.starts_with('~') {
        return Err("paths starting with `~` are not allowed".into());
    }
    let path = Path::new(raw);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("cannot read working directory: {e}"))?
            .join(path)
    };
    canonicalize_lenient(&absolute).map_err(|e| format!("cannot resolve path: {e}"))
}

pub fn is_within(path: &Path, roots: &[PathBuf]) -> bool {
    // `Path::starts_with` compares whole components, so `/srv/app2` is not
    // inside `/srv/app`.
    roots.iter().any(|root| path.starts_with(root))
}

fn canonicalize_lenient(path: &Path) -> io::Result<PathBuf> {
    let mut existing = path;
    let mut missing = Vec::new();
    loop {
        match fs::canonicalize(existing) {
            Ok(mut resolved) => {
                for component in missing.iter().rev() {
                    match component {
                        Component::Normal(name) => resolved.push(name),
                        // `..` after a missing directory cannot be resolved
                        // safely; the OS would reject the path anyway.
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "`..` after a non-existent component",
                            ));
                        }
                    }
                }
                return Ok(resolved);
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                // A dangling symlink also reports NotFound, but writing
                // through it would create its target, wherever that is.
                if fs::symlink_metadata(existing).is_ok() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "dangling symlink",
                    ));
                }
                let (Some(last), Some(parent)) =
                    (existing.components().next_back(), existing.parent())
                else {
                    return Err(err);
                };
                missing.push(last);
                existing = parent;
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory layout under the system temp dir:
    /// `<tmp>/root/{file.txt, sub/}` and `<tmp>/outside/secret.txt`.
    fn fixture(name: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("mcp-firewall-paths-{name}"));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("root/sub")).unwrap();
        fs::create_dir_all(base.join("outside")).unwrap();
        fs::write(base.join("root/file.txt"), "ok").unwrap();
        fs::write(base.join("outside/secret.txt"), "no").unwrap();
        let root = fs::canonicalize(base.join("root")).unwrap();
        (base, root)
    }

    fn allowed(raw: &Path, root: &Path) -> bool {
        resolve_argument(raw.to_str().unwrap())
            .map(|p| is_within(&p, &[root.to_path_buf()]))
            .unwrap_or(false)
    }

    #[test]
    fn accepts_paths_inside_root() {
        let (_base, root) = fixture("inside");
        assert!(allowed(&root.join("file.txt"), &root));
        assert!(allowed(&root.join("sub/new-file.txt"), &root));
        assert!(allowed(&root.join("sub/../file.txt"), &root));
        assert!(allowed(&root.join("new-dir/new-file.txt"), &root));
    }

    #[test]
    fn rejects_dot_dot_escapes() {
        let (_base, root) = fixture("dotdot");
        assert!(!allowed(&root.join("../outside/secret.txt"), &root));
        assert!(!allowed(&root.join("sub/../../outside/secret.txt"), &root));
        assert!(!allowed(&root.join("missing/../../outside/x"), &root));
    }

    #[test]
    fn sibling_with_common_prefix_is_outside() {
        let (base, root) = fixture("prefix");
        fs::create_dir_all(base.join("root2")).unwrap();
        assert!(!allowed(&base.join("root2"), &root));
    }

    #[test]
    fn rejects_tilde_empty_and_nul() {
        assert!(resolve_argument("~/file").is_err());
        assert!(resolve_argument("").is_err());
        assert!(resolve_argument("a\0b").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_judged_by_their_target() {
        use std::os::unix::fs::symlink;
        let (base, root) = fixture("symlink");
        symlink(base.join("outside"), root.join("escape")).unwrap();
        symlink(root.join("file.txt"), root.join("alias")).unwrap();
        symlink(base.join("outside/not-yet"), root.join("dangling")).unwrap();

        assert!(!allowed(&root.join("escape/secret.txt"), &root));
        assert!(!allowed(&root.join("escape/new.txt"), &root));
        assert!(!allowed(&root.join("dangling"), &root));
        assert!(allowed(&root.join("alias"), &root));
    }
}
