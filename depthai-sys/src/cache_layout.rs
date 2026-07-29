use std::{
    env,
    ffi::OsStr,
    path::{Path, PathBuf},
};

pub(crate) const CACHE_DIR_ENV: &str = "DEPTHAI_RS_CACHE_DIR";
const DEFAULT_CACHE_DIR_NAME: &str = ".depthai-rs";

pub(crate) fn cache_root_from_env() -> Result<PathBuf, String> {
    let configured = env::var_os(CACHE_DIR_ENV);
    let home = user_home_dir();
    resolve_cache_root(configured.as_deref(), home.as_deref())
}

pub(crate) fn depthai_core_cache_dir(
    cache_root: &Path,
    tag: &str,
    target: &str,
    build_variant: &str,
) -> PathBuf {
    cache_root
        .join("depthai-core")
        .join(tag)
        .join(target)
        .join(build_variant)
}

pub(crate) fn opencv_cache_dir(cache_root: &Path, version: &str, target: &str) -> PathBuf {
    cache_root.join("opencv").join(version).join(target)
}

fn resolve_cache_root(configured: Option<&OsStr>, home: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(configured) = configured {
        if configured.is_empty() {
            return Err(format!(
                "{CACHE_DIR_ENV} is set but empty; set it to an absolute directory or unset it"
            ));
        }

        let configured = PathBuf::from(configured);
        if !configured.is_absolute() {
            return Err(format!(
                "{CACHE_DIR_ENV} must be an absolute path, got '{}'",
                configured.display()
            ));
        }
        return Ok(configured);
    }

    home.map(|path| path.join(DEFAULT_CACHE_DIR_NAME))
        .ok_or_else(|| {
            format!(
                "Unable to determine the user home directory; set {CACHE_DIR_ENV} to an absolute directory"
            )
        })
}

fn user_home_dir() -> Option<PathBuf> {
    let primary = if cfg!(windows) {
        env::var_os("USERPROFILE")
    } else {
        env::var_os("HOME")
    };

    non_empty_path(primary).or_else(|| {
        let fallback = if cfg!(windows) {
            env::var_os("HOME")
        } else {
            env::var_os("USERPROFILE")
        };
        non_empty_path(fallback)
    })
}

fn non_empty_path(value: Option<impl AsRef<OsStr>>) -> Option<PathBuf> {
    value.and_then(|value| {
        let value = value.as_ref();
        (!value.is_empty()).then(|| PathBuf::from(value))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn absolute_cache_path() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"C:\native-cache")
        } else {
            PathBuf::from("/native-cache")
        }
    }

    #[test]
    fn defaults_to_dot_depthai_rs_in_home() {
        let home = absolute_cache_path().join("home");

        let cache = resolve_cache_root(None, Some(&home)).unwrap();

        assert_eq!(cache, home.join(".depthai-rs"));
    }

    #[test]
    fn absolute_environment_override_wins() {
        let configured = absolute_cache_path();
        let home = absolute_cache_path().join("ignored-home");

        let cache = resolve_cache_root(Some(configured.as_os_str()), Some(&home)).unwrap();

        assert_eq!(cache, configured);
    }

    #[test]
    fn rejects_empty_or_relative_environment_overrides() {
        assert!(resolve_cache_root(Some(OsStr::new("")), None).is_err());
        assert!(resolve_cache_root(Some(OsStr::new("relative-cache")), None).is_err());
    }

    #[test]
    fn dependency_versions_get_independent_target_folders() {
        let root = absolute_cache_path();

        assert_eq!(
            depthai_core_cache_dir(&root, "v3.8.0", "x86_64-pc-windows-msvc", "prebuilt"),
            root.join("depthai-core")
                .join("v3.8.0")
                .join("x86_64-pc-windows-msvc")
                .join("prebuilt")
        );
        assert_eq!(
            opencv_cache_dir(&root, "4.13.0", "x86_64-pc-windows-msvc"),
            root.join("opencv")
                .join("4.13.0")
                .join("x86_64-pc-windows-msvc")
        );
    }
}
