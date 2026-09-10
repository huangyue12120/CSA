use crate::BUILD_TARGET;
#[cfg(unix)]
use crate::error::ManagerError;
use crate::error::Result;
#[cfg(unix)]
use std::fs;
use std::path::Path;

/// Resolve the target used by published patched Codex artifacts.
///
/// The Manager is intentionally built for the host's normal ABI on source
/// builds, while the Linux Codex platform packages publish the portable musl
/// target.  Keeping this mapping here prevents doctor, local prepare, and
/// online install from making different decisions.
pub fn runtime_artifact_target(manager_target: &str) -> &str {
    match manager_target {
        "x86_64-unknown-linux-gnu" => "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-gnu" => "aarch64-unknown-linux-musl",
        target => target,
    }
}

pub fn selected_runtime_artifact_target() -> &'static str {
    runtime_artifact_target(BUILD_TARGET)
}

pub fn is_linux_target(target: &str) -> bool {
    target.ends_with("-unknown-linux-gnu") || target.ends_with("-unknown-linux-musl")
}

pub fn ensure_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = fs::symlink_metadata(path).map_err(|error| {
            ManagerError::io(&format!("inspect executable {}", path.display()), error)
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ManagerError::new(
                "artifact_permission_failed",
                format!("executable is not a regular file: {}", path.display()),
            ));
        }
        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() | 0o111);
        fs::set_permissions(path, permissions).map_err(|error| {
            ManagerError::new(
                "artifact_permission_failed",
                format!("set execute permission on {}: {error}", path.display()),
            )
        })?;
        fs::File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|error| ManagerError::io("sync executable permissions", error))?;
        if let Some(parent) = path.parent() {
            fs::File::open(parent)
                .and_then(|file| file.sync_all())
                .map_err(|error| ManagerError::io("sync executable directory", error))?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::ensure_executable;
    use super::runtime_artifact_target;
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn linux_gnu_targets_resolve_to_musl_artifacts() {
        assert_eq!(
            runtime_artifact_target("x86_64-unknown-linux-gnu"),
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(
            runtime_artifact_target("aarch64-unknown-linux-gnu"),
            "aarch64-unknown-linux-musl"
        );
        assert_eq!(
            runtime_artifact_target("x86_64-pc-windows-msvc"),
            "x86_64-pc-windows-msvc"
        );
    }

    #[cfg(unix)]
    #[test]
    fn executable_artifacts_receive_execute_bits_before_publish() {
        use std::os::unix::fs::PermissionsExt;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "csa-executable-mode-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let file = root.join("artifact");
        fs::write(&file, b"artifact").unwrap();
        let mut permissions = fs::metadata(&file).unwrap().permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&file, permissions).unwrap();
        ensure_executable(&file).unwrap();
        assert_ne!(fs::metadata(&file).unwrap().permissions().mode() & 0o111, 0);
        fs::remove_dir_all(root).unwrap();
    }
}
