use crate::error::{ManagerError, Result};
use crate::hash::sha256_file;
use crate::platform::selected_runtime_artifact_target;
use crate::process::{CommandSpec, ProcessRunner};
use crate::state::require_utf8_path;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileFingerprint {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageManager {
    Npm,
    Bun,
    Pnpm,
    VitePlus,
    Unknown,
}

impl PackageManager {
    pub fn environment_key(self) -> Option<&'static str> {
        match self {
            Self::Npm => Some("CODEX_MANAGED_BY_NPM"),
            Self::Bun => Some("CODEX_MANAGED_BY_BUN"),
            Self::Pnpm => Some("CODEX_MANAGED_BY_PNPM"),
            Self::VitePlus => Some("CODEX_MANAGED_BY_VITE_PLUS"),
            Self::Unknown => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OfficialRuntime {
    pub package_root: PathBuf,
    pub managed_package_root: PathBuf,
    pub package_manager: PackageManager,
    pub files: Vec<FileFingerprint>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OfficialCodex {
    pub executable: FileFingerprint,
    pub version: String,
    pub native: Option<FileFingerprint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<OfficialRuntime>,
}

#[cfg(windows)]
pub(crate) fn windows_csa_system_bin() -> Result<PathBuf> {
    let program_files = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .filter(|path| {
            path.is_absolute()
                && !path.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::CurDir | std::path::Component::ParentDir
                    )
                })
        })
        .ok_or_else(|| {
            ManagerError::new(
                "windows_program_files_missing",
                "ProgramFiles is unavailable or invalid",
            )
        })?;
    Ok(program_files.join("DSLZL").join("CSA").join("bin"))
}

pub fn detect_official(
    runner: &dyn ProcessRunner,
    explicit: Option<&Path>,
    explicit_native: Option<&Path>,
    excluded_roots: &[PathBuf],
) -> Result<OfficialCodex> {
    let effective_excluded_roots = {
        let roots = excluded_roots.to_vec();
        #[cfg(windows)]
        {
            let mut roots = roots;
            if let Ok(system_bin) = windows_csa_system_bin() {
                roots.push(system_bin);
            }
            roots
        }
        #[cfg(not(windows))]
        {
            roots
        }
    };
    let excluded_roots = effective_excluded_roots.as_slice();
    let executable_path = match explicit {
        Some(path) => canonical_launcher(path)?,
        None => find_codex_launcher(std::env::var_os("PATH").as_deref(), excluded_roots)?,
    };
    reject_excluded(&executable_path, excluded_roots)?;
    let executable = fingerprint_file(&executable_path)?;

    let discovered = discover_official_runtime(&executable_path, explicit_native, excluded_roots)?;

    let (native, runtime, runtime_version) = match discovered {
        Some((native, runtime, version)) => (Some(native), Some(runtime), Some(version)),
        None => {
            if runtime_platform().is_some() {
                return Err(ManagerError::new(
                    "official_runtime_incomplete",
                    "the explicit official native executable is not inside a complete Codex platform package",
                ));
            }
            let native = explicit_native
                .map(|path| {
                    let path = canonical_executable(path)?;
                    reject_excluded(&path, excluded_roots)?;
                    fingerprint(&path)
                })
                .transpose()?;
            (native, None, None)
        }
    };

    let launcher_version = Some(executable_version(runner, &executable_path)?);
    let native_version = native
        .as_ref()
        .map(|native| executable_version(runner, &native.path))
        .transpose()?;
    let version = launcher_version
        .as_ref()
        .or(runtime_version.as_ref())
        .or(native_version.as_ref())
        .cloned()
        .ok_or_else(|| {
            ManagerError::new(
                "official_runtime_incomplete",
                "could not locate a complete official Codex platform package",
            )
        })?;
    for (label, candidate) in [
        ("launcher", launcher_version.as_deref()),
        ("native binary", native_version.as_deref()),
        ("package marker", runtime_version.as_deref()),
    ] {
        if candidate.is_some_and(|candidate| candidate != version) {
            return Err(ManagerError::new(
                "official_version_mismatch",
                format!("official {label} does not match launcher version {version}"),
            ));
        }
    }

    Ok(OfficialCodex {
        executable,
        version,
        native,
        runtime,
    })
}

pub(crate) fn find_codex_launcher(
    path_value: Option<&OsStr>,
    excluded_roots: &[PathBuf],
) -> Result<PathBuf> {
    if let Ok(path) = find_executable("codex", path_value, excluded_roots) {
        return Ok(path);
    }
    #[cfg(windows)]
    {
        let path_value = path_value.ok_or_else(|| {
            ManagerError::new("official_not_found", "PATH is unavailable; pass --official")
        })?;
        let excluded: Vec<_> = excluded_roots
            .iter()
            .filter_map(|path| path.canonicalize().ok())
            .collect();
        for directory in std::env::split_paths(path_value) {
            for name in ["codex.cmd", "codex.bat", "codex.ps1"] {
                let candidate = directory.join(name);
                let Ok(canonical) = canonical_launcher(&candidate) else {
                    continue;
                };
                if !excluded.iter().any(|root| canonical.starts_with(root)) {
                    return Ok(canonical);
                }
            }
        }
    }
    Err(ManagerError::new(
        "official_not_found",
        "could not resolve codex to a safe launcher; pass an absolute path",
    ))
}

fn canonical_launcher(path: &Path) -> Result<PathBuf> {
    require_utf8_path(path, "executable path")?;
    if !path.is_absolute() {
        return Err(ManagerError::new(
            "unsafe_executable_path",
            format!("executable path must be absolute: {}", path.display()),
        ));
    }
    let canonical = path.canonicalize().map_err(|error| {
        ManagerError::io(
            &format!("canonicalize executable {}", path.display()),
            error,
        )
    })?;
    let metadata = fs::metadata(&canonical).map_err(|error| {
        ManagerError::io(&format!("stat executable {}", canonical.display()), error)
    })?;
    #[cfg(windows)]
    let supported = platform_executable(&canonical, &metadata)
        || canonical
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|extension| {
                ["cmd", "bat", "ps1"]
                    .iter()
                    .any(|candidate| extension.eq_ignore_ascii_case(candidate))
            });
    #[cfg(not(windows))]
    let supported = platform_executable(&canonical, &metadata);
    if !metadata.is_file() || !supported {
        return Err(ManagerError::new(
            "unsafe_executable_path",
            format!("not a supported Codex launcher: {}", canonical.display()),
        ));
    }
    Ok(canonical)
}

#[derive(Clone, Copy)]
struct RuntimePlatform {
    package_name: &'static str,
    target: &'static str,
    entrypoint: &'static str,
    required_files: &'static [&'static str],
}

fn runtime_platform() -> Option<RuntimePlatform> {
    if cfg!(windows) {
        let package_name = if cfg!(target_arch = "x86_64") {
            "@openai/codex-win32-x64"
        } else if cfg!(target_arch = "aarch64") {
            "@openai/codex-win32-arm64"
        } else {
            return None;
        };
        return Some(RuntimePlatform {
            package_name,
            target: crate::BUILD_TARGET,
            entrypoint: "bin/codex.exe",
            required_files: &[
                "bin/codex-code-mode-host.exe",
                "codex-resources/codex-command-runner.exe",
                "codex-resources/codex-windows-sandbox-setup.exe",
                "codex-path/rg.exe",
            ],
        });
    }
    if cfg!(target_os = "linux") {
        let package_name = if cfg!(target_arch = "x86_64") {
            "@openai/codex-linux-x64"
        } else if cfg!(target_arch = "aarch64") {
            "@openai/codex-linux-arm64"
        } else {
            return None;
        };
        return Some(RuntimePlatform {
            package_name,
            target: selected_runtime_artifact_target(),
            entrypoint: "bin/codex",
            required_files: &[
                "bin/codex-code-mode-host",
                "codex-resources/bwrap",
                "codex-resources/zsh/bin/zsh",
                "codex-path/rg",
            ],
        });
    }
    None
}

fn discover_official_runtime(
    launcher: &Path,
    explicit_native: Option<&Path>,
    excluded_roots: &[PathBuf],
) -> Result<Option<(FileFingerprint, OfficialRuntime, String)>> {
    let Some(platform) = runtime_platform() else {
        return Ok(None);
    };
    let explicit_native = explicit_native.map(canonical_executable).transpose()?;
    let explicit_root = explicit_native.as_ref().and_then(|native| {
        native
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
    });
    let meta_roots = official_meta_roots(launcher, explicit_root.as_deref());
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();

    for meta_root in meta_roots {
        for package_root in platform_roots(&meta_root, explicit_root.as_deref(), platform) {
            let (native, runtime, version) =
                match validate_runtime(&package_root, &meta_root, platform, excluded_roots) {
                    Ok(runtime) => runtime,
                    Err(error) if error.code == "official_in_manager_root" => return Err(error),
                    Err(_) => continue,
                };
            if explicit_native
                .as_ref()
                .is_some_and(|expected| native.path != *expected)
            {
                continue;
            }
            let key = (
                runtime.package_root.clone(),
                runtime.managed_package_root.clone(),
            );
            if seen.insert(key) {
                candidates.push((native, runtime, version));
            }
        }
    }

    match candidates.len() {
        0 => Ok(None),
        1 => Ok(candidates.pop()),
        count => Err(ManagerError::new(
            "official_runtime_ambiguous",
            format!("found {count} complete official Codex platform packages for one launcher"),
        )),
    }
}

fn official_meta_roots(launcher: &Path, package_root: Option<&Path>) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let launcher_dir = launcher.parent().unwrap_or(launcher);
    if launcher_dir.file_name() == Some(OsStr::new("bin"))
        && launcher_dir
            .parent()
            .is_some_and(|root| root.join("package.json").is_file())
    {
        roots.push(launcher_dir.parent().unwrap().to_path_buf());
    }
    for ancestor in launcher_dir.ancestors() {
        if ancestor.file_name() == Some(OsStr::new("node_modules")) {
            roots.push(ancestor.join("@openai/codex"));
        }
        roots.push(ancestor.join("node_modules/@openai/codex"));
        roots.push(ancestor.join("install/global/node_modules/@openai/codex"));
    }
    let pnpm_global = launcher_dir.join("global");
    if let Ok(entries) = fs::read_dir(pnpm_global) {
        roots.extend(
            entries
                .flatten()
                .map(|entry| entry.path().join("node_modules/@openai/codex")),
        );
    }
    if let Some(package_root) = package_root {
        for ancestor in package_root.ancestors() {
            if ancestor.file_name() == Some(OsStr::new("node_modules")) {
                roots.push(ancestor.join("@openai/codex"));
            }
        }
    }
    dedupe_existing_directories(roots)
}

fn platform_roots(
    meta_root: &Path,
    explicit_root: Option<&Path>,
    platform: RuntimePlatform,
) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(root) = explicit_root {
        roots.push(root.to_path_buf());
    }
    let package_suffix = format!("{}/vendor/{}", platform.package_name, platform.target);
    roots.push(meta_root.join("node_modules").join(&package_suffix));
    roots.push(meta_root.join("vendor").join(platform.target));
    if let Some(scope_root) = meta_root.parent() {
        roots.push(scope_root.join(&package_suffix));
        if let Some(node_modules) = scope_root.parent() {
            roots.push(node_modules.join(&package_suffix));
        }
    }
    dedupe_existing_directories(roots)
}

fn dedupe_existing_directories(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    paths
        .into_iter()
        .filter_map(|path| path.canonicalize().ok())
        .filter(|path| path.is_dir() && seen.insert(path.clone()))
        .collect()
}

#[derive(Deserialize)]
struct PackageManifest {
    name: String,
    version: String,
}

fn platform_package_manifest_matches(
    manifest: &PackageManifest,
    platform: RuntimePlatform,
    version: &str,
) -> bool {
    if manifest.name == platform.package_name && manifest.version == version {
        return true;
    }

    // npm publishes the platform tarball as @openai/codex and uses the
    // platform suffix in its version. The optional dependency alias keeps
    // the platform package directory name separate from that manifest name.
    let Some(suffix) = platform.package_name.strip_prefix("@openai/codex-") else {
        return false;
    };
    manifest.name == "@openai/codex" && manifest.version == format!("{version}-{suffix}")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackageLayout {
    layout_version: u32,
    version: String,
    target: String,
    variant: String,
    entrypoint: String,
    resources_dir: String,
    path_dir: String,
}

fn validate_runtime(
    package_root: &Path,
    meta_root: &Path,
    platform: RuntimePlatform,
    excluded_roots: &[PathBuf],
) -> Result<(FileFingerprint, OfficialRuntime, String)> {
    let package_root = package_root.canonicalize().map_err(|error| {
        ManagerError::io(
            &format!(
                "canonicalize official package root {}",
                package_root.display()
            ),
            error,
        )
    })?;
    let managed_package_root = meta_root.canonicalize().map_err(|error| {
        ManagerError::io(
            &format!(
                "canonicalize official managed package {}",
                meta_root.display()
            ),
            error,
        )
    })?;
    reject_excluded(&package_root, excluded_roots)?;
    reject_excluded(&managed_package_root, excluded_roots)?;

    let package_json_path = managed_package_root.join("package.json");
    let package_json: PackageManifest = read_json_file(&package_json_path)?;
    if package_json.name != "@openai/codex" {
        return Err(ManagerError::new(
            "official_runtime_incomplete",
            "managed package is not @openai/codex",
        ));
    }

    let marker_path = package_root.join("codex-package.json");
    let marker: PackageLayout = read_json_file(&marker_path)?;
    let platform_package_root = package_root
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| {
            ManagerError::new(
                "official_runtime_incomplete",
                "official platform package has no package root",
            )
        })?;
    let platform_package_json_path = platform_package_root.join("package.json");
    let platform_package_json = (platform_package_root != managed_package_root)
        .then(|| read_json_file::<PackageManifest>(&platform_package_json_path))
        .transpose()?;
    if marker.layout_version != 1
        || marker.target != platform.target
        || marker.variant != "codex"
        || marker.entrypoint != platform.entrypoint
        || marker.resources_dir != "codex-resources"
        || marker.path_dir != "codex-path"
        || marker.version != package_json.version
        || platform_package_json.as_ref().is_some_and(|manifest| {
            !platform_package_manifest_matches(manifest, platform, &marker.version)
        })
    {
        return Err(ManagerError::new(
            "official_runtime_incomplete",
            "official Codex package metadata does not match the selected runtime",
        ));
    }

    let package_manager = package_manager(&managed_package_root);
    if package_manager == PackageManager::Unknown {
        return Err(ManagerError::new(
            "official_runtime_incomplete",
            "could not prove which package manager owns the official Codex package",
        ));
    }

    let native = fingerprint(&package_root.join(&marker.entrypoint))?;
    let mut files = vec![
        fingerprint_file(&marker_path)?,
        fingerprint_file(&package_json_path)?,
    ];
    if platform_package_json.is_some() {
        files.push(fingerprint_file(&platform_package_json_path)?);
    }
    files.extend(
        platform
            .required_files
            .iter()
            .map(|relative| fingerprint(&package_root.join(relative)))
            .collect::<Result<Vec<_>>>()?,
    );
    for file in &files {
        reject_excluded(&file.path, excluded_roots)?;
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));

    Ok((
        native,
        OfficialRuntime {
            package_root,
            managed_package_root: managed_package_root.clone(),
            package_manager,
            files,
        },
        marker.version,
    ))
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = fs::read(path)
        .map_err(|error| ManagerError::io(&format!("read {}", path.display()), error))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        ManagerError::new(
            "official_runtime_incomplete",
            format!("invalid {}: {error}", path.display()),
        )
    })
}

fn package_manager(path: &Path) -> PackageManager {
    let components: Vec<_> = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect();
    if components
        .iter()
        .any(|component| component.eq_ignore_ascii_case(".bun"))
    {
        PackageManager::Bun
    } else if components.iter().any(|component| {
        component.eq_ignore_ascii_case("pnpm") || component.eq_ignore_ascii_case(".pnpm")
    }) {
        PackageManager::Pnpm
    } else if components.iter().any(|component| {
        component.eq_ignore_ascii_case("vite+")
            || component.eq_ignore_ascii_case("vite-plus")
            || component.eq_ignore_ascii_case(".vite-plus")
    }) {
        PackageManager::VitePlus
    } else if components
        .iter()
        .any(|component| component.eq_ignore_ascii_case("node_modules"))
    {
        PackageManager::Npm
    } else {
        PackageManager::Unknown
    }
}

fn reject_excluded(path: &Path, excluded_roots: &[PathBuf]) -> Result<()> {
    if excluded_roots
        .iter()
        .filter_map(|root| root.canonicalize().ok())
        .any(|root| path.starts_with(&root) || root.starts_with(path))
    {
        return Err(ManagerError::new(
            "official_in_manager_root",
            format!(
                "official path overlaps the managed tree: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

pub fn fingerprint(path: &Path) -> Result<FileFingerprint> {
    let path = canonical_executable(path)?;
    fingerprint_canonical_file(path)
}

pub fn fingerprint_file(path: &Path) -> Result<FileFingerprint> {
    require_utf8_path(path, "file path")?;
    if !path.is_absolute() {
        return Err(ManagerError::new(
            "unsafe_file_path",
            format!("file path must be absolute: {}", path.display()),
        ));
    }
    let path = path.canonicalize().map_err(|error| {
        ManagerError::io(&format!("canonicalize file {}", path.display()), error)
    })?;
    let metadata = fs::metadata(&path)
        .map_err(|error| ManagerError::io(&format!("stat file {}", path.display()), error))?;
    if !metadata.is_file() {
        return Err(ManagerError::new(
            "unsafe_file_path",
            format!("not a regular file: {}", path.display()),
        ));
    }
    fingerprint_canonical_file(path)
}

fn fingerprint_canonical_file(path: PathBuf) -> Result<FileFingerprint> {
    require_utf8_path(&path, "file path")?;
    let (sha256, size) = sha256_file(&path)?;
    Ok(FileFingerprint { path, sha256, size })
}

pub fn find_executable(
    name: &str,
    path_value: Option<&OsStr>,
    excluded_roots: &[PathBuf],
) -> Result<PathBuf> {
    let path_value = path_value.ok_or_else(|| {
        ManagerError::new("official_not_found", "PATH is unavailable; pass --official")
    })?;
    let excluded: Vec<_> = excluded_roots
        .iter()
        .filter_map(|path| path.canonicalize().ok())
        .collect();
    for directory in std::env::split_paths(path_value) {
        for candidate_name in candidate_names(name) {
            let candidate = directory.join(candidate_name);
            let Ok(canonical) = canonical_executable(&candidate) else {
                continue;
            };
            if excluded.iter().any(|root| canonical.starts_with(root)) {
                continue;
            }
            return Ok(canonical);
        }
    }
    Err(ManagerError::new(
        "official_not_found",
        format!("could not resolve {name} to a safe executable; pass an absolute path"),
    ))
}

fn executable_version(runner: &dyn ProcessRunner, path: &Path) -> Result<String> {
    let result = runner
        .run(&CommandSpec::captured(path).arg("--version"))?
        .require_success("official Codex --version")?;
    let stdout = std::str::from_utf8(&result.stdout).map_err(|_| {
        ManagerError::new("invalid_official_version", "version output is not UTF-8")
    })?;
    let stderr = std::str::from_utf8(&result.stderr).map_err(|_| {
        ManagerError::new("invalid_official_version", "version output is not UTF-8")
    })?;
    parse_codex_version(&format!("{stdout}\n{stderr}"))
}

pub fn parse_codex_version(text: &str) -> Result<String> {
    let mut matches = text.lines().filter_map(|line| {
        let value = line.trim();
        let version = value.strip_prefix("codex-cli ")?;
        if valid_version_text(version) {
            Some(version.to_owned())
        } else {
            None
        }
    });
    let Some(version) = matches.next() else {
        return Err(ManagerError::new(
            "invalid_official_version",
            format!("expected a complete 'codex-cli X.Y.Z' line, got {text:?}"),
        ));
    };
    if matches.next().is_some() {
        return Err(ManagerError::new(
            "invalid_official_version",
            "official version output contains multiple version lines",
        ));
    }
    Ok(version)
}

fn valid_version_text(version: &str) -> bool {
    let parts: Vec<_> = version.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn canonical_executable(path: &Path) -> Result<PathBuf> {
    require_utf8_path(path, "executable path")?;
    if !path.is_absolute() {
        return Err(ManagerError::new(
            "unsafe_executable_path",
            format!("executable path must be absolute: {}", path.display()),
        ));
    }
    let canonical = path.canonicalize().map_err(|error| {
        ManagerError::io(
            &format!("canonicalize executable {}", path.display()),
            error,
        )
    })?;
    let metadata = fs::metadata(&canonical).map_err(|error| {
        ManagerError::io(&format!("stat executable {}", canonical.display()), error)
    })?;
    if !metadata.is_file() || !platform_executable(&canonical, &metadata) {
        return Err(ManagerError::new(
            "unsafe_executable_path",
            format!("not an executable file: {}", canonical.display()),
        ));
    }
    Ok(canonical)
}

#[cfg(windows)]
fn candidate_names(name: &str) -> Vec<OsString> {
    if Path::new(name).extension().is_some() {
        vec![OsString::from(name)]
    } else {
        vec![
            OsString::from(format!("{name}.exe")),
            OsString::from(format!("{name}.com")),
        ]
    }
}

#[cfg(not(windows))]
fn candidate_names(name: &str) -> Vec<OsString> {
    vec![OsString::from(name)]
}

#[cfg(windows)]
fn platform_executable(path: &Path, _: &fs::Metadata) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("exe") || extension.eq_ignore_ascii_case("com")
        })
}

#[cfg(unix)]
fn platform_executable(_: &Path, metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::{PackageManager, detect_official, find_codex_launcher};
    #[cfg(target_os = "linux")]
    use super::{PackageManager, detect_official, package_manager};
    use super::{find_executable, parse_codex_version};
    #[cfg(windows)]
    use crate::BUILD_TARGET;
    #[cfg(windows)]
    use crate::error::Result;
    #[cfg(target_os = "linux")]
    use crate::error::Result;
    #[cfg(windows)]
    use crate::process::{CommandResult, CommandSpec, ProcessRunner};
    #[cfg(target_os = "linux")]
    use crate::process::{CommandResult, CommandSpec, ProcessRunner};
    use std::fs;
    #[cfg(any(windows, target_os = "linux"))]
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn version_parser_is_exact() {
        assert_eq!(
            parse_codex_version("codex-cli 0.147.0\n").unwrap(),
            "0.147.0"
        );
        assert!(parse_codex_version("codex 0.147.0").is_err());
        assert!(parse_codex_version("codex-cli 0.147").is_err());
        assert!(parse_codex_version("codex-cli 0.147.0-beta").is_err());
        assert_eq!(
            parse_codex_version("warning: bundled runtime\ncodex-cli 0.147.0\n").unwrap(),
            "0.147.0"
        );
        assert!(parse_codex_version("codex-cli 0.147.0\ncodex-cli 0.147.0").is_err());
        assert!(parse_codex_version("codex-cli 0.147.0 (CSA test)").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unknown_package_manager_layout_does_not_default_to_npm() {
        assert_eq!(
            package_manager(Path::new("/tmp/opaque/@openai/codex")),
            PackageManager::Unknown
        );
        assert_eq!(
            package_manager(Path::new("/tmp/node_modules/@openai/codex")),
            PackageManager::Npm
        );
    }

    #[test]
    fn path_resolution_is_absolute_and_honors_exclusions() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("csa-resolve-{}-{unique}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let executable = directory.join(if cfg!(windows) { "codex.exe" } else { "codex" });
        fs::write(&executable, b"fixture").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&executable, permissions).unwrap();
        }
        let path = std::env::join_paths([&directory]).unwrap();
        assert_eq!(
            find_executable("codex", Some(&path), &[]).unwrap(),
            executable.canonicalize().unwrap()
        );
        assert!(find_executable("codex", Some(&path), std::slice::from_ref(&directory)).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(windows)]
    fn write_windows_runtime(managed: &Path, package: &Path, target: &str) {
        fs::create_dir_all(managed).unwrap();
        fs::create_dir_all(package.join("bin")).unwrap();
        fs::create_dir_all(package.join("codex-resources")).unwrap();
        fs::create_dir_all(package.join("codex-path")).unwrap();
        fs::write(
            package
                .parent()
                .and_then(Path::parent)
                .unwrap()
                .join("package.json"),
            format!(
                r#"{{"name":"{}","version":"0.149.0"}}"#,
                super::runtime_platform().unwrap().package_name
            ),
        )
        .unwrap();
        fs::write(
            managed.join("package.json"),
            br#"{"name":"@openai/codex","version":"0.149.0"}"#,
        )
        .unwrap();
        fs::write(
            package.join("codex-package.json"),
            format!(
                r#"{{"layoutVersion":1,"version":"0.149.0","target":"{target}","variant":"codex","entrypoint":"bin/codex.exe","resourcesDir":"codex-resources","pathDir":"codex-path"}}"#
            ),
        )
        .unwrap();
        for relative in [
            "bin/codex.exe",
            "bin/codex-code-mode-host.exe",
            "codex-resources/codex-command-runner.exe",
            "codex-resources/codex-windows-sandbox-setup.exe",
            "codex-path/rg.exe",
        ] {
            fs::write(package.join(relative), relative.as_bytes()).unwrap();
        }
    }

    #[cfg(windows)]
    #[test]
    fn discovers_complete_npm_bun_and_pnpm_platform_packages() {
        struct VersionRunner;
        impl ProcessRunner for VersionRunner {
            fn run(&self, _: &CommandSpec) -> Result<CommandResult> {
                Ok(CommandResult::success("codex-cli 0.149.0\n"))
            }
        }

        for (name, expected) in [
            ("npm", PackageManager::Npm),
            ("bun", PackageManager::Bun),
            ("pnpm", PackageManager::Pnpm),
        ] {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir()
                .join(format!(
                    "csa-pnpm-looking-parent-{}-{unique}",
                    std::process::id()
                ))
                .join(name);
            let (launcher_dir, node_modules, launcher_name) = match name {
                "npm" => (root.join("npm"), root.join("npm/node_modules"), "codex.cmd"),
                "bun" => (
                    root.join(".bun/bin"),
                    root.join(".bun/install/global/node_modules"),
                    "codex.exe",
                ),
                "pnpm" => (
                    root.join("pnpm"),
                    root.join("pnpm/global/5/node_modules"),
                    "codex.cmd",
                ),
                _ => unreachable!(),
            };
            let managed = node_modules.join("@openai/codex");
            let package = node_modules
                .join(format!(
                    "{}/vendor",
                    super::runtime_platform().unwrap().package_name
                ))
                .join(BUILD_TARGET);
            fs::create_dir_all(&launcher_dir).unwrap();
            fs::write(launcher_dir.join(launcher_name), b"launcher").unwrap();
            write_windows_runtime(&managed, &package, BUILD_TARGET);

            let path = std::env::join_paths([&launcher_dir]).unwrap();
            let launcher = find_codex_launcher(Some(&path), &[]).unwrap();
            let official = detect_official(&VersionRunner, Some(&launcher), None, &[]).unwrap();
            let runtime = official.runtime.unwrap();
            assert_eq!(runtime.package_manager, expected);
            assert_eq!(runtime.package_root, package.canonicalize().unwrap());
            assert_eq!(
                official.native.unwrap().path,
                package.join("bin/codex.exe").canonicalize().unwrap()
            );

            if name == "npm" {
                let second_modules = root.join("node_modules");
                let second_managed = second_modules.join("@openai/codex");
                let second_package = second_modules
                    .join(format!(
                        "{}/vendor",
                        super::runtime_platform().unwrap().package_name
                    ))
                    .join(BUILD_TARGET);
                write_windows_runtime(&second_managed, &second_package, BUILD_TARGET);
                let error =
                    detect_official(&VersionRunner, Some(&launcher), None, &[]).unwrap_err();
                assert_eq!(error.code, "official_runtime_ambiguous");
            }
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    fn write_linux_executable(path: &Path, contents: &[u8]) {
        use std::os::unix::fs::PermissionsExt;

        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn write_linux_runtime(
        root: &Path,
        manager: &str,
        version: &str,
        target: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let modules = match manager {
            "npm" => root.join("node_modules"),
            "bun" => root.join(".bun/install/global/node_modules"),
            "pnpm" => root.join(".pnpm/node_modules"),
            "vite+" => root.join(".vite-plus/node_modules"),
            _ => unreachable!(),
        };
        let managed = modules.join("@openai/codex");
        let platform_name = if cfg!(target_arch = "x86_64") {
            "codex-linux-x64"
        } else {
            "codex-linux-arm64"
        };
        let platform = modules.join("@openai").join(platform_name);
        let package = platform
            .join("vendor")
            .join(crate::platform::selected_runtime_artifact_target());
        fs::create_dir_all(managed.join("bin")).unwrap();
        fs::create_dir_all(package.join("bin")).unwrap();
        fs::create_dir_all(package.join("codex-resources/zsh/bin")).unwrap();
        fs::create_dir_all(package.join("codex-path")).unwrap();
        fs::write(
            managed.join("package.json"),
            format!(r#"{{"name":"@openai/codex","version":"{version}"}}"#),
        )
        .unwrap();
        fs::write(
            platform.join("package.json"),
            format!(r#"{{"name":"@openai/{platform_name}","version":"{version}"}}"#),
        )
        .unwrap();
        fs::write(
            package.join("codex-package.json"),
            format!(
                r#"{{"layoutVersion":1,"version":"{version}","target":"{target}","variant":"codex","entrypoint":"bin/codex","resourcesDir":"codex-resources","pathDir":"codex-path"}}"#
            ),
        )
        .unwrap();
        for relative in [
            "bin/codex",
            "bin/codex-code-mode-host",
            "codex-resources/bwrap",
            "codex-resources/zsh/bin/zsh",
            "codex-path/rg",
        ] {
            write_linux_executable(&package.join(relative), relative.as_bytes());
        }
        let launcher = managed.join("bin/codex");
        write_linux_executable(&launcher, b"launcher");
        (launcher, package.join("bin/codex"), package)
    }

    #[cfg(target_os = "linux")]
    struct VersionRunner;

    #[cfg(target_os = "linux")]
    impl ProcessRunner for VersionRunner {
        fn run(&self, _: &CommandSpec) -> Result<CommandResult> {
            Ok(CommandResult::success("codex-cli 1.2.3\n"))
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn discovers_linux_npm_bun_pnpm_and_vite_plus_layouts() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for (manager, expected) in [
            ("npm", PackageManager::Npm),
            ("bun", PackageManager::Bun),
            ("pnpm", PackageManager::Pnpm),
            ("vite+", PackageManager::VitePlus),
        ] {
            let root = std::env::temp_dir().join(format!(
                "csa-linux-runtime-{manager}-{}-{unique}",
                std::process::id()
            ));
            let (launcher, native, package) = write_linux_runtime(
                &root,
                manager,
                "1.2.3",
                crate::platform::selected_runtime_artifact_target(),
            );
            let official = detect_official(&VersionRunner, Some(&launcher), None, &[]).unwrap();
            let runtime = official.runtime.unwrap();
            assert_eq!(runtime.package_manager, expected);
            assert_eq!(runtime.package_root, package.canonicalize().unwrap());
            assert_eq!(
                official.native.unwrap().path,
                native.canonicalize().unwrap()
            );
            assert_eq!(runtime.files.len(), 7);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_runtime_rejects_missing_helpers_wrong_target_and_version_drift() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let target = crate::platform::selected_runtime_artifact_target();

        let missing_root =
            std::env::temp_dir().join(format!("csa-linux-missing-{}-{unique}", std::process::id()));
        let (missing_launcher, _, missing_package) =
            write_linux_runtime(&missing_root, "npm", "1.2.3", target);
        fs::remove_file(missing_package.join("codex-resources/bwrap")).unwrap();
        let error =
            detect_official(&VersionRunner, Some(&missing_launcher), None, &[]).unwrap_err();
        assert_eq!(error.code, "official_runtime_incomplete");
        fs::remove_dir_all(missing_root).unwrap();

        let wrong_root =
            std::env::temp_dir().join(format!("csa-linux-target-{}-{unique}", std::process::id()));
        let wrong_target = if target == "x86_64-unknown-linux-musl" {
            "aarch64-unknown-linux-musl"
        } else {
            "x86_64-unknown-linux-musl"
        };
        let (wrong_launcher, _, _) = write_linux_runtime(&wrong_root, "npm", "1.2.3", wrong_target);
        let error = detect_official(&VersionRunner, Some(&wrong_launcher), None, &[]).unwrap_err();
        assert_eq!(error.code, "official_runtime_incomplete");
        fs::remove_dir_all(wrong_root).unwrap();

        let drift_root =
            std::env::temp_dir().join(format!("csa-linux-version-{}-{unique}", std::process::id()));
        let (drift_launcher, _, _) = write_linux_runtime(&drift_root, "npm", "9.9.9", target);
        let error = detect_official(&VersionRunner, Some(&drift_launcher), None, &[]).unwrap_err();
        assert_eq!(error.code, "official_version_mismatch");
        fs::remove_dir_all(drift_root).unwrap();

        let explicit_root = std::env::temp_dir().join(format!(
            "csa-linux-explicit-native-{}-{unique}",
            std::process::id()
        ));
        let (explicit_launcher, _, _) = write_linux_runtime(
            &explicit_root,
            "npm",
            "1.2.3",
            crate::platform::selected_runtime_artifact_target(),
        );
        let unrelated_root = std::env::temp_dir().join(format!(
            "csa-linux-unrelated-native-{}-{unique}",
            std::process::id()
        ));
        let unrelated_native = unrelated_root.join("bin/codex");
        write_linux_executable(&unrelated_native, b"unrelated-native");
        let error = detect_official(
            &VersionRunner,
            Some(&explicit_launcher),
            Some(&unrelated_native),
            &[],
        )
        .unwrap_err();
        assert_eq!(error.code, "official_runtime_incomplete");
        fs::remove_dir_all(explicit_root).unwrap();
        fs::remove_dir_all(unrelated_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_runtime_discovery_rejects_ambiguous_complete_packages() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "csa-linux-ambiguous-{}-{unique}",
            std::process::id()
        ));
        let first_root = root.join("app");
        let (launcher, _, _) = write_linux_runtime(
            &first_root,
            "npm",
            "1.2.3",
            crate::platform::selected_runtime_artifact_target(),
        );
        let _ = write_linux_runtime(
            &root,
            "npm",
            "1.2.3",
            crate::platform::selected_runtime_artifact_target(),
        );
        let error = detect_official(&VersionRunner, Some(&launcher), None, &[]).unwrap_err();
        assert_eq!(error.code, "official_runtime_ambiguous");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_runtime_discovery_supports_legacy_vendor_layout() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("csa-linux-legacy-{}-{unique}", std::process::id()));
        let (launcher, _native, package) = write_linux_runtime(
            &root,
            "npm",
            "1.2.3",
            crate::platform::selected_runtime_artifact_target(),
        );
        let managed = launcher.parent().unwrap().parent().unwrap().to_path_buf();
        let platform = package.parent().unwrap().parent().unwrap().to_path_buf();
        let legacy = managed
            .join("vendor")
            .join(crate::platform::selected_runtime_artifact_target());
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        fs::rename(&package, &legacy).unwrap();
        fs::remove_dir_all(platform).unwrap();

        let official = detect_official(&VersionRunner, Some(&launcher), None, &[]).unwrap();
        assert_eq!(
            official.native.unwrap().path,
            legacy.join("bin/codex").canonicalize().unwrap()
        );
        assert_eq!(official.runtime.unwrap().files.len(), 6);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_runtime_discovery_supports_npm_platform_alias_metadata() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "csa-linux-npm-alias-{}-{unique}",
            std::process::id()
        ));
        let (launcher, native, package) = write_linux_runtime(
            &root,
            "npm",
            "1.2.3",
            crate::platform::selected_runtime_artifact_target(),
        );
        let platform_root = package
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .to_path_buf();
        let platform = super::runtime_platform().unwrap();
        let suffix = platform
            .package_name
            .strip_prefix("@openai/codex-")
            .unwrap();
        fs::write(
            platform_root.join("package.json"),
            format!(r#"{{"name":"@openai/codex","version":"1.2.3-{suffix}"}}"#),
        )
        .unwrap();

        let official = detect_official(&VersionRunner, Some(&launcher), None, &[]).unwrap();
        assert_eq!(
            official.native.unwrap().path,
            native.canonicalize().unwrap()
        );
        assert_eq!(
            official.runtime.unwrap().package_root,
            package.canonicalize().unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn platform_package_metadata_requires_matching_name_version_and_platform() {
        for suffix in ["linux-x64", "linux-arm64", "win32-x64", "win32-arm64"] {
            let package_name = match suffix {
                "linux-x64" => "@openai/codex-linux-x64",
                "linux-arm64" => "@openai/codex-linux-arm64",
                "win32-x64" => "@openai/codex-win32-x64",
                _ => "@openai/codex-win32-arm64",
            };
            let platform = super::RuntimePlatform {
                package_name,
                target: "unused",
                entrypoint: "unused",
                required_files: &[],
            };
            for (name, version, expected) in [
                (package_name, "1.2.3".to_owned(), true),
                ("@openai/codex", format!("1.2.3-{suffix}"), true),
                (package_name, "1.2.4".to_owned(), false),
                ("@openai/codex", format!("1.2.4-{suffix}"), false),
                ("@openai/codex", "1.2.3-other-platform".to_owned(), false),
                ("@openai/codex", "1.2.3".to_owned(), false),
                ("unrelated", format!("1.2.3-{suffix}"), false),
            ] {
                let manifest = super::PackageManifest {
                    name: name.to_owned(),
                    version,
                };
                assert_eq!(
                    super::platform_package_manifest_matches(&manifest, platform, "1.2.3"),
                    expected,
                    "{name} {} for {suffix}",
                    manifest.version,
                );
            }
        }
    }
}
