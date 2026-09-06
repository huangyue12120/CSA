use crate::detect::{
    FileFingerprint, OfficialCodex, detect_official, find_codex_launcher, fingerprint,
};
#[cfg(windows)]
use crate::detect::{parse_codex_version, windows_csa_system_bin};
use crate::error::{ManagerError, Result};
use crate::manager::{official_command, patched_command, validate_prepared_state};
use crate::process::{CommandSpec, ProcessRunner};
use crate::state::{
    Clock, ManagerPaths, PrepareLock, PreparedState, StateStore, remove_file_if_exists,
    remove_managed_tree, write_new_synced,
};
#[cfg(not(windows))]
use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(windows)]
const SHIM_NAME: &str = "codex.exe";
#[cfg(not(windows))]
const SHIM_NAME: &str = "codex";
#[cfg(windows)]
const STAGED_SHIM_NAME: &str = ".csa.staging.exe";
#[cfg(not(windows))]
const STAGED_SHIM_NAME: &str = ".csa.staging";
#[cfg(windows)]
const REMOVED_SHIM_NAME: &str = ".csa.removed.exe";
#[cfg(not(windows))]
const REMOVED_SHIM_NAME: &str = ".csa.removed";
#[cfg(windows)]
const MANAGER_ROOT_ENV: &str = "DSLZL_CSA_MANAGER_ROOT";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationBinding {
    pub compat_id: String,
    pub manifest_path: PathBuf,
    pub artifact_path: PathBuf,
    pub artifact_sha256: String,
    pub artifact_size: u64,
    pub official: OfficialCodex,
}

impl ActivationBinding {
    fn from_prepared(state: &PreparedState) -> Self {
        Self {
            compat_id: state.compat_id.clone(),
            manifest_path: state.manifest_path.clone(),
            artifact_path: state.artifact_path.clone(),
            artifact_sha256: state.artifact_sha256.clone(),
            artifact_size: state.artifact_size,
            official: state.official.clone(),
        }
    }

    fn matches(&self, state: &PreparedState) -> bool {
        self == &Self::from_prepared(state)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationState {
    pub schema: u32,
    pub binding: ActivationBinding,
    pub shim_sha256: String,
    pub shim_size: u64,
    pub activated_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActivationReport {
    pub status: &'static str,
    pub effective: bool,
    pub managed_bin: PathBuf,
    pub shim_path: PathBuf,
    pub command_resolution: CommandResolution,
    pub state: Option<ActivationState>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CommandResolution {
    pub managed_bin_on_path: bool,
    pub resolved_codex: Option<PathBuf>,
    pub resolves_to_managed_shim: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UserPathReport {
    pub status: &'static str,
    pub changed: bool,
    pub command_resolution: CommandResolution,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction: Option<String>,
}

#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsPathUpdate {
    changed: bool,
    effective_path: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PlugReport {
    pub schema: u32,
    pub status: &'static str,
    pub changed: bool,
    pub managed_bin_on_path: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_path: Option<UserPathReport>,
    pub activation: ActivationReport,
}

#[derive(Clone, Debug, Serialize)]
pub struct UnplugReport {
    pub schema: u32,
    pub status: &'static str,
    pub changed: bool,
    pub managed_bin: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct PurgeReport {
    pub schema: u32,
    pub status: &'static str,
    pub changed: bool,
    pub manager_root: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShimSelection {
    pub mode: &'static str,
    pub target: PathBuf,
    pub official: OfficialCodex,
    pub compat_id: Option<String>,
    pub fallback_reason: Option<String>,
}

pub fn shim_path(paths: &ManagerPaths) -> PathBuf {
    paths.bin.join(SHIM_NAME)
}

pub fn is_current_process_shim() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.file_name().map(OsStr::to_os_string))
        .is_some_and(|name| name.eq_ignore_ascii_case(OsStr::new(SHIM_NAME)))
}

pub fn plug(
    manager_root: Option<PathBuf>,
    runner: &dyn ProcessRunner,
    clock: &dyn Clock,
    shim_source: &Path,
) -> Result<PlugReport> {
    let paths = ManagerPaths::resolve(manager_root)?;
    let _lock = PrepareLock::acquire(&paths)?;
    recover(&paths)?;
    let store = StateStore::new(&paths);
    store.recover()?;
    let prepared = store
        .load()?
        .ok_or_else(|| ManagerError::new("not_prepared", "prepare must succeed before plug"))?;
    let official = validate_prepared_state(&prepared, &paths, runner)?;
    let source = fingerprint(shim_source)?;
    reject_shim_source(&source, &paths, &prepared, &official)?;

    if let Ok(active) = read_active(&paths.active) {
        let final_shim = shim_path(&paths);
        if active.schema == 2
            && active.binding.matches(&prepared)
            && active.shim_sha256 == source.sha256
            && active.shim_size == source.size
            && fingerprint(&final_shim)
                .is_ok_and(|shim| shim.sha256 == source.sha256 && shim.size == source.size)
        {
            let activation = inspect(&paths, Some(&prepared));
            return Ok(PlugReport {
                schema: 1,
                status: "plugged",
                changed: false,
                managed_bin_on_path: activation.command_resolution.managed_bin_on_path,
                user_path: None,
                activation,
            });
        }
    }

    deactivate_locked(&paths)?;
    let staged = paths.bin.join(STAGED_SHIM_NAME);
    remove_owned_file(&staged)?;
    if let Err(error) = copy_synced(&source.path, &staged) {
        let _ = remove_owned_file(&staged);
        return Err(error);
    }
    let staged_fingerprint = fingerprint(&staged)?;
    if staged_fingerprint.sha256 != source.sha256 || staged_fingerprint.size != source.size {
        remove_owned_file(&staged)?;
        return Err(ManagerError::new(
            "shim_hash_mismatch",
            "staged activation shim differs from the manager executable",
        ));
    }
    #[cfg(unix)]
    verify_staged_shim(&staged, runner)?;

    let active = ActivationState {
        schema: 2,
        binding: ActivationBinding::from_prepared(&prepared),
        shim_sha256: staged_fingerprint.sha256,
        shim_size: staged_fingerprint.size,
        activated_at_unix_seconds: clock.unix_seconds()?,
    };
    publish_active(&paths, &active)?;
    let final_shim = shim_path(&paths);
    if let Err(error) = fs::rename(&staged, &final_shim) {
        let _ = remove_file_if_exists(&paths.active);
        let _ = remove_owned_file(&staged);
        return Err(ManagerError::io("publish activation shim", error));
    }
    if let Err(error) = sync_directory(&paths.bin) {
        deactivate_locked(&paths)?;
        return Err(error);
    }

    if let Err(error) = validate_prepared_state(&prepared, &paths, runner) {
        deactivate_locked(&paths)?;
        return Err(error);
    }
    let activation = inspect(&paths, Some(&prepared));
    if activation.status != "plugged" {
        deactivate_locked(&paths)?;
        return Err(ManagerError::new(
            "activation_verification_failed",
            activation
                .reason
                .unwrap_or_else(|| "activation post-verification failed".to_owned()),
        ));
    }
    Ok(PlugReport {
        schema: 1,
        status: "plugged",
        changed: true,
        managed_bin_on_path: activation.command_resolution.managed_bin_on_path,
        user_path: None,
        activation,
    })
}

pub fn unplug(manager_root: Option<PathBuf>) -> Result<UnplugReport> {
    let paths = ManagerPaths::resolve(manager_root)?;
    if !paths.root.exists() {
        return Ok(UnplugReport {
            schema: 1,
            status: "unplugged",
            changed: false,
            managed_bin: paths.bin,
        });
    }
    let _lock = PrepareLock::acquire(&paths)?;
    let recovered = recover(&paths)?;
    let changed = recovered || deactivate_locked(&paths)?;
    Ok(UnplugReport {
        schema: 1,
        status: "unplugged",
        changed,
        managed_bin: paths.bin,
    })
}

pub fn purge(manager_root: Option<PathBuf>) -> Result<PurgeReport> {
    let paths = ManagerPaths::resolve(manager_root)?;
    if !paths.root.exists() {
        return Ok(PurgeReport {
            schema: 1,
            status: "purged",
            changed: false,
            manager_root: paths.root,
        });
    }
    let changed_before = managed_data_exists(&paths)?;
    let _lock = PrepareLock::acquire(&paths)?;
    recover(&paths)?;
    deactivate_locked(&paths)?;
    for directory in [
        &paths.artifacts,
        &paths.shell,
        &paths.manifests,
        &paths.downloads,
        &paths.sources,
        &paths.builds,
    ] {
        remove_managed_tree(&paths.root, directory)?;
    }
    for state in [
        paths.state.clone(),
        paths.root.join("state.json.next"),
        paths.root.join("state.json.previous"),
    ] {
        remove_owned_file(&state)?;
    }
    Ok(PurgeReport {
        schema: 1,
        status: "purged",
        changed: changed_before,
        manager_root: paths.root,
    })
}

pub fn inspect(paths: &ManagerPaths, prepared: Option<&PreparedState>) -> ActivationReport {
    let final_shim = shim_path(paths);
    let path_value = std::env::var_os("PATH");
    let command_resolution = inspect_command_resolution(paths, path_value.as_deref());
    let active_exists = fs::symlink_metadata(&paths.active).is_ok();
    let shim_exists = fs::symlink_metadata(&final_shim).is_ok();
    if !active_exists && !shim_exists {
        return ActivationReport {
            status: "unplugged",
            effective: false,
            managed_bin: paths.bin.clone(),
            shim_path: final_shim,
            command_resolution,
            state: None,
            reason: None,
        };
    }

    let checked = (|| {
        let active = read_active(&paths.active)?;
        let prepared = prepared.ok_or_else(|| {
            ManagerError::new("activation_fallback", "prepared state is not valid")
        })?;
        if !active.binding.matches(prepared) {
            return Err(ManagerError::new(
                "activation_state_mismatch",
                "active state does not bind the current prepared state",
            ));
        }
        let shim = fingerprint(&final_shim)?;
        if shim.sha256 != active.shim_sha256 || shim.size != active.shim_size {
            return Err(ManagerError::new(
                "shim_hash_mismatch",
                "activation shim hash or size changed",
            ));
        }
        Ok(active)
    })();
    match checked {
        Ok(active) => ActivationReport {
            status: "plugged",
            effective: command_resolution.resolves_to_managed_shim,
            managed_bin: paths.bin.clone(),
            shim_path: final_shim,
            command_resolution,
            state: Some(active),
            reason: None,
        },
        Err(error) => ActivationReport {
            status: "fallback",
            effective: false,
            managed_bin: paths.bin.clone(),
            shim_path: final_shim,
            command_resolution,
            state: read_active(&paths.active).ok(),
            reason: Some(error.to_string()),
        },
    }
}

pub fn inspect_command_resolution(
    paths: &ManagerPaths,
    path_value: Option<&OsStr>,
) -> CommandResolution {
    let resolved_codex = find_codex_launcher(path_value, &[]).ok();
    let managed_shim = shim_path(paths).canonicalize().ok();
    #[cfg(windows)]
    let system_bin = windows_csa_system_bin().ok();
    #[cfg(windows)]
    let system_managed = resolved_codex.as_ref().is_some_and(|actual| {
        system_bin
            .as_ref()
            .and_then(|bin| bin.join(SHIM_NAME).canonicalize().ok())
            .is_some_and(|system_shim| {
                actual == &system_shim
                    && fingerprint(&system_shim)
                        .ok()
                        .zip(fingerprint(&shim_path(paths)).ok())
                        .is_some_and(|(system, user)| {
                            system.sha256 == user.sha256 && system.size == user.size
                        })
            })
    });
    #[cfg(not(windows))]
    let system_managed = false;
    #[cfg(windows)]
    let system_bin_on_path = system_bin
        .as_ref()
        .is_some_and(|bin| path_contains(bin, path_value));
    #[cfg(not(windows))]
    let system_bin_on_path = false;
    CommandResolution {
        managed_bin_on_path: path_contains(&paths.bin, path_value) || system_bin_on_path,
        resolves_to_managed_shim: resolved_codex.as_ref().is_some_and(|actual| {
            managed_shim
                .as_ref()
                .is_some_and(|expected| actual == expected)
        }) || system_managed,
        resolved_codex,
    }
}

#[cfg(not(windows))]
pub fn prioritize_posix_user_path(activation: &ActivationReport) -> Result<UserPathReport> {
    let home = posix_home()?;
    prioritize_posix_user_path_in_home(activation, &home)
}

#[cfg(not(windows))]
fn prioritize_posix_user_path_in_home(
    activation: &ActivationReport,
    home: &Path,
) -> Result<UserPathReport> {
    let manager_root = activation.managed_bin.parent().ok_or_else(|| {
        ManagerError::new("unsafe_manager_root", "managed bin has no manager root")
    })?;
    let fragment = manager_root.join("shell/csa.sh");
    let fish_fragment = manager_root.join("shell/csa.fish");
    let profiles = posix_profiles_for_home(home)?;
    let fragment_contents = posix_fragment(&activation.managed_bin);

    let mut changes = Vec::with_capacity(profiles.len());
    for (path, shell) in profiles {
        let before = read_owned_text(&path)?;
        let fragment_for_shell = if shell == "fish" {
            &fish_fragment
        } else {
            &fragment
        };
        let block = posix_profile_block(fragment_for_shell, shell);
        let after = replace_posix_block(before.as_deref().unwrap_or_default(), &block)?;
        changes.push((path, before, after));
    }
    write_owned_text(&fragment, fragment_contents.as_bytes())?;
    write_owned_text(
        &fish_fragment,
        format!(
            "set -gx PATH {} $PATH;\n",
            shell_quote(&activation.managed_bin)
        )
        .as_bytes(),
    )?;
    let mut changed = false;
    for (path, before, after) in changes {
        if before.as_deref() != Some(after.as_str()) {
            write_owned_text(&path, after.as_bytes())?;
            changed = true;
        }
    }

    let verification_path = prepend_path(&activation.managed_bin, std::env::var_os("PATH"))?;
    let paths = ManagerPaths::resolve(Some(manager_root.to_path_buf()))?;
    let command_resolution = inspect_command_resolution(&paths, Some(&verification_path));
    if !command_resolution.resolves_to_managed_shim {
        return Ok(UserPathReport {
            status: "manual_required",
            changed,
            command_resolution,
            instruction: Some(posix_activation_instruction(&activation.managed_bin)),
        });
    }
    Ok(UserPathReport {
        status: "persisted_for_new_shell",
        changed,
        command_resolution,
        instruction: Some(posix_activation_instruction(&activation.managed_bin)),
    })
}

#[cfg(not(windows))]
pub fn remove_posix_user_path(managed_bin: &Path) -> Result<bool> {
    let home = posix_home()?;
    remove_posix_user_path_in_home(managed_bin, &home)
}

#[cfg(not(windows))]
fn remove_posix_user_path_in_home(managed_bin: &Path, home: &Path) -> Result<bool> {
    managed_bin.parent().ok_or_else(|| {
        ManagerError::new("unsafe_manager_root", "managed bin has no manager root")
    })?;
    let mut changed = false;
    for (path, _) in posix_profiles_for_home(home)? {
        let Some(before) = read_owned_text(&path)? else {
            continue;
        };
        let after = remove_posix_block(&before, "")?;
        if after != before {
            write_owned_text(&path, after.as_bytes())?;
            changed = true;
        }
    }
    Ok(changed)
}

#[cfg(not(windows))]
pub fn shell_env(manager_root: Option<PathBuf>, shell: &str) -> Result<String> {
    let paths = ManagerPaths::resolve(manager_root)?;
    let shell = normalize_shell(shell)?;
    Ok(match shell {
        "fish" => format!("set -gx PATH {} $PATH;", shell_quote(&paths.bin)),
        _ => format!("export PATH={}:$PATH;", shell_quote(&paths.bin)),
    })
}

#[cfg(not(windows))]
pub fn shell_init(manager_root: Option<PathBuf>, shell: &str) -> Result<String> {
    let paths = ManagerPaths::resolve(manager_root)?;
    let shell = normalize_shell(shell)?;
    let fragment = if shell == "fish" {
        paths.shell.join("csa.fish")
    } else {
        paths.shell.join("csa.sh")
    };
    Ok(match shell {
        "fish" => format!(
            "if test -r {}; source {}; end",
            shell_quote(&fragment),
            shell_quote(&fragment)
        ),
        _ => format!(
            "[ -r {} ] && . {}",
            shell_quote(&fragment),
            shell_quote(&fragment)
        ),
    })
}

#[cfg(not(windows))]
fn normalize_shell(shell: &str) -> Result<&str> {
    match shell {
        "sh" | "bash" | "zsh" | "fish" => Ok(shell),
        _ => Err(ManagerError::new(
            "invalid_shell",
            "supported shells are sh, bash, zsh, and fish",
        )),
    }
}

#[cfg(not(windows))]
fn posix_home() -> Result<PathBuf> {
    let home = BaseDirs::new()
        .map(|dirs| dirs.home_dir().to_path_buf())
        .ok_or_else(|| {
            ManagerError::new(
                "home_directory_unavailable",
                "cannot resolve the POSIX home directory for shell activation",
            )
        })?;
    crate::state::require_utf8_path(&home, "home directory")?;
    Ok(home)
}

#[cfg(not(windows))]
fn posix_profiles_for_home(home: &Path) -> Result<Vec<(PathBuf, &'static str)>> {
    crate::state::require_utf8_path(home, "home directory")?;
    Ok(vec![
        (home.join(".profile"), "sh"),
        (home.join(".bashrc"), "bash"),
        (home.join(".zshrc"), "zsh"),
        (home.join(".config/fish/conf.d/csa.fish"), "fish"),
    ])
}

#[cfg(not(windows))]
fn posix_fragment(managed_bin: &Path) -> String {
    format!("export PATH={}:$PATH\n", shell_quote(managed_bin))
}

#[cfg(not(windows))]
fn posix_profile_block(fragment: &Path, shell: &str) -> String {
    let command = if shell == "fish" {
        format!(
            "if test -r {}; source {}; end",
            shell_quote(fragment),
            shell_quote(fragment)
        )
    } else {
        format!(
            "[ -r {} ] && . {}",
            shell_quote(fragment),
            shell_quote(fragment)
        )
    };
    format!("# >>> CSA managed PATH >>>\n{command}\n# <<< CSA managed PATH <<<")
}

#[cfg(not(windows))]
fn posix_activation_instruction(managed_bin: &Path) -> String {
    format!(
        "Open a new shell, or run export PATH={}:$PATH; then use command -v codex and codex --version.",
        shell_quote(managed_bin)
    )
}

#[cfg(not(windows))]
fn prepend_path(directory: &Path, current: Option<OsString>) -> Result<OsString> {
    let mut entries = vec![directory.to_path_buf()];
    if let Some(current) = current {
        entries.extend(std::env::split_paths(&current));
    }
    std::env::join_paths(entries)
        .map_err(|error| ManagerError::new("path_activation_failed", error.to_string()))
}

#[cfg(not(windows))]
fn shell_quote(path: &Path) -> String {
    let value = path.to_string_lossy();
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(not(windows))]
fn read_owned_text(path: &Path) -> Result<Option<String>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(ManagerError::new(
                "unsafe_profile_path",
                format!("shell profile is not a regular file: {}", path.display()),
            ))
        }
        Ok(_) => {
            let bytes = fs::read(path).map_err(|error| {
                ManagerError::io(&format!("read shell profile {}", path.display()), error)
            })?;
            String::from_utf8(bytes).map(Some).map_err(|_| {
                ManagerError::new(
                    "non_utf8_path",
                    format!("shell profile is not UTF-8: {}", path.display()),
                )
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ManagerError::io(
            &format!("inspect shell profile {}", path.display()),
            error,
        )),
    }
}

#[cfg(not(windows))]
fn write_owned_text(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            ManagerError::io(
                &format!("create shell profile directory {}", parent.display()),
                error,
            )
        })?;
    }
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(ManagerError::new(
            "unsafe_profile_path",
            format!("shell profile is not a regular file: {}", path.display()),
        ));
    }
    let existing_permissions = fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions());
    let staging = path.with_file_name(format!(
        ".{}.csa-staging-{}",
        path.file_name()
            .and_then(OsStr::to_str)
            .unwrap_or("profile"),
        std::process::id()
    ));
    remove_file_if_exists(&staging)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staging)
        .map_err(|error| ManagerError::io(&format!("create {}", staging.display()), error))?;
    if let Some(permissions) = existing_permissions {
        fs::set_permissions(&staging, permissions).map_err(|error| {
            let _ = fs::remove_file(&staging);
            ManagerError::io(
                &format!("preserve shell profile permissions {}", path.display()),
                error,
            )
        })?;
    }
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&staging);
        return Err(ManagerError::io(
            &format!("write {}", staging.display()),
            error,
        ));
    }
    drop(file);
    fs::rename(&staging, path).map_err(|error| {
        ManagerError::io(&format!("publish shell profile {}", path.display()), error)
    })
}

#[cfg(not(windows))]
fn replace_posix_block(existing: &str, block: &str) -> Result<String> {
    let stripped = remove_posix_block(existing, block)?;
    let mut result = stripped.trim_end_matches('\n').to_owned();
    if !result.is_empty() {
        result.push('\n');
    }
    result.push_str(block);
    result.push('\n');
    Ok(result)
}

#[cfg(not(windows))]
fn remove_posix_block(existing: &str, _: &str) -> Result<String> {
    const START: &str = "# >>> CSA managed PATH >>>";
    const END: &str = "# <<< CSA managed PATH <<<";
    let mut result = String::with_capacity(existing.len());
    let mut remainder = existing;
    while let Some(start) = remainder.find(START) {
        result.push_str(&remainder[..start]);
        let after_start = &remainder[start..];
        let end = after_start.find(END).ok_or_else(|| {
            ManagerError::new(
                "invalid_profile_block",
                "CSA shell profile marker is incomplete",
            )
        })?;
        let after_end = &after_start[end + END.len()..];
        remainder = after_end.strip_prefix('\n').unwrap_or(after_end);
    }
    result.push_str(remainder);
    Ok(result)
}

#[cfg(windows)]
pub fn prioritize_windows_user_path(
    activation: &ActivationReport,
    runner: &dyn ProcessRunner,
) -> Result<UserPathReport> {
    let root = activation.managed_bin.parent().ok_or_else(|| {
        ManagerError::new("unsafe_manager_root", "managed bin has no manager root")
    })?;
    let powershell = windows_system_executable("System32/WindowsPowerShell/v1.0/powershell.exe")?;
    let update = runner
        .run(
            &CommandSpec::captured(&powershell)
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    WINDOWS_USER_PATH_SCRIPT,
                ])
                .env("CSA_MANAGED_BIN", activation.managed_bin.as_os_str())
                .env("CSA_MANAGER_ROOT", root.as_os_str())
                .env("CSA_PATH_MODE", "prepend"),
        )?
        .require_success("put the CSA managed bin first in the Windows user PATH")?;
    let mut update = parse_windows_path_update(&update.stdout, "path_activation_failed")?;
    let paths = ManagerPaths::resolve(Some(root.to_path_buf()))?;
    let mut verification_path = OsString::from(&update.effective_path);
    let mut command_resolution =
        inspect_command_resolution(&paths, Some(verification_path.as_os_str()));
    if !command_resolution.resolves_to_managed_shim {
        let elevated = prioritize_windows_machine_path(activation, root, &powershell, runner)?;
        update.changed |= elevated.changed;
        verification_path = OsString::from(elevated.effective_path);
        command_resolution =
            inspect_command_resolution(&paths, Some(verification_path.as_os_str()));
    }
    if !command_resolution.resolves_to_managed_shim {
        let resolved = command_resolution.resolved_codex.as_ref().map_or_else(
            || "no Codex command".to_owned(),
            |path| path.display().to_string(),
        );
        return Err(ManagerError::new(
            "path_precedence_conflict",
            format!(
                "Windows still selects {resolved} before the CSA shim {} after elevated PATH activation",
                activation.shim_path.display()
            ),
        ));
    }

    let active = activation.state.as_ref().ok_or_else(|| {
        ManagerError::new(
            "path_activation_failed",
            "active state is unavailable for `codex --version` verification",
        )
    })?;
    let resolved = command_resolution.resolved_codex.as_ref().ok_or_else(|| {
        ManagerError::new(
            "path_activation_failed",
            "the verified Codex command path is unavailable",
        )
    })?;
    let version = runner
        .run(
            &CommandSpec::captured(resolved)
                .arg("--version")
                .env("PATH", &verification_path)
                .env(MANAGER_ROOT_ENV, root.as_os_str()),
        )?
        .require_success("verify patched Codex with `codex --version`")?;
    let version_bytes = if version.stdout.is_empty() {
        &version.stderr
    } else {
        &version.stdout
    };
    let version_text = std::str::from_utf8(version_bytes).map_err(|_| {
        ManagerError::new(
            "path_activation_failed",
            "`codex --version` returned non-UTF-8 output",
        )
    })?;
    let actual_version =
        parse_csa_codex_version(version_text, &active.binding.compat_id).map_err(|error| {
            ManagerError::new(
                "path_activation_failed",
                format!("`codex --version` verification failed: {error}"),
            )
        })?;
    let expected_version = active.binding.official.version.as_str();
    if actual_version != expected_version {
        return Err(ManagerError::new(
            "path_activation_failed",
            format!("`codex --version` returned {actual_version}, expected {expected_version}"),
        ));
    }
    Ok(UserPathReport {
        status: "verified",
        changed: update.changed,
        command_resolution,
        instruction: None,
    })
}

#[cfg(windows)]
fn prioritize_windows_machine_path(
    activation: &ActivationReport,
    root: &Path,
    powershell: &Path,
    runner: &dyn ProcessRunner,
) -> Result<WindowsPathUpdate> {
    let update = runner
        .run(
            &CommandSpec::captured(powershell)
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    WINDOWS_MACHINE_PATH_SCRIPT,
                ])
                .env("CSA_MACHINE_PATH_MODE", "install")
                .env("CSA_SHIM_SOURCE", activation.shim_path.as_os_str())
                .env("CSA_MANAGER_ROOT", root.as_os_str()),
        )
        .map_err(|error| {
            ManagerError::new(
                "path_elevation_failed",
                format!("could not request administrator permission: {error}"),
            )
        })?
        .require_success("install the elevated CSA Codex dispatcher")
        .map_err(|error| ManagerError::new("path_elevation_failed", error.to_string()))?;
    parse_windows_path_update(&update.stdout, "path_elevation_failed")
}

#[cfg(windows)]
fn parse_csa_codex_version(text: &str, compat_id: &str) -> Result<String> {
    let suffix = format!(" (CSA {compat_id})");
    let value = text.trim();
    let version = value.strip_suffix(&suffix).ok_or_else(|| {
        ManagerError::new(
            "invalid_csa_version",
            format!("expected a CSA version marker for {compat_id}, got {value:?}"),
        )
    })?;
    parse_codex_version(version)
}

#[cfg(windows)]
pub fn remove_windows_user_path(managed_bin: &Path, runner: &dyn ProcessRunner) -> Result<bool> {
    let root = managed_bin.parent().ok_or_else(|| {
        ManagerError::new("unsafe_manager_root", "managed bin has no manager root")
    })?;
    let powershell = windows_system_executable("System32/WindowsPowerShell/v1.0/powershell.exe")?;
    let user_update = runner
        .run(
            &CommandSpec::captured(&powershell)
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    WINDOWS_USER_PATH_SCRIPT,
                ])
                .env("CSA_MANAGED_BIN", managed_bin.as_os_str())
                .env("CSA_MANAGER_ROOT", root.as_os_str())
                .env("CSA_PATH_MODE", "remove"),
        )?
        .require_success("remove the CSA managed bin from the Windows user PATH")
        .map_err(|error| ManagerError::new("path_deactivation_failed", error.to_string()))?;
    let user_update = parse_windows_path_update(&user_update.stdout, "path_deactivation_failed")?;
    let machine_update = runner
        .run(
            &CommandSpec::captured(&powershell)
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    WINDOWS_MACHINE_PATH_SCRIPT,
                ])
                .env("CSA_MACHINE_PATH_MODE", "remove"),
        )
        .map_err(|error| {
            ManagerError::new(
                "path_deactivation_failed",
                format!("could not request administrator permission: {error}"),
            )
        })?
        .require_success("remove the elevated CSA Codex dispatcher")
        .map_err(|error| ManagerError::new("path_deactivation_failed", error.to_string()))?;
    let machine_update =
        parse_windows_path_update(&machine_update.stdout, "path_deactivation_failed")?;
    Ok(user_update.changed || machine_update.changed)
}

#[cfg(windows)]
fn parse_windows_path_update(bytes: &[u8], error_code: &'static str) -> Result<WindowsPathUpdate> {
    serde_json::from_slice(bytes).map_err(|error| {
        ManagerError::new(
            error_code,
            format!("Windows user PATH update returned invalid JSON: {error}"),
        )
    })
}

#[cfg(windows)]
fn windows_system_executable(relative: &str) -> Result<PathBuf> {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| ManagerError::new("windows_system_root_missing", "SystemRoot is invalid"))?;
    let executable = root.join(relative).canonicalize().map_err(|error| {
        ManagerError::io(
            &format!("resolve Windows system executable {relative}"),
            error,
        )
    })?;
    if !executable.is_file() {
        return Err(ManagerError::new(
            "windows_system_tool_missing",
            format!(
                "Windows system executable is missing: {}",
                executable.display()
            ),
        ));
    }
    Ok(executable)
}

#[cfg(windows)]
const WINDOWS_USER_PATH_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$managed = $env:CSA_MANAGED_BIN
$managerRoot = $env:CSA_MANAGER_ROOT
$mode = $env:CSA_PATH_MODE
$key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
if ($null -eq $key) { throw 'cannot open HKCU\Environment' }
try {
  $current = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  try { $kind = $key.GetValueKind('Path') }
  catch { $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString }
  $entries = @($current -split ';' | Where-Object { $_ -and $_ -ine $managed })
  if ($mode -eq 'prepend') { $updated = (@($managed) + $entries) -join ';' }
  elseif ($mode -eq 'remove') { $updated = $entries -join ';' }
  else { throw 'invalid CSA_PATH_MODE' }
  $pathChanged = $updated -cne $current
  if ($pathChanged) {
    $key.SetValue('Path', $updated, $kind)
  }
  $rootName = 'DSLZL_CSA_MANAGER_ROOT'
  $savedRoot = [string]$key.GetValue($rootName, '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  $rootChanged = $false
  if ($mode -eq 'prepend' -and $savedRoot -ine $managerRoot) {
    $key.SetValue($rootName, $managerRoot, [Microsoft.Win32.RegistryValueKind]::String)
    $rootChanged = $true
  }
  elseif ($mode -eq 'remove' -and $savedRoot -ieq $managerRoot) {
    $key.DeleteValue($rootName, $false)
    $rootChanged = $true
  }
  $changed = $pathChanged -or $rootChanged
  if ($changed) {
    try {
      $member = '[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, UIntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);'
      $native = Add-Type -MemberDefinition $member -Name NativeMethods -Namespace CSA -PassThru
      $result = [UIntPtr]::Zero
      [void]$native::SendMessageTimeout([IntPtr]0xffff, 0x1a, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
    } catch {}
  }
  $saved = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  $savedEntries = @($saved -split ';' | Where-Object { $_ })
  $managedMatches = @($savedEntries | Where-Object { $_ -ieq $managed })
  if ($mode -eq 'prepend' -and ($savedEntries.Count -eq 0 -or $savedEntries[0] -ine $managed)) {
    throw 'managed bin is not first in the saved user PATH'
  }
  if ($mode -eq 'remove' -and $managedMatches.Count -ne 0) {
    throw 'managed bin remains in the saved user PATH'
  }
  $machinePath = [Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine)
  $userPath = [Environment]::ExpandEnvironmentVariables($saved)
  $effectivePath = (@([string]$machinePath, [string]$userPath) | Where-Object { $_ }) -join ';'
  $result = [ordered]@{ changed = [bool]$changed; effective_path = $effectivePath }
  [Console]::Out.Write(($result | ConvertTo-Json -Compress))
}
finally { $key.Dispose() }
"#;

#[cfg(windows)]
const WINDOWS_MACHINE_PATH_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$mode = $env:CSA_MACHINE_PATH_MODE
if ($mode -notin @('install', 'remove')) { throw 'invalid CSA_MACHINE_PATH_MODE' }
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$machineBin = [IO.Path]::GetFullPath((Join-Path $programFiles 'DSLZL\CSA\bin'))
$destination = Join-Path $machineBin 'codex.exe'
$source = if ($mode -eq 'install') { [IO.Path]::GetFullPath($env:CSA_SHIM_SOURCE) } else { '' }
if ($mode -eq 'install' -and -not (Test-Path -LiteralPath $source -PathType Leaf)) {
  throw 'CSA shim source is missing'
}
$beforePath = [string][Environment]::GetEnvironmentVariable('Path', [EnvironmentVariableTarget]::Machine)
$beforeHash = if (Test-Path -LiteralPath $destination -PathType Leaf) {
  (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
} else { '' }
$registered = @($beforePath -split ';' | Where-Object { $_ -and $_ -ieq $machineBin }).Count -gt 0
$needsElevation = $mode -eq 'install' -or $registered -or (Test-Path -LiteralPath $destination)
if ($needsElevation) {
  $source64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($source))
  $childTemplate = @'
$ErrorActionPreference = 'Stop'
$mode = '__MODE__'
$source = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('__SOURCE__'))
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$machineBin = [IO.Path]::GetFullPath((Join-Path $programFiles 'DSLZL\CSA\bin'))
$destination = Join-Path $machineBin 'codex.exe'
$staged = Join-Path $machineBin '.csa.staging.exe'
$registryPath = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($registryPath, $true)
if ($null -eq $key) { throw 'cannot open the machine environment registry key' }
try {
  $current = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  try { $kind = $key.GetValueKind('Path') }
  catch { $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString }
  $entries = @($current -split ';' | Where-Object { $_ -and $_ -ine $machineBin })
  if ($mode -eq 'install') {
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'CSA shim source is missing' }
    [void](New-Item -ItemType Directory -Path $machineBin -Force)
    Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $source -Destination $staged
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $staged -Algorithm SHA256).Hash) {
      throw 'staged system dispatcher hash mismatch'
    }
    if (Test-Path -LiteralPath $destination -PathType Leaf) {
      if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $staged -Algorithm SHA256).Hash) {
        Remove-Item -LiteralPath $staged -Force
      } else {
        [IO.File]::Replace($staged, $destination, $null)
      }
    } else {
      Move-Item -LiteralPath $staged -Destination $destination
    }
    $updated = (@($machineBin) + $entries) -join ';'
  } else {
    $updated = $entries -join ';'
  }
  if ($updated -cne $current) { $key.SetValue('Path', $updated, $kind) }
}
finally { $key.Dispose() }
if ($mode -eq 'remove') {
  Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $machineBin -ErrorAction SilentlyContinue
}
try {
  $member = '[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, UIntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);'
  $native = Add-Type -MemberDefinition $member -Name NativeMethods -Namespace CSA -PassThru
  $result = [UIntPtr]::Zero
  [void]$native::SendMessageTimeout([IntPtr]0xffff, 0x1a, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
} catch {}
'@
  $child = $childTemplate.Replace('__MODE__', $mode).Replace('__SOURCE__', $source64)
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
  try {
    $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) -Verb RunAs -WindowStyle Hidden -Wait -PassThru
  }
  catch { throw "administrator permission was denied or unavailable: $($_.Exception.Message)" }
  if ($process.ExitCode -ne 0) { throw "elevated PATH helper failed with exit code $($process.ExitCode)" }
}
$afterPath = [string][Environment]::GetEnvironmentVariable('Path', [EnvironmentVariableTarget]::Machine)
$afterHash = if (Test-Path -LiteralPath $destination -PathType Leaf) {
  (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
} else { '' }
$machineEntries = @($afterPath -split ';' | Where-Object { $_ })
if ($mode -eq 'install' -and ($machineEntries.Count -eq 0 -or $machineEntries[0] -ine $machineBin)) {
  throw 'CSA system dispatcher is not first in the machine PATH'
}
if ($mode -eq 'install' -and -not (Test-Path -LiteralPath $destination -PathType Leaf)) {
  throw 'CSA system dispatcher was not installed'
}
if ($mode -eq 'remove' -and @($machineEntries | Where-Object { $_ -ieq $machineBin }).Count -ne 0) {
  throw 'CSA system dispatcher remains in the machine PATH'
}
if ($mode -eq 'remove' -and (Test-Path -LiteralPath $destination)) {
  throw 'CSA system dispatcher remains installed'
}
$userPath = [Environment]::ExpandEnvironmentVariables([string][Environment]::GetEnvironmentVariable('Path', [EnvironmentVariableTarget]::User))
$effectivePath = (@($afterPath, $userPath) | Where-Object { $_ }) -join ';'
$changed = $beforePath -cne $afterPath -or $beforeHash -cne $afterHash
$result = [ordered]@{ changed = [bool]$changed; effective_path = $effectivePath }
[Console]::Out.Write(($result | ConvertTo-Json -Compress))
"#;

pub fn forward_current_shim(args: Vec<OsString>, runner: &dyn ProcessRunner) -> Result<i32> {
    let current = std::env::current_exe()
        .map_err(|error| ManagerError::io("resolve current activation shim", error))?
        .canonicalize()
        .map_err(|error| ManagerError::io("canonicalize current activation shim", error))?;
    let bin = current
        .parent()
        .ok_or_else(|| ManagerError::new("unsafe_shim_path", "activation shim has no parent"))?;
    #[cfg(windows)]
    if windows_csa_system_bin()
        .ok()
        .and_then(|path| path.canonicalize().ok())
        .is_some_and(|system_bin| system_bin == bin)
    {
        let root = std::env::var_os(MANAGER_ROOT_ENV).map(PathBuf::from);
        let paths = ManagerPaths::resolve(root)?;
        let path_value = std::env::var_os("PATH");
        let filtered_path = path_value
            .as_deref()
            .map(|value| path_without(bin, value))
            .transpose()?;
        return forward_shim_impl(
            &paths,
            args,
            filtered_path.as_deref(),
            &shim_path(&paths),
            runner,
            true,
        );
    }
    if bin.file_name() != Some(OsStr::new("bin")) {
        return Err(ManagerError::new(
            "unsafe_shim_path",
            "activation shim must be inside the manager bin directory",
        ));
    }
    let root = bin
        .parent()
        .ok_or_else(|| ManagerError::new("unsafe_shim_path", "manager bin has no parent"))?;
    let paths = ManagerPaths::resolve(Some(root.to_path_buf()))?;
    let path_value = std::env::var_os("PATH");
    forward_shim_impl(&paths, args, path_value.as_deref(), &current, runner, true)
}

pub fn forward_shim(
    paths: &ManagerPaths,
    args: Vec<OsString>,
    path_value: Option<&OsStr>,
    current_shim: &Path,
    runner: &dyn ProcessRunner,
) -> Result<i32> {
    forward_shim_impl(paths, args, path_value, current_shim, runner, false)
}

fn forward_shim_impl(
    paths: &ManagerPaths,
    args: Vec<OsString>,
    path_value: Option<&OsStr>,
    current_shim: &Path,
    runner: &dyn ProcessRunner,
    replace_process: bool,
) -> Result<i32> {
    let selection = match PrepareLock::acquire(paths) {
        Ok(_lock) => select_shim_target(paths, path_value, current_shim, runner)?,
        Err(lock_error) => {
            let fallback_state = StateStore::new(paths).load().ok().flatten();
            let (target, official) = resolve_official_fallback(
                paths,
                path_value,
                current_shim,
                fallback_state.as_ref(),
                runner,
            )?;
            ShimSelection {
                mode: "official",
                target,
                official,
                compat_id: None,
                fallback_reason: Some(lock_error.to_string()),
            }
        }
    };
    if selection.mode == "patched"
        && matches!(args.as_slice(), [arg] if arg == "--version" || arg == "-V")
    {
        let compat_id = selection.compat_id.as_deref().ok_or_else(|| {
            ManagerError::new(
                "invalid_activation_state",
                "patched shim selection has no compatibility ID",
            )
        })?;
        println!("codex-cli {} (CSA {compat_id})", selection.official.version);
        return Ok(0);
    }
    let command = CommandSpec::captured(&selection.target)
        .args(args)
        .inherited();
    let command = if selection.mode == "patched" {
        patched_command(command, &selection.official)?
    } else {
        official_command(command, &selection.official)?
    };
    let result = if replace_process {
        return runner.exec(&command);
    } else {
        runner.run(&command)?
    };
    Ok(result.exit_code())
}

pub fn select_shim_target(
    paths: &ManagerPaths,
    path_value: Option<&OsStr>,
    current_shim: &Path,
    runner: &dyn ProcessRunner,
) -> Result<ShimSelection> {
    let store = StateStore::new(paths);
    let prepared = store.recover().and_then(|()| store.load());
    let fallback_state = prepared
        .as_ref()
        .ok()
        .and_then(|state| state.as_ref())
        .cloned();
    let patched = (|| {
        let prepared = prepared?.ok_or_else(|| {
            ManagerError::new("not_prepared", "no verified prepared state exists")
        })?;
        let official = validate_prepared_state(&prepared, paths, runner)?;
        let active = read_active(&paths.active)?;
        if !active.binding.matches(&prepared) {
            return Err(ManagerError::new(
                "activation_state_mismatch",
                "active state does not bind the current prepared state",
            ));
        }
        let current = fingerprint(current_shim)?;
        if current.sha256 != active.shim_sha256 || current.size != active.shim_size {
            return Err(ManagerError::new(
                "shim_hash_mismatch",
                "running shim does not match active state",
            ));
        }
        Ok((prepared.artifact_path, official, prepared.compat_id))
    })();

    match patched {
        Ok((target, official, compat_id)) => Ok(ShimSelection {
            mode: "patched",
            target,
            official,
            compat_id: Some(compat_id),
            fallback_reason: None,
        }),
        Err(error) => {
            let (target, official) = resolve_official_fallback(
                paths,
                path_value,
                current_shim,
                fallback_state.as_ref(),
                runner,
            )?;
            Ok(ShimSelection {
                mode: "official",
                target,
                official,
                compat_id: None,
                fallback_reason: Some(error.to_string()),
            })
        }
    }
}

pub fn recover(paths: &ManagerPaths) -> Result<bool> {
    let mut changed = false;
    for path in [
        paths.root.join("active.json.next"),
        paths.bin.join(STAGED_SHIM_NAME),
        paths.bin.join(REMOVED_SHIM_NAME),
    ] {
        if owned_path_exists(&path)? {
            remove_owned_file(&path)?;
            changed = true;
        }
    }
    let active = owned_path_exists(&paths.active)?;
    let shim = owned_path_exists(&shim_path(paths))?;
    if active && !shim {
        remove_owned_file(&paths.active)?;
        changed = true;
    } else if shim && !active {
        withdraw_shim(paths)?;
        changed = true;
    }
    Ok(changed)
}

fn publish_active(paths: &ManagerPaths, state: &ActivationState) -> Result<()> {
    let next = paths.root.join("active.json.next");
    remove_owned_file(&next)?;
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|error| ManagerError::new("invalid_activation_state", error.to_string()))?;
    write_new_synced(&next, &bytes)?;
    fs::rename(&next, &paths.active)
        .map_err(|error| ManagerError::io("publish active state", error))?;
    sync_directory(&paths.root)
}

fn read_active(path: &Path) -> Result<ActivationState> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ManagerError::io(&format!("inspect active state {}", path.display()), error)
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ManagerError::new(
            "invalid_activation_state",
            format!("active state is not a real file: {}", path.display()),
        ));
    }
    let bytes = fs::read(path).map_err(|error| {
        ManagerError::io(&format!("read active state {}", path.display()), error)
    })?;
    let state: ActivationState = serde_json::from_slice(&bytes).map_err(|error| {
        ManagerError::new(
            "invalid_activation_state",
            format!("active state JSON: {error}"),
        )
    })?;
    if !matches!(state.schema, 1 | 2) {
        return Err(ManagerError::new(
            "invalid_activation_state",
            format!("unsupported active state schema: {}", state.schema),
        ));
    }
    Ok(state)
}

fn reject_shim_source(
    source: &FileFingerprint,
    paths: &ManagerPaths,
    prepared: &PreparedState,
    official: &OfficialCodex,
) -> Result<()> {
    let conflicts = source.path.starts_with(&paths.root)
        || source.path == prepared.artifact_path
        || source.path == official.executable.path
        || official
            .native
            .as_ref()
            .is_some_and(|native| source.path == native.path)
        || official.runtime.as_ref().is_some_and(|runtime| {
            source.path.starts_with(&runtime.package_root)
                || source.path.starts_with(&runtime.managed_package_root)
        });
    if conflicts {
        return Err(ManagerError::new(
            "unsafe_shim_source",
            "shim source must be a distinct manager executable outside managed and Codex paths",
        ));
    }
    Ok(())
}

fn resolve_official_fallback(
    paths: &ManagerPaths,
    path_value: Option<&OsStr>,
    current_shim: &Path,
    prepared: Option<&PreparedState>,
    runner: &dyn ProcessRunner,
) -> Result<(PathBuf, OfficialCodex)> {
    if let Ok(launcher) = find_codex_launcher(path_value, std::slice::from_ref(&paths.root))
        && let Ok(official) = detect_official(
            runner,
            Some(&launcher),
            None,
            std::slice::from_ref(&paths.root),
        )
    {
        let target = official_target(&official);
        if safe_fallback(&target, paths, current_shim, prepared) {
            return Ok((target, official));
        }
    }
    if let Some(prepared) = prepared {
        let saved = &prepared.official;
        if let Ok(official) = detect_official(
            runner,
            Some(&saved.executable.path),
            saved.native.as_ref().map(|native| native.path.as_path()),
            std::slice::from_ref(&paths.root),
        ) {
            let target = official_target(&official);
            if safe_fallback(&target, paths, current_shim, Some(prepared)) {
                return Ok((target, official));
            }
        }
        if fingerprint(&saved.executable.path).is_ok_and(|current| current == saved.executable)
            && safe_fallback(&saved.executable.path, paths, current_shim, Some(prepared))
        {
            return Ok((saved.executable.path.clone(), saved.clone()));
        }
    }
    Err(ManagerError::new(
        "official_fallback_unavailable",
        "could not resolve a safe official Codex outside the managed activation tree",
    ))
}

fn official_target(official: &OfficialCodex) -> PathBuf {
    official
        .runtime
        .as_ref()
        .and(official.native.as_ref())
        .map_or_else(
            || official.executable.path.clone(),
            |native| native.path.clone(),
        )
}

fn safe_fallback(
    candidate: &Path,
    paths: &ManagerPaths,
    current_shim: &Path,
    prepared: Option<&PreparedState>,
) -> bool {
    !candidate.starts_with(&paths.root)
        && candidate != current_shim
        && prepared.is_none_or(|state| candidate != state.artifact_path)
}

fn deactivate_locked(paths: &ManagerPaths) -> Result<bool> {
    let changed = owned_path_exists(&shim_path(paths))? || owned_path_exists(&paths.active)?;
    withdraw_shim(paths)?;
    remove_owned_file(&paths.active)?;
    remove_owned_file(&paths.root.join("active.json.next"))?;
    sync_directory(&paths.root)?;
    Ok(changed)
}

fn withdraw_shim(paths: &ManagerPaths) -> Result<()> {
    let final_shim = shim_path(paths);
    if !owned_path_exists(&final_shim)? {
        return Ok(());
    }
    let removed = paths.bin.join(REMOVED_SHIM_NAME);
    remove_owned_file(&removed)?;
    let metadata = fs::symlink_metadata(&final_shim).map_err(|error| {
        ManagerError::io(&format!("inspect shim {}", final_shim.display()), error)
    })?;
    if metadata.is_dir() {
        return Err(ManagerError::new(
            "unsafe_shim_path",
            format!("managed shim path is a directory: {}", final_shim.display()),
        ));
    }
    fs::rename(&final_shim, &removed)
        .map_err(|error| ManagerError::io("withdraw activation shim", error))?;
    remove_owned_file(&removed)?;
    sync_directory(&paths.bin)
}

fn remove_owned_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Err(ManagerError::new(
            "unsafe_managed_file",
            format!("managed file path is a directory: {}", path.display()),
        )),
        Ok(_) => fs::remove_file(path)
            .map_err(|error| ManagerError::io(&format!("remove {}", path.display()), error)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ManagerError::io(
            &format!("inspect {}", path.display()),
            error,
        )),
    }
}

fn copy_synced(source: &Path, destination: &Path) -> Result<()> {
    let mut input = File::open(source)
        .map_err(|error| ManagerError::io(&format!("open {}", source.display()), error))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| ManagerError::io(&format!("create {}", destination.display()), error))?;
    io::copy(&mut input, &mut output)
        .map_err(|error| ManagerError::io("copy activation shim", error))?;
    let permissions = fs::metadata(source)
        .map_err(|error| ManagerError::io(&format!("stat {}", source.display()), error))?
        .permissions();
    fs::set_permissions(destination, permissions)
        .map_err(|error| ManagerError::io("set activation shim permissions", error))?;
    output
        .sync_all()
        .map_err(|error| ManagerError::io("sync staged activation shim", error))
}

#[cfg(unix)]
fn verify_staged_shim(path: &Path, runner: &dyn ProcessRunner) -> Result<()> {
    let result = runner
        .run(&CommandSpec::captured(path).arg("--version"))
        .map_err(|error| {
            if error.message.to_ascii_lowercase().contains("permission denied") {
                ManagerError::new(
                    "noexec_filesystem",
                    format!(
                        "the executable filesystem rejected {}: choose an executable-capable --manager-root",
                        path.display()
                    ),
                )
            } else {
                error
            }
        })?;
    if result.code != Some(0) {
        return Err(ManagerError::new(
            "shim_not_runnable",
            format!(
                "staged CSA shim did not complete --version: {}",
                result.signal.map_or_else(
                    || format!("{:?}", result.code),
                    |signal| format!("signal {signal}"),
                )
            ),
        ));
    }
    Ok(())
}

fn owned_path_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(ManagerError::io(
            &format!("inspect {}", path.display()),
            error,
        )),
    }
}

fn managed_data_exists(paths: &ManagerPaths) -> Result<bool> {
    let shim = shim_path(paths);
    if [
        paths.state.as_path(),
        paths.active.as_path(),
        shim.as_path(),
    ]
    .iter()
    .any(|path| fs::symlink_metadata(path).is_ok())
    {
        return Ok(true);
    }
    for directory in [
        &paths.artifacts,
        &paths.shell,
        &paths.manifests,
        &paths.downloads,
        &paths.sources,
        &paths.builds,
    ] {
        match fs::read_dir(directory) {
            Ok(entries) => {
                if entries.into_iter().next().is_some() {
                    return Ok(true);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ManagerError::io(
                    &format!("inspect managed directory {}", directory.display()),
                    error,
                ));
            }
        }
    }
    Ok(false)
}

fn path_contains(directory: &Path, path_value: Option<&OsStr>) -> bool {
    let canonical = directory.canonicalize().ok();
    path_value.is_some_and(|value| {
        std::env::split_paths(value).any(|entry| {
            entry == directory
                || canonical.as_ref().is_some_and(|expected| {
                    entry.canonicalize().is_ok_and(|actual| &actual == expected)
                })
        })
    })
}

#[cfg(windows)]
fn path_without(directory: &Path, path_value: &OsStr) -> Result<OsString> {
    let canonical = directory.canonicalize().ok();
    std::env::join_paths(std::env::split_paths(path_value).filter(|entry| {
        !entry
            .as_os_str()
            .eq_ignore_ascii_case(directory.as_os_str())
            && !canonical.as_ref().is_some_and(|expected| {
                entry.canonicalize().is_ok_and(|actual| &actual == expected)
            })
    }))
    .map_err(|error| ManagerError::new("invalid_path", format!("rebuild PATH: {error}")))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| ManagerError::io(&format!("sync directory {}", path.display()), error))
}

#[cfg(not(unix))]
fn sync_directory(_: &Path) -> Result<()> {
    Ok(())
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::{
        ActivationReport, CommandResolution, prioritize_posix_user_path_in_home,
        remove_posix_block, remove_posix_user_path_in_home, replace_posix_block, shell_quote,
        verify_staged_shim,
    };
    use crate::error::{ManagerError, Result};
    use crate::process::{CommandResult, CommandSpec, ProcessRunner};
    use std::fs;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn posix_profile_block_is_idempotent_and_reversible() {
        let existing = "export EDITOR=vi\n";
        let block = "# >>> CSA managed PATH >>>\n[ -r '/tmp/csa/shell/csa.sh' ] && . '/tmp/csa/shell/csa.sh'\n# <<< CSA managed PATH <<<";
        let once = replace_posix_block(existing, block).unwrap();
        let twice = replace_posix_block(&once, block).unwrap();
        assert_eq!(once, twice);
        assert_eq!(remove_posix_block(&twice, "").unwrap(), existing);
    }

    #[test]
    fn incomplete_posix_profile_block_fails_closed() {
        let error = remove_posix_block("# >>> CSA managed PATH >>>\n", "").unwrap_err();
        assert_eq!(error.code, "invalid_profile_block");
    }

    #[test]
    fn posix_shell_quote_escapes_single_quotes() {
        assert_eq!(
            shell_quote(Path::new("/tmp/it's-csa/bin")),
            "'/tmp/it'\\''s-csa/bin'"
        );
    }

    #[test]
    fn posix_profile_files_are_idempotent_reversible_and_preserve_mode() {
        use std::os::unix::fs::PermissionsExt;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("csa-posix-profile-{}-{unique}", std::process::id()));
        let home = root.join("home");
        let manager_root = root.join("manager");
        let managed_bin = manager_root.join("bin");
        let shim = managed_bin.join("codex");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&managed_bin).unwrap();
        fs::write(home.join(".profile"), b"export EDITOR=vi\n").unwrap();
        let mut profile_permissions = fs::metadata(home.join(".profile")).unwrap().permissions();
        profile_permissions.set_mode(0o600);
        fs::set_permissions(home.join(".profile"), profile_permissions).unwrap();
        fs::write(&shim, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut shim_permissions = fs::metadata(&shim).unwrap().permissions();
        shim_permissions.set_mode(0o755);
        fs::set_permissions(&shim, shim_permissions).unwrap();

        let activation = ActivationReport {
            status: "plugged",
            effective: false,
            managed_bin: managed_bin.clone(),
            shim_path: shim,
            command_resolution: CommandResolution {
                managed_bin_on_path: false,
                resolved_codex: None,
                resolves_to_managed_shim: false,
            },
            state: None,
            reason: None,
        };
        let first = prioritize_posix_user_path_in_home(&activation, &home).unwrap();
        assert_eq!(first.status, "persisted_for_new_shell");
        assert!(first.changed);
        let profile = home.join(".profile");
        let first_contents = fs::read_to_string(&profile).unwrap();
        assert!(first_contents.contains("export EDITOR=vi"));
        assert!(first_contents.contains("CSA managed PATH"));
        assert_eq!(
            fs::metadata(&profile).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let second = prioritize_posix_user_path_in_home(&activation, &home).unwrap();
        assert_eq!(second.status, "persisted_for_new_shell");
        assert!(!second.changed);
        assert_eq!(fs::read_to_string(&profile).unwrap(), first_contents);

        assert!(remove_posix_user_path_in_home(&managed_bin, &home).unwrap());
        assert_eq!(fs::read_to_string(profile).unwrap(), "export EDITOR=vi\n");
        assert!(!remove_posix_user_path_in_home(&managed_bin, &home).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    struct PermissionDeniedRunner;

    impl ProcessRunner for PermissionDeniedRunner {
        fn run(&self, _: &CommandSpec) -> Result<CommandResult> {
            Err(ManagerError::new("io_error", "Permission denied"))
        }
    }

    #[test]
    fn staged_shim_reports_noexec_as_a_dedicated_error() {
        let error =
            verify_staged_shim(Path::new("/tmp/csa-staged"), &PermissionDeniedRunner).unwrap_err();
        assert_eq!(error.code, "noexec_filesystem");
    }
}
