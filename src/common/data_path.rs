// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::domain::error::AppError;
use std::path::{Path, PathBuf};

const DATA_DIR_ENV: &str = "DATA_DIR";

fn absolute(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        return path;
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(path),
        Err(_) => path,
    }
}

fn normalize_data_relative(path: &Path) -> PathBuf {
    path.strip_prefix("data")
        .map(PathBuf::from)
        .unwrap_or_else(|_| path.to_path_buf())
}

fn env_data_dir() -> Option<String> {
    std::env::var(DATA_DIR_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn executable_data_dir_candidate() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let parent = exe.parent()?;
    Some(absolute(parent.join("..").join("data")))
}

/// Resolve the active data directory using precedence:
/// 1) explicit `DATA_DIR`
/// 2) executable-relative `../data` (if present)
/// 3) cwd-relative `./data`
pub fn resolve_data_dir(explicit_data_dir: Option<&str>) -> PathBuf {
    if let Some(dir) = explicit_data_dir
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .or_else(env_data_dir)
    {
        return absolute(PathBuf::from(dir));
    }
    if let Some(exe_data) = executable_data_dir_candidate()
        && exe_data.exists()
    {
        return exe_data;
    }
    absolute(PathBuf::from("data"))
}

/// Resolve a path that may be absolute or relative.
/// Relative paths honor DATA_DIR precedence and are returned as absolute paths.
pub fn resolve_data_path(raw_path: &str, explicit_data_dir: Option<&str>) -> PathBuf {
    let as_path = PathBuf::from(raw_path);
    if as_path.is_absolute() {
        return as_path;
    }
    let normalized_rel = normalize_data_relative(&as_path);
    if explicit_data_dir
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_some()
        || env_data_dir().is_some()
    {
        return resolve_data_dir(explicit_data_dir).join(normalized_rel);
    }
    if let Some(exe_data) = executable_data_dir_candidate() {
        let exe_candidate = exe_data.join(&normalized_rel);
        if exe_candidate.exists() {
            return exe_candidate;
        }
    }
    absolute(as_path)
}

pub fn resolve_default_data_file(file_name: &str, explicit_data_dir: Option<&str>) -> PathBuf {
    resolve_data_dir(explicit_data_dir).join(file_name)
}

pub fn resolve_required_data_path(
    raw_path: &str,
    explicit_data_dir: Option<&str>,
) -> Result<PathBuf, AppError> {
    let resolved = resolve_data_path(raw_path, explicit_data_dir);
    if resolved.exists() {
        return Ok(resolved);
    }
    Err(AppError::Config(format!(
        "expected at {}; set DATA_DIR",
        resolved.display()
    )))
}
