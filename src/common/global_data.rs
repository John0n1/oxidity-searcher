// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@oxidity.io>

use crate::common::error::AppError;
use serde::de::DeserializeOwned;
use std::fs;
use std::path::Path;

pub fn read_global_data_raw(path: &Path) -> Result<String, AppError> {
    if !path.exists() {
        return Err(AppError::Config(format!(
            "Global data file not found: {}",
            path.display()
        )));
    }
    fs::read_to_string(path).map_err(|e| {
        AppError::Config(format!(
            "Failed to read global data file {}: {e}",
            path.display()
        ))
    })
}

pub fn parse_global_data_file<T: DeserializeOwned>(
    path: &Path,
    section_label: &str,
) -> Result<T, AppError> {
    let raw = read_global_data_raw(path)?;
    serde_json::from_str(&raw).map_err(|e| {
        AppError::Config(format!(
            "Failed to parse {section_label} from {}: {e}",
            path.display()
        ))
    })
}
