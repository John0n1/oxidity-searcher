// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@on1.no>

use crate::common::error::AppError;
use alloy_json_abi::JsonAbi;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct AbiRegistry {
    abis: HashMap<String, JsonAbi>,
}

impl AbiRegistry {
    pub fn new() -> Self {
        Self {
            abis: HashMap::new(),
        }
    }

    pub fn load_from_directory(&mut self, dir_path: &str) -> Result<(), AppError> {
        let path = Path::new(dir_path);

        if !path.exists() {
            return Err(AppError::Config(format!(
                "ABI directory not found: {}",
                dir_path
            )));
        }

        for entry in fs::read_dir(path).map_err(|e| AppError::Initialization(e.to_string()))? {
            let entry = entry.map_err(|e| AppError::Initialization(e.to_string()))?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let file_stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                let file_content = fs::read_to_string(&path).map_err(|e| {
                    AppError::Config(format!("Failed to read ABI {}: {}", file_stem, e))
                })?;

                let abi: JsonAbi = serde_json::from_str(&file_content).map_err(|e| {
                    AppError::Config(format!("Failed to parse ABI {}: {}", file_stem, e))
                })?;

                tracing::info!("Loaded ABI: {}", file_stem);
                self.abis.insert(file_stem, abi);
            }
        }
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&JsonAbi> {
        self.abis.get(name)
    }
}
