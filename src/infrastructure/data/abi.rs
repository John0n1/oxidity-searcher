// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 ® John Hauger Mitander <john@mitander.dev>

use crate::common::error::AppError;
use alloy_json_abi::JsonAbi;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct AbiRegistry {
    abis: HashMap<String, JsonAbi>,
}

#[derive(Debug, Deserialize, Default)]
struct GlobalDataAbiFile {
    #[serde(default)]
    executor_abi: Vec<Value>,
}

impl Default for AbiRegistry {
    fn default() -> Self {
        Self::new()
    }
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

        let global_data_path = path.join("global_data.json");
        let raw = fs::read_to_string(&global_data_path).map_err(|e| {
            AppError::Config(format!(
                "Failed to read ABI source {}: {}",
                global_data_path.display(),
                e
            ))
        })?;
        let parsed: GlobalDataAbiFile = serde_json::from_str(&raw).map_err(|e| {
            AppError::Config(format!(
                "Failed to parse ABI source {}: {}",
                global_data_path.display(),
                e
            ))
        })?;
        if parsed.executor_abi.is_empty() {
            return Err(AppError::Config(format!(
                "Missing executor_abi in {}",
                global_data_path.display()
            )));
        }
        let abi_raw = serde_json::to_string(&parsed.executor_abi)
            .map_err(|e| AppError::Config(format!("Failed to serialize executor_abi: {}", e)))?;
        let abi: JsonAbi = serde_json::from_str(&abi_raw)
            .map_err(|e| AppError::Config(format!("Failed to parse executor_abi: {}", e)))?;
        self.abis
            .insert("UnifiedHardenedExecutor_abi".to_string(), abi.clone());
        self.abis.insert("UnifiedHardenedExecutor".to_string(), abi);
        tracing::info!("Loaded ABI: UnifiedHardenedExecutor from global_data.json");
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&JsonAbi> {
        self.abis.get(name)
    }
}
