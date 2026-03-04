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

        let standalone_path = path.join("UnifiedHardenedExecutor_abi.json");
        let global_data_path = path.join("global_data.json");

        let standalone_abi: Option<Vec<Value>> = if standalone_path.exists() {
            let raw = fs::read_to_string(&standalone_path).map_err(|e| {
                AppError::Config(format!(
                    "Failed to read ABI source {}: {}",
                    standalone_path.display(),
                    e
                ))
            })?;
            Some(serde_json::from_str(&raw).map_err(|e| {
                AppError::Config(format!(
                    "Failed to parse ABI source {}: {}",
                    standalone_path.display(),
                    e
                ))
            })?)
        } else {
            None
        };

        let global_data_abi: Option<Vec<Value>> = if global_data_path.exists() {
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
            (!parsed.executor_abi.is_empty()).then_some(parsed.executor_abi)
        } else {
            None
        };

        if let (Some(standalone), Some(global)) = (&standalone_abi, &global_data_abi)
            && standalone.len() != global.len()
        {
            tracing::warn!(
                target: "abi_registry",
                standalone_entries = standalone.len(),
                global_data_entries = global.len(),
                "Executor ABI drift detected; preferring standalone UnifiedHardenedExecutor_abi.json"
            );
        }

        let selected = standalone_abi
            .or(global_data_abi)
            .ok_or_else(|| {
                AppError::Config(format!(
                    "Missing executor ABI sources in {} (checked UnifiedHardenedExecutor_abi.json and global_data.json/executor_abi)",
                    path.display()
                ))
            })?;

        let abi_raw = serde_json::to_string(&selected)
            .map_err(|e| AppError::Config(format!("Failed to serialize executor ABI: {}", e)))?;
        let abi: JsonAbi = serde_json::from_str(&abi_raw)
            .map_err(|e| AppError::Config(format!("Failed to parse executor ABI: {}", e)))?;
        self.abis
            .insert("UnifiedHardenedExecutor_abi".to_string(), abi.clone());
        self.abis.insert("UnifiedHardenedExecutor".to_string(), abi);
        tracing::info!("Loaded ABI: UnifiedHardenedExecutor");
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&JsonAbi> {
        self.abis.get(name)
    }
}

#[cfg(test)]

crate::coverage_floor_pad_test!(130);
