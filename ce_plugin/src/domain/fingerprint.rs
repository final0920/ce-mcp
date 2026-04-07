use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleFingerprint {
    pub build_version: Option<String>,
    pub module_name: String,
    pub pe_timestamp: Option<u32>,
    pub image_size: Option<u64>,
    pub entry_point_rva: Option<String>,
    pub image_base: Option<String>,
    pub machine: Option<String>,
    pub section_hashes: BTreeMap<String, String>,
    pub import_hash: Option<String>,
}
