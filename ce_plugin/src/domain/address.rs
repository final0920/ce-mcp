use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressSource {
    Runtime,
    Dump,
    Derived,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressRef {
    pub module_name: String,
    pub module_base: String,
    pub va: String,
    pub rva: String,
    pub file_offset: Option<String>,
    pub arch: String,
    pub source: AddressSource,
}
