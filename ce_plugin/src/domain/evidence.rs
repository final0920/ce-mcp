use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::address::AddressRef;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    BreakpointHit,
    MemorySnapshot,
    PointerSnapshot,
    ValidatorPass,
    ValidatorFail,
    ManualNote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub event_type: EvidenceType,
    pub captured_at: String,
    pub session_id: Option<String>,
    pub scenario_id: Option<String>,
    pub address: Option<AddressRef>,
    pub thread_id: Option<u32>,
    pub registers: Option<BTreeMap<String, String>>,
    pub summary: Option<String>,
    pub payload: Value,
    pub tags: Vec<String>,
}
