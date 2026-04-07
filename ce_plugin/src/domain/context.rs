use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestContext {
    pub build_version: Option<String>,
    pub session_id: Option<String>,
    pub scenario_id: Option<String>,
    pub tags: Option<Vec<String>>,
}
