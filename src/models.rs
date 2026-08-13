use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct AnalyzeAlertRequest {
    pub alert_type: String,
    pub raw_alert: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct AnalyzeAlertResponse {
    pub alert_type: String,
    pub summary: String,
    pub source_ip: Option<String>,
    pub username: Option<String>,
    pub hostname: Option<String>,
    pub timestamp: Option<String>,
    pub ipv4_addresses: Vec<String>,
    pub report: InvestigationReport,
}
#[derive(Debug, Default, PartialEq)]
pub struct ParsedAlert {
    pub source_ip: Option<String>,
    pub username: Option<String>,
    pub hostname: Option<String>,
    pub timestamp: Option<String>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MitreTechnique {
    pub technique_id: String,
    pub technique_name: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KnowledgeFact {
    pub title: String,
    pub description: String,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Recommendation {
    pub priority: String,
    pub action: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfidenceAssessment {
    pub score: u8,
    pub level: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InvestigationReport {
    pub report_id: String,
    pub generated_at: u64,
    pub case_status: String,
    pub severity: String,
    pub confidence: ConfidenceAssessment,
    pub mitre: Vec<MitreTechnique>,
    pub knowledge: Vec<KnowledgeFact>,
    pub recommendations: Vec<Recommendation>,
    pub narrative: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_analysis: Option<String>,
}
