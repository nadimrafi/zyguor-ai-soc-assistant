use crate::models::AnalyzeAlertResponse;

#[derive(Debug, Clone)]
pub struct ExportReport {
    pub report_id: String,
    pub status: String,
    pub generated_at: u64,
    pub severity: String,
    pub confidence_level: String,
    pub confidence_score: u8,
    pub narrative: String,
}

pub struct ReportBuilder;

impl ReportBuilder {
    pub fn build(
        response: &AnalyzeAlertResponse,
    ) -> ExportReport {
        ExportReport {
            report_id: response.report.report_id.clone(),
            status: response.report.case_status.clone(),
            generated_at: response.report.generated_at,
            severity: response.report.severity.clone(),
            confidence_level: response.report.confidence.level.clone(),
            confidence_score: response.report.confidence.score,
            narrative: response.report.narrative.clone(),
        }
    }
}