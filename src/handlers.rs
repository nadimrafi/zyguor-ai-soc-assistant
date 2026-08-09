use crate::confidence::calculate_confidence;
use crate::ioc::extract_ipv4_addresses;
use crate::knowledge::build_knowledge;

use crate::models::{AnalyzeAlertRequest, AnalyzeAlertResponse, InvestigationReport};
use crate::narrative::build_narrative;
use crate::parser::parse_alert;
use crate::recommendations::build_recommendations;
use crate::rules::{Severity, determine_severity, map_mitre_techniques};
use axum::{Json, http::StatusCode};

pub async fn analyze_alert(
    Json(payload): Json<AnalyzeAlertRequest>,
) -> Result<Json<AnalyzeAlertResponse>, (StatusCode, String)> {
    let alert_type = payload.alert_type.trim();
    let raw_alert = payload.raw_alert.trim();

    if alert_type.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Alert type cannot be empty.".to_string(),
        ));
    }

    if raw_alert.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Raw alert cannot be empty.".to_string(),
        ));
    }

    let parsed = parse_alert(raw_alert);
    let ipv4_addresses = extract_ipv4_addresses(raw_alert);

    let severity = determine_severity(&parsed, &ipv4_addresses);

    let mitre = map_mitre_techniques(&parsed, &ipv4_addresses);
    let confidence = calculate_confidence(&parsed, &ipv4_addresses, &mitre);

    let knowledge = build_knowledge(&parsed, &severity, &mitre);

    let recommendations = build_recommendations(&parsed, &severity, &mitre);

    let severity_text = match severity {
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
    };

    let narrative = build_narrative(severity_text, &confidence, &mitre);

    let report = InvestigationReport {
        severity: severity_text.to_string(),
        confidence,
        mitre,
        knowledge,
        recommendations,
        narrative,
    };

    let response = AnalyzeAlertResponse {
        alert_type: alert_type.to_string(),
        summary: "Alert received, validated, and analyzed successfully.".to_string(),
        source_ip: parsed.source_ip,
        username: parsed.username,
        hostname: parsed.hostname,
        timestamp: parsed.timestamp,
        ipv4_addresses,
        report,
    };

    Ok(Json(response))
}
