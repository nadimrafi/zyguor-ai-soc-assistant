use crate::confidence::calculate_confidence;
use crate::ioc::extract_ipv4_addresses;
use crate::knowledge::build_knowledge;
use crate::models::{AnalyzeAlertRequest, AnalyzeAlertResponse, InvestigationReport};
use crate::narrative::build_narrative;
use crate::parser::parse_alert;
use crate::pdf::generate_investigation_pdf;
use crate::recommendations::build_recommendations;
use crate::report::{generate_report_id, generate_timestamp};

use crate::rules::{Severity, determine_severity, map_mitre_techniques};
use crate::storage::{list_reports, load_report, save_report};
use axum::{Json, extract::Path as AxumPath, http::StatusCode, response::IntoResponse};

pub async fn export_pdf(
    AxumPath(report_id): AxumPath<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !crate::storage::is_valid_report_id(&report_id) {
        return Err((StatusCode::BAD_REQUEST, "Invalid report ID.".to_string()));
    }

    let report = crate::storage::load_report_model(&report_id).map_err(|error| {
        (
            StatusCode::NOT_FOUND,
            format!("Unable to load report: {error}"),
        )
    })?;

    std::fs::create_dir_all("exports").map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to create export directory: {error}"),
        )
    })?;

    let output_path = format!("exports/{report_id}.pdf");

    generate_investigation_pdf(&report, &output_path).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to generate PDF: {error}"),
        )
    })?;

    Ok(format!("PDF generated successfully: {output_path}"))
}

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
    let mitre = map_mitre_techniques(alert_type, raw_alert, &parsed, &ipv4_addresses);
    let confidence = calculate_confidence(&parsed, &ipv4_addresses, &mitre);
    let knowledge = build_knowledge(&parsed, &severity, &mitre);
    let recommendations = build_recommendations(&parsed, &severity, &mitre);

    let severity_text = match severity {
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
    };

    let narrative = build_narrative(severity_text, &confidence, &mitre);

    let report_id = generate_report_id().map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to generate investigation ID: {error}"),
        )
    })?;

    let generated_at = generate_timestamp().map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to generate investigation timestamp: {error}"),
        )
    })?;

    let report = InvestigationReport {
        report_id,
        generated_at,
        case_status: "Open".to_string(),
        severity: severity_text.to_string(),
        confidence,
        mitre,
        knowledge,
        recommendations,
        narrative,
    };

    save_report(&report).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to save investigation: {error}"),
        )
    })?;

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

pub async fn history() -> Result<Json<Vec<String>>, (StatusCode, String)> {
    let reports = list_reports().map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to load investigation history: {error}"),
        )
    })?;

    Ok(Json(reports))
}

pub async fn load_history_report(
    AxumPath(report_id): AxumPath<String>,
) -> Result<String, (StatusCode, String)> {
    if !crate::storage::is_valid_report_id(&report_id) {
        return Err((StatusCode::BAD_REQUEST, "Invalid report ID.".to_string()));
    }

    let report = load_report(&report_id).map_err(|error| {
        (
            StatusCode::NOT_FOUND,
            format!("Unable to load investigation report: {error}"),
        )
    })?;

    Ok(report)
}
