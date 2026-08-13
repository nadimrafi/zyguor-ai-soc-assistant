use crate::config::{OLLAMA_MODEL, OLLAMA_URL};
use crate::models::InvestigationReport;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct OllamaChatRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    stream: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct OllamaMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct OllamaChatResponse {
    message: OllamaMessage,
}

pub async fn generate_ai_analysis(
    report: &InvestigationReport,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let prompt = build_analysis_prompt(report);

    let request = OllamaChatRequest {
        model: OLLAMA_MODEL.to_string(),
        messages: vec![
            OllamaMessage {
                role: "system".to_string(),
                content: system_prompt().to_string(),
            },
            OllamaMessage {
                role: "user".to_string(),
                content: prompt,
            },
        ],
        stream: false,
    };

    let client = reqwest::Client::new();

    let response = client
        .post(OLLAMA_URL)
        .json(&request)
        .send()
        .await?
        .error_for_status()?;

    let body = response.json::<OllamaChatResponse>().await?;

    Ok(body.message.content.trim().to_string())
}

fn system_prompt() -> &'static str {
    "You are assisting a SOC analyst.

The Rust security engine has already performed the deterministic
security analysis.

Do not override the supplied severity, confidence score, or
MITRE ATT&CK mappings.

Explain the investigation evidence in clear professional language.

Identify useful investigation context and practical next steps.

Do not invent indicators, users, hosts, events, or evidence that
are not present in the supplied report.

Clearly distinguish facts from possible interpretations.

Keep the response concise and suitable for inclusion in a SOC
investigation report."
}

fn build_analysis_prompt(report: &InvestigationReport) -> String {
    let mitre = if report.mitre.is_empty() {
        "None".to_string()
    } else {
        report
            .mitre
            .iter()
            .map(|technique| format!("{} - {}", technique.technique_id, technique.technique_name))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let findings = if report.knowledge.is_empty() {
        "None".to_string()
    } else {
        report
            .knowledge
            .iter()
            .map(|fact| format!("{}: {}", fact.title, fact.description))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let recommendations = if report.recommendations.is_empty() {
        "None".to_string()
    } else {
        report
            .recommendations
            .iter()
            .map(|recommendation| {
                format!("[{}] {}", recommendation.priority, recommendation.action)
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        "Analyze the following deterministic SOC investigation.

Report ID: {}
Status: {}
Severity: {}
Confidence: {} ({}%)

MITRE ATT&CK:
{}

Security Findings:
{}

Existing Analyst Recommendations:
{}

Deterministic Narrative:
{}

Provide a concise AI-assisted analyst explanation based only on
the evidence above.",
        report.report_id,
        report.case_status,
        report.severity,
        report.confidence.level,
        report.confidence.score,
        mitre,
        findings,
        recommendations,
        report.narrative,
    )
}
