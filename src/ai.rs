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
    "You are an AI assistant supporting a SOC analyst.

The Rust security engine has already performed the authoritative
deterministic analysis.

Treat the supplied severity, confidence score, MITRE ATT&CK mappings,
security findings, and observed indicators as the established output
of the Rust engine.

Do not override, recalculate, downgrade, or upgrade those deterministic
results.

Your role is to explain the evidence, provide useful security context,
and suggest practical investigation steps.

Never invent IP addresses, usernames, hostnames, timestamps, events,
attack techniques, indicators, or other evidence that is not present
in the supplied investigation.

Do not claim that malicious activity, compromise, account takeover,
successful exploitation, or attacker intent has been confirmed unless
the supplied evidence explicitly establishes it.

When the evidence supports suspicion but not confirmation, use cautious
language such as 'may indicate', 'could represent', 'is consistent with',
or 'requires analyst verification'.

Clearly distinguish:
- observed facts,
- deterministic Rust findings,
- possible interpretations,
- items requiring further verification.

MITRE ATT&CK mappings describe observed or suspected techniques and
must not by themselves be treated as proof of compromise.

Recommendations must be practical and proportionate to the supplied
severity and evidence.

Do not contradict the deterministic investigation report.

Do not infer that an alert is a false positive, benign, insignificant,
or safe merely because its severity is Low, confidence is limited, or
no MITRE ATT&CK technique has been mapped.

Absence of evidence in the supplied report must not be treated as
evidence that malicious activity did not occur.

When evidence is limited, state that the available information is
insufficient for a stronger conclusion and identify what additional
evidence an analyst should verify.

Keep the response concise, professional, evidence-based, and suitable
for inclusion in a SOC investigation report."
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
