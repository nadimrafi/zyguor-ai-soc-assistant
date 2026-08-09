use crate::models::{KnowledgeFact, MitreTechnique, ParsedAlert};
use crate::rules::Severity;

pub fn build_knowledge(
    parsed: &ParsedAlert,
    severity: &Severity,
    mitre: &[MitreTechnique],
) -> Vec<KnowledgeFact> {
    let mut facts = Vec::new();

    if let Some(username) = &parsed.username
        && (username.eq_ignore_ascii_case("administrator")
            || username.eq_ignore_ascii_case("admin")
            || username.eq_ignore_ascii_case("root"))
    {
        facts.push(KnowledgeFact {
            title: "Privileged Account".to_string(),
            description: format!("The alert involves the privileged account '{}'.", username),
        });
    }

    match severity {
        Severity::High => facts.push(KnowledgeFact {
            title: "High Severity".to_string(),
            description: "The alert has been classified as High.".to_string(),
        }),

        Severity::Medium => facts.push(KnowledgeFact {
            title: "Medium Severity".to_string(),
            description: "The alert has been classified as Medium.".to_string(),
        }),

        Severity::Low => facts.push(KnowledgeFact {
            title: "Low Severity".to_string(),
            description: "The alert has been classified as Low.".to_string(),
        }),
    }

    for technique in mitre {
        facts.push(KnowledgeFact {
            title: format!("MITRE {}", technique.technique_id),
            description: technique.technique_name.clone(),
        });
    }

    facts
}
