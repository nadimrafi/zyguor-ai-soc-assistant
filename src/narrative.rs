use crate::models::{ConfidenceAssessment, MitreTechnique};

pub fn build_narrative(
    severity: &str,
    confidence: &ConfidenceAssessment,
    mitre: &[MitreTechnique],
) -> String {
    let mut narrative = format!(
        "The alert has been classified as {} severity. \
         The confidence in this assessment is {} ({}%).",
        severity, confidence.level, confidence.score
    );

    if !mitre.is_empty() {
        narrative.push_str(" Mapped MITRE ATT&CK techniques include ");

        for (index, technique) in mitre.iter().enumerate() {
            if index > 0 {
                narrative.push_str(", ");
            }

            narrative.push_str(&format!(
                "{} ({})",
                technique.technique_id, technique.technique_name
            ));
        }

        narrative.push('.');
    }

    narrative
}

#[cfg(test)]
mod tests {
    use super::build_narrative;
    use crate::models::{ConfidenceAssessment, MitreTechnique};

    #[test]
    fn builds_high_severity_narrative() {
        let confidence = ConfidenceAssessment {
            score: 90,
            level: "High".to_string(),
            reasons: vec!["Strong evidence available".to_string()],
        };

        let mitre = vec![MitreTechnique {
            technique_id: "T1110".to_string(),
            technique_name: "Brute Force".to_string(),
        }];

        let narrative = build_narrative("High", &confidence, &mitre);

        assert!(narrative.contains("High severity"));
        assert!(narrative.contains("90%"));
        assert!(narrative.contains("T1110"));
        assert!(narrative.contains("Brute Force"));
    }
}
