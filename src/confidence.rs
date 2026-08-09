use crate::models::{ConfidenceAssessment, MitreTechnique, ParsedAlert};

pub fn calculate_confidence(
    parsed: &ParsedAlert,
    ipv4_addresses: &[String],
    mitre: &[MitreTechnique],
) -> ConfidenceAssessment {
    let mut score: u8 = 20;
    let mut reasons = Vec::new();

    if parsed.username.is_some() {
        score = score.saturating_add(15);
        reasons.push("Username identified".to_string());
    }

    if parsed.hostname.is_some() {
        score = score.saturating_add(10);
        reasons.push("Hostname identified".to_string());
    }

    if parsed.timestamp.is_some() {
        score = score.saturating_add(10);
        reasons.push("Event timestamp identified".to_string());
    }

    if !ipv4_addresses.is_empty() {
        score = score.saturating_add(20);
        reasons.push("Valid IPv4 indicator identified".to_string());
    }

    if !mitre.is_empty() {
        score = score.saturating_add(25);
        reasons.push("MITRE ATT&CK mapping available".to_string());
    }

    let score = score.min(100);

    let level = match score {
        0..=39 => "Low",
        40..=69 => "Medium",
        _ => "High",
    };

    ConfidenceAssessment {
        score,
        level: level.to_string(),
        reasons,
    }
}
#[cfg(test)]
mod tests {
    use super::calculate_confidence;
    use crate::models::{MitreTechnique, ParsedAlert};

    #[test]
    fn richer_evidence_produces_high_confidence() {
        let parsed = ParsedAlert {
            source_ip: Some("8.8.8.8".to_string()),
            username: Some("administrator".to_string()),
            hostname: Some("DC-01".to_string()),
            timestamp: Some("03:14 UTC".to_string()),
        };

        let ips = vec!["8.8.8.8".to_string()];

        let mitre = vec![MitreTechnique {
            technique_id: "T1110".to_string(),
            technique_name: "Brute Force".to_string(),
        }];

        let result = calculate_confidence(&parsed, &ips, &mitre);

        assert_eq!(result.score, 100);
        assert_eq!(result.level, "High");
        assert!(!result.reasons.is_empty());
    }

    #[test]
    fn limited_evidence_produces_low_confidence() {
        let parsed = ParsedAlert {
            source_ip: None,
            username: None,
            hostname: None,
            timestamp: None,
        };

        let result = calculate_confidence(&parsed, &[], &[]);

        assert_eq!(result.score, 20);
        assert_eq!(result.level, "Low");
    }
}
