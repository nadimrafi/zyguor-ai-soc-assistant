use crate::models::{MitreTechnique, ParsedAlert, Recommendation};
use crate::rules::Severity;

pub fn build_recommendations(
    parsed: &ParsedAlert,
    severity: &Severity,
    mitre: &[MitreTechnique],
) -> Vec<Recommendation> {
    let mut recommendations = Vec::new();

    let privileged_account = parsed
        .username
        .as_deref()
        .map(|username| {
            username.eq_ignore_ascii_case("administrator")
                || username.eq_ignore_ascii_case("admin")
                || username.eq_ignore_ascii_case("root")
        })
        .unwrap_or(false);

    let brute_force_detected = mitre
        .iter()
        .any(|technique| technique.technique_id == "T1110");

    if privileged_account {
        recommendations.push(Recommendation {
            priority: "High".to_string(),
            action: "Verify whether activity involving the privileged account is legitimate."
                .to_string(),
        });

        recommendations.push(Recommendation {
            priority: "High".to_string(),
            action:
                "Confirm that multi-factor authentication is enabled for the privileged account."
                    .to_string(),
        });
    }

    if brute_force_detected {
        recommendations.push(Recommendation {
            priority: "High".to_string(),
            action: "Review authentication logs for repeated failed login attempts and related source addresses."
                .to_string(),
        });
    }

    match severity {
        Severity::High => {
            recommendations.push(Recommendation {
                priority: "Critical".to_string(),
                action: "Escalate the alert for immediate analyst investigation.".to_string(),
            });

            recommendations.push(Recommendation {
                priority: "High".to_string(),
                action: "Consider containment if malicious activity is confirmed.".to_string(),
            });
        }

        Severity::Medium => {
            recommendations.push(Recommendation {
                priority: "Medium".to_string(),
                action: "Perform additional investigation and validate the observed activity."
                    .to_string(),
            });
        }

        Severity::Low => {
            recommendations.push(Recommendation {
                priority: "Low".to_string(),
                action: "Document the alert and continue monitoring for related activity."
                    .to_string(),
            });
        }
    }

    recommendations
}

#[cfg(test)]
mod tests {
    use super::build_recommendations;
    use crate::models::{MitreTechnique, ParsedAlert};
    use crate::rules::Severity;

    fn parsed_alert(username: Option<&str>) -> ParsedAlert {
        ParsedAlert {
            source_ip: None,
            username: username.map(str::to_string),
            hostname: None,
            timestamp: None,
        }
    }

    #[test]
    fn high_severity_privileged_alert_generates_actions() {
        let parsed = parsed_alert(Some("administrator"));

        let mitre = vec![MitreTechnique {
            technique_id: "T1110".to_string(),
            technique_name: "Brute Force".to_string(),
        }];

        let recommendations = build_recommendations(&parsed, &Severity::High, &mitre);

        assert!(!recommendations.is_empty());

        assert!(
            recommendations
                .iter()
                .any(|item| item.priority == "Critical")
        );
    }

    #[test]
    fn low_severity_alert_generates_monitoring_action() {
        let parsed = parsed_alert(Some("user1"));

        let recommendations = build_recommendations(&parsed, &Severity::Low, &[]);

        assert!(recommendations.iter().any(|item| item.priority == "Low"));
    }
}
