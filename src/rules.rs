use std::net::Ipv4Addr;

use crate::models::{MitreTechnique, ParsedAlert};

#[derive(Debug, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
}

pub fn determine_severity(parsed: &ParsedAlert, ipv4_addresses: &[String]) -> Severity {
    let privileged_account = parsed
        .username
        .as_deref()
        .map(|username| {
            username.eq_ignore_ascii_case("administrator")
                || username.eq_ignore_ascii_case("admin")
                || username.eq_ignore_ascii_case("root")
        })
        .unwrap_or(false);

    let external_ip_present = ipv4_addresses.iter().any(|ip| {
        ip.parse::<Ipv4Addr>()
            .map(|address| !address.is_private())
            .unwrap_or(false)
    });

    match (privileged_account, external_ip_present) {
        (true, true) => Severity::High,
        (true, false) | (false, true) => Severity::Medium,
        (false, false) => Severity::Low,
    }
}

pub fn map_mitre_techniques(
    alert_type: &str,
    raw_alert: &str,
    parsed: &ParsedAlert,
    ipv4_addresses: &[String],
) -> Vec<MitreTechnique> {
    let mut techniques = Vec::new();

    let combined_text = format!("{alert_type} {raw_alert}").to_lowercase();

    let authentication_failure_evidence = combined_text.contains("failed login")
        || combined_text.contains("failed logon")
        || combined_text.contains("multiple failed")
        || combined_text.contains("brute force")
        || combined_text.contains("bruteforce")
        || combined_text.contains("password spray");

    let successful_login_evidence = combined_text.contains("successful login")
        || combined_text.contains("successful logon")
        || combined_text.contains("valid credentials")
        || combined_text.contains("account compromise");

    let external_ip_present = ipv4_addresses.iter().any(|ip| {
        ip.parse::<Ipv4Addr>()
            .map(|address| !address.is_private())
            .unwrap_or(false)
    });

    let privileged_account = parsed.username.as_deref().is_some_and(|username| {
        username.eq_ignore_ascii_case("administrator")
            || username.eq_ignore_ascii_case("admin")
            || username.eq_ignore_ascii_case("root")
    });

    if authentication_failure_evidence && external_ip_present {
        techniques.push(MitreTechnique {
            technique_id: "T1110".to_string(),
            technique_name: "Brute Force".to_string(),
        });
    }

    if successful_login_evidence && privileged_account {
        techniques.push(MitreTechnique {
            technique_id: "T1078".to_string(),
            technique_name: "Valid Accounts".to_string(),
        });
    }

    techniques
}

#[cfg(test)]
mod tests {
    use super::{Severity, determine_severity, map_mitre_techniques};

    use crate::models::ParsedAlert;

    fn parsed_alert_with_user(username: Option<&str>) -> ParsedAlert {
        ParsedAlert {
            source_ip: None,
            username: username.map(str::to_string),
            hostname: None,
            timestamp: None,
        }
    }

    #[test]
    fn privileged_account_and_external_ip_is_high() {
        let parsed = parsed_alert_with_user(Some("administrator"));

        let ips = vec!["8.8.8.8".to_string()];

        assert_eq!(determine_severity(&parsed, &ips), Severity::High);
    }

    #[test]
    fn privileged_account_only_is_medium() {
        let parsed = parsed_alert_with_user(Some("admin"));

        let ips = vec!["192.168.1.20".to_string()];

        assert_eq!(determine_severity(&parsed, &ips), Severity::Medium);
    }

    #[test]
    fn external_ip_only_is_medium() {
        let parsed = parsed_alert_with_user(Some("user1"));

        let ips = vec!["1.1.1.1".to_string()];

        assert_eq!(determine_severity(&parsed, &ips), Severity::Medium);
    }

    #[test]
    fn ordinary_account_and_private_ip_is_low() {
        let parsed = parsed_alert_with_user(Some("user1"));

        let ips = vec!["10.0.0.15".to_string()];

        assert_eq!(determine_severity(&parsed, &ips), Severity::Low);
    }

    #[test]
    fn maps_brute_force_when_failed_logins_and_external_ip_exist() {
        let parsed = parsed_alert_with_user(Some("administrator"));

        let ips = vec!["8.8.8.8".to_string()];

        let mitre = map_mitre_techniques(
            "Multiple Failed Login Attempts",
            "User: administrator\nSource IP: 8.8.8.8",
            &parsed,
            &ips,
        );

        assert!(
            mitre
                .iter()
                .any(|technique| technique.technique_id == "T1110")
        );
    }

    #[test]
    fn external_ip_alone_does_not_map_brute_force() {
        let parsed = parsed_alert_with_user(Some("user1"));

        let ips = vec!["8.8.8.8".to_string()];

        let mitre = map_mitre_techniques(
            "Network Connection",
            "User: user1\nSource IP: 8.8.8.8",
            &parsed,
            &ips,
        );

        assert!(
            !mitre
                .iter()
                .any(|technique| technique.technique_id == "T1110")
        );
    }

    #[test]
    fn successful_privileged_login_maps_valid_accounts() {
        let parsed = parsed_alert_with_user(Some("administrator"));

        let ips = vec!["8.8.8.8".to_string()];

        let mitre = map_mitre_techniques(
            "Successful Login",
            "User: administrator\nSource IP: 8.8.8.8",
            &parsed,
            &ips,
        );

        assert!(
            mitre
                .iter()
                .any(|technique| technique.technique_id == "T1078")
        );
    }

    #[test]
    fn privileged_account_without_success_evidence_does_not_map_valid_accounts() {
        let parsed = parsed_alert_with_user(Some("administrator"));

        let ips = vec!["8.8.8.8".to_string()];

        let mitre = map_mitre_techniques(
            "Network Connection",
            "User: administrator\nSource IP: 8.8.8.8",
            &parsed,
            &ips,
        );

        assert!(
            !mitre
                .iter()
                .any(|technique| technique.technique_id == "T1078")
        );
    }
}
