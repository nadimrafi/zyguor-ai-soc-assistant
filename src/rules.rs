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
    parsed: &ParsedAlert,
    ipv4_addresses: &[String],
) -> Vec<MitreTechnique> {
    let mut techniques = Vec::new();

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

    if external_ip_present {
        techniques.push(MitreTechnique {
            technique_id: "T1110".to_string(),
            technique_name: "Brute Force".to_string(),
        });
    }

    if privileged_account {
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
    fn maps_mitre_techniques() {
        let parsed = parsed_alert_with_user(Some("administrator"));

        let ips = vec!["8.8.8.8".to_string()];

        let mitre = map_mitre_techniques(&parsed, &ips);

        assert_eq!(mitre.len(), 2);

        assert_eq!(mitre[0].technique_id, "T1110");

        assert_eq!(mitre[1].technique_id, "T1078");
    }
}
