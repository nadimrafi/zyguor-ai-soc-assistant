use crate::models::ParsedAlert;

pub fn parse_alert(raw_alert: &str) -> ParsedAlert {
    let mut parsed = ParsedAlert::default();

    for line in raw_alert.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };

        let key = key.trim().to_lowercase();
        let value = value.trim();

        if value.is_empty() {
            continue;
        }

        match key.as_str() {
            "source ip" | "source_ip" | "src ip" => {
                parsed.source_ip = Some(value.to_string());
            }
            "username" | "user" | "account" => {
                parsed.username = Some(value.to_string());
            }
            "hostname" | "host" | "computer" => {
                parsed.hostname = Some(value.to_string());
            }
            "time" | "timestamp" | "event time" => {
                parsed.timestamp = Some(value.to_string());
            }
            _ => {}
        }
    }

    parsed
}

#[cfg(test)]
mod tests {
    use super::parse_alert;

    #[test]
    fn parses_common_soc_alert_fields() {
        let alert = r#"
Alert Name: Multiple Failed Login Attempts
Source IP: 185.100.25.12
Username: administrator
Hostname: DC-01
Time: 03:14 UTC
"#;

        let parsed = parse_alert(alert);

        assert_eq!(parsed.source_ip.as_deref(), Some("185.100.25.12"));
        assert_eq!(parsed.username.as_deref(), Some("administrator"));
        assert_eq!(parsed.hostname.as_deref(), Some("DC-01"));
        assert_eq!(parsed.timestamp.as_deref(), Some("03:14 UTC"));
    }

    #[test]
    fn ignores_unknown_fields() {
        let alert = r#"
Random Field: Test
Source IP: 10.0.0.5
"#;

        let parsed = parse_alert(alert);

        assert_eq!(parsed.source_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(parsed.username, None);
    }

    #[test]
    fn handles_empty_alert_safely() {
        let parsed = parse_alert("");

        assert_eq!(parsed.source_ip, None);
        assert_eq!(parsed.username, None);
        assert_eq!(parsed.hostname, None);
        assert_eq!(parsed.timestamp, None);
    }
}
