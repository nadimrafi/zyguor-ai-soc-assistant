use crate::models::ParsedAlert;

const ALL_FIELD_LABELS: &[&str] = &[
    "source ip",
    "source_ip",
    "src ip",
    "external ip",
    "username",
    "user",
    "account",
    "hostname",
    "host",
    "computer",
    "timestamp",
    "event time",
    "time",
];

pub fn parse_alert(raw_alert: &str) -> ParsedAlert {
    ParsedAlert {
        source_ip: extract_field(
            raw_alert,
            &["source ip", "source_ip", "src ip", "external ip"],
        ),
        username: extract_field(raw_alert, &["username", "user", "account"]),
        hostname: extract_field(raw_alert, &["hostname", "host", "computer"]),
        timestamp: extract_field(raw_alert, &["timestamp", "event time", "time"]),
    }
}

fn extract_field(raw_alert: &str, accepted_labels: &[&str]) -> Option<String> {
    let lowercase = raw_alert.to_ascii_lowercase();

    let mut selected_position = None;
    let mut selected_value_start = 0;

    for label in accepted_labels {
        let pattern = format!("{label}:");

        if let Some(position) = lowercase.find(&pattern) {
            let is_valid_boundary = position == 0
                || lowercase
                    .as_bytes()
                    .get(position.wrapping_sub(1))
                    .is_some_and(|byte| byte.is_ascii_whitespace());

            if !is_valid_boundary {
                continue;
            }

            if selected_position.is_none_or(|current_position| position < current_position) {
                selected_position = Some(position);
                selected_value_start = position + pattern.len();
            }
        }
    }

    selected_position?;

    let remaining_lowercase = &lowercase[selected_value_start..];

    let mut value_end = remaining_lowercase.len();

    if let Some(newline_position) = remaining_lowercase.find('\n') {
        value_end = value_end.min(newline_position);
    }

    for label in ALL_FIELD_LABELS {
        let next_pattern = format!("{label}:");

        if let Some(position) = remaining_lowercase.find(&next_pattern) {
            let is_valid_boundary = position == 0
                || remaining_lowercase
                    .as_bytes()
                    .get(position.wrapping_sub(1))
                    .is_some_and(|byte| byte.is_ascii_whitespace());

            if is_valid_boundary {
                value_end = value_end.min(position);
            }
        }
    }

    let value = raw_alert
        .get(selected_value_start..selected_value_start + value_end)?
        .trim();

    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::parse_alert;

    #[test]
    fn parses_multiline_soc_alert_fields() {
        let alert = r#"
Source IP: 185.100.25.12
User: administrator
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
    fn parses_inline_soc_alert_fields() {
        let alert = "Multiple failed login attempts detected. \
User: administrator Source IP: 8.8.8.8 \
Hostname: FINANCE-SERVER";

        let parsed = parse_alert(alert);

        assert_eq!(parsed.username.as_deref(), Some("administrator"));

        assert_eq!(parsed.source_ip.as_deref(), Some("8.8.8.8"));

        assert_eq!(parsed.hostname.as_deref(), Some("FINANCE-SERVER"));
    }

    #[test]
    fn parses_external_ip_label() {
        let alert = "User: administrator External IP: 8.8.8.8";

        let parsed = parse_alert(alert);

        assert_eq!(parsed.source_ip.as_deref(), Some("8.8.8.8"));

        assert_eq!(parsed.username.as_deref(), Some("administrator"));
    }

    #[test]
    fn parses_alternative_field_labels() {
        let alert = r#"
src ip: 1.1.1.1
Account: admin
Computer: SERVER-01
Event Time: 2026-08-13T16:00:00Z
"#;

        let parsed = parse_alert(alert);

        assert_eq!(parsed.source_ip.as_deref(), Some("1.1.1.1"));

        assert_eq!(parsed.username.as_deref(), Some("admin"));

        assert_eq!(parsed.hostname.as_deref(), Some("SERVER-01"));

        assert_eq!(parsed.timestamp.as_deref(), Some("2026-08-13T16:00:00Z"));
    }

    #[test]
    fn ignores_unknown_fields() {
        let alert = r#"
Unknown Field: something
Source IP: 10.0.0.5
"#;

        let parsed = parse_alert(alert);

        assert_eq!(parsed.source_ip.as_deref(), Some("10.0.0.5"));

        assert_eq!(parsed.username, None);
    }

    #[test]
    fn empty_field_returns_none() {
        let alert = "User:\nHostname: SERVER-01";

        let parsed = parse_alert(alert);

        assert_eq!(parsed.username, None);

        assert_eq!(parsed.hostname.as_deref(), Some("SERVER-01"));
    }
}
