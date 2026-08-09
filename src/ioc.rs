use std::net::Ipv4Addr;
use std::str::FromStr;

pub fn extract_ipv4_addresses(raw_alert: &str) -> Vec<String> {
    let mut addresses = Vec::new();

    for token in raw_alert.split_whitespace() {
        let cleaned = token.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');

        if cleaned.is_empty() {
            continue;
        }

        if Ipv4Addr::from_str(cleaned).is_ok() && !addresses.iter().any(|ip| ip == cleaned) {
            addresses.push(cleaned.to_string());
        }
    }

    addresses
}

#[cfg(test)]
mod tests {
    use super::extract_ipv4_addresses;

    #[test]
    fn extracts_valid_ipv4_addresses() {
        let alert = r#"
Source IP: 185.100.25.12
Destination IP: 10.0.0.5
"#;

        let ips = extract_ipv4_addresses(alert);

        assert_eq!(
            ips,
            vec!["185.100.25.12".to_string(), "10.0.0.5".to_string()]
        );
    }

    #[test]
    fn ignores_invalid_ipv4_addresses() {
        let alert = r#"
Source IP: 999.999.999.999
Destination IP: 10.0.0.5
"#;

        let ips = extract_ipv4_addresses(alert);

        assert_eq!(ips, vec!["10.0.0.5".to_string()]);
    }

    #[test]
    fn removes_duplicate_ipv4_addresses() {
        let alert = r#"
Source IP: 192.168.1.10
Repeated IP: 192.168.1.10
"#;

        let ips = extract_ipv4_addresses(alert);

        assert_eq!(ips, vec!["192.168.1.10".to_string()]);
    }

    #[test]
    fn handles_empty_input() {
        let ips = extract_ipv4_addresses("");

        assert!(ips.is_empty());
    }
}
