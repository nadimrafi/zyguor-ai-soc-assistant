use crate::models::InvestigationReport;

use std::fs;
use std::io;
use std::path::Path;

pub fn is_valid_report_id(report_id: &str) -> bool {
    let Some(number) = report_id.strip_prefix("SOC-") else {
        return false;
    };

    !number.is_empty() && number.chars().all(|character| character.is_ascii_digit())
}

pub fn save_report(report: &InvestigationReport) -> io::Result<()> {
    let directory = Path::new("investigations");

    if !directory.exists() {
        fs::create_dir_all(directory)?;
    }

    let filename = directory.join(format!("{}.json", report.report_id));

    let json = serde_json::to_string_pretty(report).map_err(io::Error::other)?;

    fs::write(filename, json)?;

    Ok(())
}

pub fn list_reports() -> io::Result<Vec<String>> {
    let directory = Path::new("investigations");

    if !directory.exists() {
        return Ok(Vec::new());
    }

    let mut reports = Vec::new();

    for entry in fs::read_dir(directory)? {
        let entry = entry?;

        if let Some(file_name) = entry.file_name().to_str() {
            reports.push(file_name.to_string());
        }
    }

    reports.sort();

    Ok(reports)
}

pub fn load_report(report_id: &str) -> io::Result<String> {
    if !is_valid_report_id(report_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid report ID",
        ));
    }

    let filename = Path::new("investigations").join(format!("{report_id}.json"));

    fs::read_to_string(filename)
}
#[cfg(test)]
mod tests {
    use super::is_valid_report_id;

    #[test]
    fn accepts_valid_report_id() {
        assert!(is_valid_report_id("SOC-1786366419"));
    }

    #[test]
    fn rejects_missing_numeric_part() {
        assert!(!is_valid_report_id("SOC-"));
    }

    #[test]
    fn rejects_non_numeric_report_id() {
        assert!(!is_valid_report_id("SOC-ABC"));
    }

    #[test]
    fn rejects_extra_suffix() {
        assert!(!is_valid_report_id("SOC-123-test"));
    }

    #[test]
    fn rejects_json_filename() {
        assert!(!is_valid_report_id("SOC-1786366419.json"));
    }

    #[test]
    fn rejects_path_traversal_style_input() {
        assert!(!is_valid_report_id("../../Cargo.toml"));
    }

    #[test]
    fn rejects_wrong_prefix() {
        assert!(!is_valid_report_id("CASE-1786366419"));
    }

    #[test]
    fn load_report_rejects_invalid_report_id() {
        let result = super::load_report("../../Cargo.toml");

        assert!(result.is_err());

        if let Err(error) = result {
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
    }
}
