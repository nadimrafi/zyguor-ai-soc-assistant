use crate::models::InvestigationReport;
use std::fs;
use std::io;
use std::path::Path;

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
use std::fs::DirEntry;

pub fn list_reports() -> io::Result<Vec<String>> {
    let directory = Path::new("investigations");

    if !directory.exists() {
        return Ok(Vec::new());
    }

    let mut reports = Vec::new();

    for entry in fs::read_dir(directory)? {
        let entry: DirEntry = entry?;

        if let Some(file_name) = entry.file_name().to_str() {
            reports.push(file_name.to_string());
        }
    }

    reports.sort();

    Ok(reports)
}
pub fn load_report(report_id: &str) -> io::Result<String> {
    let filename = Path::new("investigations").join(format!("{report_id}.json"));

    fs::read_to_string(filename)
}
