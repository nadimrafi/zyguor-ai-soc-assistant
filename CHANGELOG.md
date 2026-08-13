# Changelog

All notable changes to Zyguor AI SOC Assistant are documented in this file.

## [1.0.0] - 2026-08-13

### Added

- Rust/Axum security alert analysis backend
- Browser-based SOC investigation interface
- Alert input validation
- Structured alert parser
- Support for multiline and inline SOC alert fields
- Source IP, username, hostname, and timestamp extraction
- IPv4 IOC extraction
- Deterministic severity classification
- Investigation confidence scoring
- MITRE ATT&CK mapping
- Security knowledge findings
- Recommended analyst actions
- Deterministic analyst narrative
- Investigation report IDs and timestamps
- JSON investigation persistence
- Investigation history and saved-report loading
- Report ID validation
- Path-traversal protection for report access
- JSON report export
- PDF investigation report generation
- Local Ollama integration
- Llama 3.2 AI-assisted analyst analysis
- AI analysis persistence in InvestigationReport
- AI-assisted analysis display in the browser
- AI-assisted analysis in PDF reports
- AI reasoning guardrails
- Graceful fallback to deterministic Rust analysis when AI is unavailable
- Automated Rust tests
- Strict Clippy QA

### Security

- Deterministic Rust analysis remains authoritative over AI-generated explanations.
- AI is instructed not to override severity, confidence, MITRE ATT&CK mappings, or established findings.
- AI output is treated as analyst assistance rather than confirmed security evidence.
- Invalid and path-traversal-style report identifiers are rejected.
- Runtime investigation and export data are excluded from source control.

### Notes

Version 1.0 focuses on a reliable, explainable SOC investigation workflow.

Advanced UI design, broader detection coverage, additional AI providers, deeper enrichment, and other product enhancements are reserved for future versions.