# Zyguor AI SOC Assistant

A Rust-based, AI-enhanced security operations application for analyzing security alerts and producing structured SOC investigation reports.

Zyguor AI SOC Assistant combines a deterministic Rust security engine with local Llama-based analyst assistance. Rust remains responsible for validation, parsing, IOC extraction, severity classification, confidence scoring, MITRE ATT&CK mapping, security findings, and analyst recommendations. Llama provides an additional natural-language analyst explanation based on the structured investigation produced by Rust.

The AI layer is designed to assist rather than replace the deterministic security engine or human SOC analyst.

## Version

**v1.0.0**

## Project Status

Zyguor AI SOC Assistant v1.0 is the first stable release of the application.

The focus of v1.0 is a reliable end-to-end SOC investigation workflow rather than advanced UI design or autonomous AI decision-making.

## Core Features

- Security alert submission through a web interface
- Raw alert parsing
- Username, hostname, timestamp, and source IP extraction
- IPv4 indicator extraction
- Severity classification
- Confidence scoring
- MITRE ATT&CK technique mapping
- Structured security findings
- Recommended SOC analyst actions
- Analyst narrative generation
- Local AI-assisted investigation analysis using Ollama and Llama 3.2
- Evidence-based AI analyst explanations
- AI guardrails designed to preserve deterministic Rust findings
- Graceful deterministic-analysis fallback when AI analysis is unavailable
- Investigation report IDs and timestamps
- JSON-based investigation persistence
- Investigation history
- Loading previously saved investigations
- Investigation report copy function
- JSON export
- PDF investigation report generation
- AI-assisted analyst explanation in the web investigation report
- AI-assisted analyst explanation in PDF reports
- Report ID validation
- Path traversal protection for stored reports
- Rust unit tests and strict Clippy QA

## Technology Stack

### Backend

- Rust 2024 Edition
- Axum
- Tokio
- Serde / Serde JSON
- Tower HTTP
- Reqwest
- Tracing
- Anyhow
- Thiserror

### AI

- Ollama
- Llama 3.2
- Local Ollama HTTP API
- Rust `reqwest` HTTP client

The AI model runs locally through Ollama. The Rust application sends structured investigation context to Llama after the deterministic analysis has been completed.

### PDF

- printpdf

### Frontend

- HTML
- CSS
- JavaScript

## Project Structure

```text
zyguor-ai-soc-assistant/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── CHANGELOG.md
├── docs/
├── src/
│   ├── ai.rs
│   ├── confidence.rs
│   ├── config.rs
│   ├── errors.rs
│   ├── handlers.rs
│   ├── ioc.rs
│   ├── knowledge.rs
│   ├── main.rs
│   ├── models.rs
│   ├── narrative.rs
│   ├── parser.rs
│   ├── pdf.rs
│   ├── pdf_assets.rs
│   ├── pdf_builder.rs
│   ├── pdf_layout.rs
│   ├── prompt.rs
│   ├── recommendations.rs
│   ├── report.rs
│   ├── report_builder.rs
│   ├── responses.rs
│   ├── rules.rs
│   ├── state.rs
│   └── storage.rs
├── static/
│   ├── css/
│   ├── images/
│   ├── index.html
│   └── js/
├── templates/
└── tests/
```

Generated investigation and PDF files are stored locally at runtime and are excluded from Git tracking.

Security Alert
      |
      v
Input Validation
      |
      v
Rust Alert Parser
      |
      v
IOC Extraction
      |
      v
Deterministic Rust Security Engine
      |
      +---- Severity
      |
      +---- MITRE ATT&CK
      |
      +---- Confidence
      |
      +---- Security Findings
      |
      +---- Recommendations
      |
      v
InvestigationReport
      |
      v
Ollama / Llama 3.2
      |
      v
AI-Assisted Analyst Explanation
      |
      v
Rust-Controlled Investigation Report
      |
      +------> JSON Storage / History
      |
      +------> Web Interface
      |
      +------> PDF Export

### Deterministic Security + AI Design

Zyguor AI SOC Assistant does not send a raw alert directly to an LLM and treat the generated response as the security decision.

The deterministic Rust engine performs the core security analysis first. The resulting structured investigation is then provided to the AI layer for additional explanation and analyst assistance.

The AI is instructed not to override the severity, confidence score, MITRE ATT&CK mappings, or established security findings produced by the Rust engine.

If AI analysis is unavailable, the deterministic investigation remains usable.      


## Severity Analysis

The v1.0 rules engine evaluates security context such as:

- privileged accounts
- external IPv4 addresses
- authentication failure evidence

Severity is classified as:

- Low
- Medium
- High

The rules are intentionally deterministic and explainable.

## MITRE ATT&CK Mapping

The current rules engine can map supported authentication activity to techniques including:

- **T1110 — Brute Force**
- **T1078 — Valid Accounts**

Mappings are evidence-driven rather than assigned solely because an IP address or username exists.

## Confidence Assessment

Each investigation contains a confidence assessment consisting of:

- numerical score
- confidence level
- supporting reasons

This separates the severity of an alert from confidence in the available evidence.

## Investigation History

Completed investigations are persisted locally as JSON reports.

The application supports:

- listing saved investigations
- loading an investigation by report ID
- validating report IDs before file access
- rejecting malformed or path-traversal-style report identifiers

Runtime investigation data is excluded from the Git repository.

## PDF Reports

The application can generate a PDF from a stored `InvestigationReport`.

The v1.0 PDF contains investigation information such as:

- report ID
- case status
- severity
- confidence
- MITRE ATT&CK techniques
- security findings
- recommended analyst actions
- analyst narrative
- AI-assisted analyst explanation

Advanced PDF styling and layout improvements are reserved for future versions.

## Running Locally

### Requirements

Install a current stable Rust toolchain.

Confirm Rust and Cargo are available:

```bash
rustc --version
cargo --version
```

### Local AI Requirements

v1.0 uses Ollama with Llama 3.2 for local AI-assisted analysis.

After installing Ollama, verify it:

```bash
ollama --version

### Clone and Build

```bash
git clone <repository-url>
cd zyguor-ai-soc-assistant
cargo build
```

### Run

```bash
cargo run
```

The development server runs on:

```text
http://127.0.0.1:3000
```

Open that address in a browser to use the application.

## Quality Assurance

Before release, the project is checked with:

```bash
cargo fmt --check
cargo check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

These checks cover formatting, compilation, automated tests, and strict linting.

## Security Considerations

The v1.0 application includes defensive handling for stored investigation reports.

Report IDs must follow the expected format:

```text
SOC-<numeric-id>
```

Invalid identifiers and path-traversal-style inputs are rejected before filesystem access.

Generated investigations and PDF exports are also excluded from source control.

## v1.0 Scope

Version 1.0 concentrates on:

- reliable alert processing
- explainable rules
- structured SOC triage
- persistent investigation reports
- security-conscious file access
- investigation history
- report export
- testing and QA

Advanced UI improvements and other larger enhancements are intentionally deferred to later releases.

## Disclaimer

Zyguor AI SOC Assistant is intended to support security analysis and SOC workflows. It should not replace qualified human investigation, organizational security procedures, or professional incident-response judgment.

## Author

**Muhammad Nadim**

Full-Stack Engineer (Rust) | Cybersecurity Engineer

## Product

**Zyguor AI SOC Assistant**

Secure. Smart. Scalable.
