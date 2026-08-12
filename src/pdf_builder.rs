use crate::models::InvestigationReport;

use printpdf::{BuiltinFont, Mm, Op, PdfFontHandle, PdfPage, Point, Pt, TextItem};

pub fn build_report_page(report: &InvestigationReport) -> PdfPage {
    let mut operations = Vec::new();

    add_text(
        &mut operations,
        "ZYGUOR",
        25.0,
        275.0,
        24.0,
        BuiltinFont::HelveticaBold,
    );

    add_text(
        &mut operations,
        "AI SOC Assistant",
        25.0,
        263.0,
        12.0,
        BuiltinFont::Helvetica,
    );

    add_text(
        &mut operations,
        "Security Investigation Report",
        25.0,
        245.0,
        18.0,
        BuiltinFont::HelveticaBold,
    );

    add_text(
        &mut operations,
        &format!("Report ID: {}", report.report_id),
        25.0,
        225.0,
        11.0,
        BuiltinFont::Helvetica,
    );

    add_text(
        &mut operations,
        &format!("Status: {}", report.case_status),
        25.0,
        216.0,
        11.0,
        BuiltinFont::Helvetica,
    );

    add_text(
        &mut operations,
        &format!("Severity: {}", report.severity),
        25.0,
        207.0,
        11.0,
        BuiltinFont::HelveticaBold,
    );

    add_text(
        &mut operations,
        &format!(
            "Confidence: {} ({}%)",
            report.confidence.level, report.confidence.score
        ),
        25.0,
        198.0,
        11.0,
        BuiltinFont::Helvetica,
    );

    add_text(
        &mut operations,
        "MITRE ATT&CK",
        25.0,
        180.0,
        13.0,
        BuiltinFont::HelveticaBold,
    );

    let mut y = 170.0;

    if report.mitre.is_empty() {
        add_text(
            &mut operations,
            "No MITRE ATT&CK techniques mapped.",
            25.0,
            y,
            10.0,
            BuiltinFont::Helvetica,
        );

        y -= 9.0;
    } else {
        for technique in &report.mitre {
            add_text(
                &mut operations,
                &format!("{} - {}", technique.technique_id, technique.technique_name),
                25.0,
                y,
                10.0,
                BuiltinFont::Helvetica,
            );

            y -= 9.0;
        }
    }

    y -= 5.0;

    add_text(
        &mut operations,
        "Security Findings",
        25.0,
        y,
        13.0,
        BuiltinFont::HelveticaBold,
    );

    y -= 11.0;

    for fact in &report.knowledge {
        add_text(
            &mut operations,
            &format!("{}: {}", fact.title, fact.description),
            25.0,
            y,
            9.0,
            BuiltinFont::Helvetica,
        );

        y -= 9.0;
    }

    y -= 5.0;

    add_text(
        &mut operations,
        "Recommended Analyst Actions",
        25.0,
        y,
        13.0,
        BuiltinFont::HelveticaBold,
    );

    y -= 11.0;

    for recommendation in &report.recommendations {
        add_text(
            &mut operations,
            &format!("[{}] {}", recommendation.priority, recommendation.action),
            25.0,
            y,
            9.0,
            BuiltinFont::Helvetica,
        );

        y -= 9.0;
    }

    y -= 5.0;

    add_text(
        &mut operations,
        "Analyst Narrative",
        25.0,
        y,
        13.0,
        BuiltinFont::HelveticaBold,
    );

    y -= 11.0;

    add_text(
        &mut operations,
        &report.narrative,
        25.0,
        y,
        9.0,
        BuiltinFont::Helvetica,
    );

    PdfPage::new(Mm(210.0), Mm(297.0), operations)
}

fn add_text(
    operations: &mut Vec<Op>,
    text: &str,
    x_mm: f32,
    y_mm: f32,
    size_pt: f32,
    font: BuiltinFont,
) {
    operations.push(Op::StartTextSection);

    operations.push(Op::SetTextCursor {
        pos: Point::new(Mm(x_mm), Mm(y_mm)),
    });

    operations.push(Op::SetFont {
        font: PdfFontHandle::Builtin(font),
        size: Pt(size_pt),
    });

    operations.push(Op::ShowText {
        items: vec![TextItem::Text(text.to_string())],
    });

    operations.push(Op::EndTextSection);
}
