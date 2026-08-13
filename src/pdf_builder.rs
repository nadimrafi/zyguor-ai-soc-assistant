use crate::models::InvestigationReport;

use printpdf::{BuiltinFont, Mm, Op, PdfFontHandle, PdfPage, Point, Pt, TextItem};

const PAGE_WIDTH: f32 = 210.0;
const PAGE_HEIGHT: f32 = 297.0;

const LEFT_MARGIN: f32 = 25.0;
const TOP_Y: f32 = 275.0;
const BOTTOM_Y: f32 = 20.0;

const BODY_FONT_SIZE: f32 = 9.0;
const LINE_HEIGHT: f32 = 6.0;
const MAX_LINE_CHARS: usize = 88;

pub fn build_report_pages(report: &InvestigationReport) -> Vec<PdfPage> {
    let mut builder = PageBuilder::new();

    builder.add_text("ZYGUOR", 24.0, BuiltinFont::HelveticaBold);

    builder.move_down(6.0);

    builder.add_text("AI SOC Assistant", 12.0, BuiltinFont::Helvetica);

    builder.move_down(10.0);

    builder.add_text(
        "Security Investigation Report",
        18.0,
        BuiltinFont::HelveticaBold,
    );

    builder.move_down(12.0);

    builder.add_text(
        &format!("Report ID: {}", report.report_id),
        11.0,
        BuiltinFont::Helvetica,
    );

    builder.add_text(
        &format!("Status: {}", report.case_status),
        11.0,
        BuiltinFont::Helvetica,
    );

    builder.add_text(
        &format!("Severity: {}", report.severity),
        11.0,
        BuiltinFont::HelveticaBold,
    );

    builder.add_text(
        &format!(
            "Confidence: {} ({}%)",
            report.confidence.level, report.confidence.score
        ),
        11.0,
        BuiltinFont::Helvetica,
    );

    builder.move_down(8.0);

    builder.add_heading("MITRE ATT&CK");

    if report.mitre.is_empty() {
        builder.add_wrapped_text("No MITRE ATT&CK techniques mapped.");
    } else {
        for technique in &report.mitre {
            builder.add_wrapped_text(&format!(
                "{} - {}",
                technique.technique_id, technique.technique_name
            ));
        }
    }

    builder.move_down(4.0);
    builder.add_heading("Security Findings");

    for fact in &report.knowledge {
        builder.add_wrapped_text(&format!("{}: {}", fact.title, fact.description));

        builder.move_down(2.0);
    }

    builder.move_down(3.0);
    builder.add_heading("Recommended Analyst Actions");

    for recommendation in &report.recommendations {
        builder.add_wrapped_text(&format!(
            "[{}] {}",
            recommendation.priority, recommendation.action
        ));

        builder.move_down(2.0);
    }

    builder.move_down(3.0);
    builder.add_heading("Analyst Narrative");

    builder.add_wrapped_text(&report.narrative);

    builder.move_down(5.0);

    builder.add_heading("AI-Assisted Analyst Explanation");

    let ai_text = report.ai_analysis.as_deref().unwrap_or(
        "AI analysis unavailable. \
Deterministic Rust analysis remains valid.",
    );

    let cleaned_ai_text = clean_ai_text(ai_text);

    builder.add_wrapped_text(&cleaned_ai_text);

    builder.finish()
}

struct PageBuilder {
    pages: Vec<PdfPage>,
    operations: Vec<Op>,
    y: f32,
}

impl PageBuilder {
    fn new() -> Self {
        Self {
            pages: Vec::new(),
            operations: Vec::new(),
            y: TOP_Y,
        }
    }

    fn add_heading(&mut self, text: &str) {
        self.ensure_space(12.0);

        self.add_text(text, 13.0, BuiltinFont::HelveticaBold);

        self.move_down(4.0);
    }

    fn add_text(&mut self, text: &str, size_pt: f32, font: BuiltinFont) {
        self.ensure_space(LINE_HEIGHT);

        push_text(
            &mut self.operations,
            text,
            LEFT_MARGIN,
            self.y,
            size_pt,
            font,
        );

        self.y -= LINE_HEIGHT;
    }

    fn add_wrapped_text(&mut self, text: &str) {
        for paragraph in text.lines() {
            if paragraph.trim().is_empty() {
                self.move_down(LINE_HEIGHT);
                continue;
            }

            for line in wrap_text(paragraph, MAX_LINE_CHARS) {
                self.ensure_space(LINE_HEIGHT);

                push_text(
                    &mut self.operations,
                    &line,
                    LEFT_MARGIN,
                    self.y,
                    BODY_FONT_SIZE,
                    BuiltinFont::Helvetica,
                );

                self.y -= LINE_HEIGHT;
            }
        }
    }

    fn move_down(&mut self, amount: f32) {
        self.ensure_space(amount);
        self.y -= amount;
    }

    fn ensure_space(&mut self, required: f32) {
        if self.y - required < BOTTOM_Y {
            self.finish_current_page();
            self.start_continuation_page();
        }
    }

    fn finish_current_page(&mut self) {
        if self.operations.is_empty() {
            return;
        }

        let operations = std::mem::take(&mut self.operations);

        self.pages
            .push(PdfPage::new(Mm(PAGE_WIDTH), Mm(PAGE_HEIGHT), operations));
    }

    fn start_continuation_page(&mut self) {
        self.y = TOP_Y;

        push_text(
            &mut self.operations,
            "ZYGUOR",
            LEFT_MARGIN,
            self.y,
            16.0,
            BuiltinFont::HelveticaBold,
        );

        self.y -= 9.0;

        push_text(
            &mut self.operations,
            "Security Investigation Report - Continued",
            LEFT_MARGIN,
            self.y,
            11.0,
            BuiltinFont::Helvetica,
        );

        self.y -= 12.0;
    }

    fn finish(mut self) -> Vec<PdfPage> {
        self.finish_current_page();

        self.pages
    }
}

fn clean_ai_text(text: &str) -> String {
    text.replace("**", "").replace("* ", "- ").replace('\r', "")
}

fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        let additional_length = if current_line.is_empty() {
            word.len()
        } else {
            word.len() + 1
        };

        if current_line.len() + additional_length > max_chars {
            if !current_line.is_empty() {
                lines.push(current_line);
            }

            current_line = word.to_string();
        } else {
            if !current_line.is_empty() {
                current_line.push(' ');
            }

            current_line.push_str(word);
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    lines
}

fn push_text(
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
