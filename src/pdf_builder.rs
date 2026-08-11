use printpdf::{BuiltinFont, Mm, Op, PdfFontHandle, PdfPage, Point, Pt, TextItem};

pub fn build_cover_page() -> PdfPage {
    let operations = vec![
        Op::StartTextSection,
        // ZYGUOR
        Op::SetTextCursor {
            pos: Point::new(Mm(25.0), Mm(265.0)),
        },
        Op::SetFont {
            font: PdfFontHandle::Builtin(BuiltinFont::HelveticaBold),
            size: Pt(26.0),
        },
        Op::ShowText {
            items: vec![TextItem::Text("ZYGUOR".to_string())],
        },
        // Product name
        Op::SetTextCursor {
            pos: Point::new(Mm(25.0), Mm(250.0)),
        },
        Op::SetFont {
            font: PdfFontHandle::Builtin(BuiltinFont::Helvetica),
            size: Pt(14.0),
        },
        Op::ShowText {
            items: vec![TextItem::Text("AI SOC Assistant".to_string())],
        },
        // Report title
        Op::SetTextCursor {
            pos: Point::new(Mm(25.0), Mm(225.0)),
        },
        Op::SetFont {
            font: PdfFontHandle::Builtin(BuiltinFont::HelveticaBold),
            size: Pt(22.0),
        },
        Op::ShowText {
            items: vec![TextItem::Text("Security Investigation Report".to_string())],
        },
        // Subtitle
        Op::SetTextCursor {
            pos: Point::new(Mm(25.0), Mm(210.0)),
        },
        Op::SetFont {
            font: PdfFontHandle::Builtin(BuiltinFont::Helvetica),
            size: Pt(11.0),
        },
        Op::ShowText {
            items: vec![TextItem::Text(
                "Structured SOC investigation and analyst guidance".to_string(),
            )],
        },
        Op::EndTextSection,
    ];

    PdfPage::new(Mm(210.0), Mm(297.0), operations)
}
