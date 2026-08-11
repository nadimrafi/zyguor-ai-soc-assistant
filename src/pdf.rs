use crate::pdf_builder::build_cover_page;

use printpdf::{PdfDocument, PdfSaveOptions};

use std::fs::File;
use std::io::{BufWriter, Write};

pub fn generate_investigation_pdf(
    _report: &crate::models::InvestigationReport,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut document = PdfDocument::new("Zyguor SOC Investigation Report");

    let page = build_cover_page();

    document.with_pages(vec![page]);

    let mut warnings = Vec::new();

    let bytes = document.save(&PdfSaveOptions::default(), &mut warnings);

    let file = File::create(output_path)?;

    let mut writer = BufWriter::new(file);

    writer.write_all(&bytes)?;

    Ok(())
}
