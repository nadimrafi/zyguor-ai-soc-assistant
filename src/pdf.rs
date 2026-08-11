use crate::pdf_builder::build_cover_page;

use printpdf::{PdfDocument, PdfSaveOptions};

use std::fs::File;
use std::io::{BufWriter, Write};

pub fn create_sample_pdf() -> Result<(), Box<dyn std::error::Error>> {
    let mut document = PdfDocument::new("Zyguor SOC Investigation Report");

    let page = build_cover_page();

    document.with_pages(vec![page]);

    let mut warnings = Vec::new();

    let bytes = document.save(&PdfSaveOptions::default(), &mut warnings);

    let file = File::create("sample-report.pdf")?;

    let mut writer = BufWriter::new(file);

    writer.write_all(&bytes)?;

    Ok(())
}
