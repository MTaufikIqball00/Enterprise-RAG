use std::io::{Cursor, Read};
use std::path::Path;
use calamine::{Data, Reader, Xlsx};
use thiserror::Error;

use crate::core::enums::SupportedFileType;

#[derive(Debug, Error)]
pub enum DocumentParseError {
    #[error("Nama file harus memiliki ekstensi yang valid (.pdf, .docx, .xlsx, .csv).")]
    InvalidFilename,

    #[error("File kosong (0 byte) tidak dapat diproses.")]
    EmptyFile,

    #[error("Ukuran file ({0} byte) melebihi batas maksimum ({1} byte).")]
    FileTooLarge(usize, usize),

    #[error("Format file '.{0}' tidak didukung. Format yang didukung: PDF, DOCX, XLSX, CSV.")]
    UnsupportedFormat(String),

    #[error("File PDF rusak atau header bukan '%PDF-' yang valid.")]
    InvalidPdfMagic,

    #[error("File {0} rusak (bukan arsip OpenXML/ZIP yang valid).")]
    InvalidZipMagic(String),

    #[error("Gagal membaca struktur PDF (file rusak): {0}")]
    PdfCorrupt(String),

    #[error("Dokumen PDF tidak memiliki halaman.")]
    PdfNoPages,

    #[error("PDF tidak mengandung lapisan teks digital (kemungkinan hasil scan gambar). Engine OCR belum diaktifkan pada environment ini.")]
    PdfScannedOnly,

    #[error("Gagal membaca file DOCX (file rusak): {0}")]
    DocxCorrupt(String),

    #[error("Dokumen DOCX tidak memiliki teks atau tabel yang dapat diekstrak.")]
    DocxEmpty,

    #[error("Gagal membaca file XLSX (file rusak): {0}")]
    XlsxCorrupt(String),

    #[error("File XLSX tidak memiliki data pada sheet mana pun.")]
    XlsxEmpty,

    #[error("Encoding CSV tidak dapat dibaca: {0}")]
    CsvEncodingError(String),

    #[error("Format CSV rusak: {0}")]
    CsvCorrupt(String),

    #[error("File CSV tidak memiliki baris data.")]
    CsvEmpty,

    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSegment {
    pub text: String,
    pub page_number: Option<i64>,
    pub sheet_name: Option<String>,
    pub row_start: Option<i64>,
    pub row_end: Option<i64>,
    pub section_label: Option<String>,
}

pub fn detect_and_validate_file_type(
    filename: &str,
    raw_bytes: &[u8],
    max_size_bytes: usize,
) -> Result<SupportedFileType, DocumentParseError> {
    if filename.is_empty() || !filename.contains('.') {
        return Err(DocumentParseError::InvalidFilename);
    }
    if raw_bytes.is_empty() {
        return Err(DocumentParseError::EmptyFile);
    }
    if raw_bytes.len() > max_size_bytes {
        return Err(DocumentParseError::FileTooLarge(raw_bytes.len(), max_size_bytes));
    }

    let ext = Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    let file_type = match ext.as_str() {
        "pdf" => SupportedFileType::Pdf,
        "docx" => SupportedFileType::Docx,
        "xlsx" => SupportedFileType::Xlsx,
        "csv" => SupportedFileType::Csv,
        other => return Err(DocumentParseError::UnsupportedFormat(other.to_string())),
    };

    if file_type == SupportedFileType::Pdf && !raw_bytes.starts_with(b"%PDF-") {
        return Err(DocumentParseError::InvalidPdfMagic);
    }

    if (file_type == SupportedFileType::Docx || file_type == SupportedFileType::Xlsx)
        && !raw_bytes.starts_with(b"PK\x03\x04")
    {
        return Err(DocumentParseError::InvalidZipMagic(file_type.as_str().to_uppercase()));
    }

    Ok(file_type)
}

pub fn parse_csv_bytes(raw_bytes: &[u8], rows_per_segment: usize) -> Result<Vec<ParsedSegment>, DocumentParseError> {
    let decoded = match std::str::from_utf8(raw_bytes) {
        Ok(s) => s.trim_start_matches('\u{feff}').to_string(),
        Err(_) => raw_bytes.iter().map(|&b| b as char).collect::<String>(),
    };

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(decoded.as_bytes());

    let mut all_rows: Vec<(usize, Vec<String>)> = Vec::new();
    let mut line_idx = 1;

    for result in rdr.records() {
        let record = result.map_err(|e| DocumentParseError::CsvCorrupt(e.to_string()))?;
        let row_vals: Vec<String> = record.iter().map(|s| s.trim().to_string()).collect();
        if row_vals.iter().any(|s| !s.is_empty()) {
            all_rows.push((line_idx, row_vals));
        }
        line_idx += 1;
    }

    if all_rows.is_empty() {
        return Err(DocumentParseError::CsvEmpty);
    }

    let (header_idx, raw_headers) = &all_rows[0];
    let headers: Vec<String> = raw_headers
        .iter()
        .enumerate()
        .map(|(i, h)| if !h.is_empty() { h.clone() } else { format!("Column_{}", i + 1) })
        .collect();

    let data_rows = &all_rows[1..];
    if data_rows.is_empty() {
        return Ok(vec![ParsedSegment {
            text: format!("[CSV | Header: {}]", headers.join(", ")),
            page_number: None,
            sheet_name: Some("CSV".to_string()),
            row_start: Some(*header_idx as i64),
            row_end: Some(*header_idx as i64),
            section_label: Some("CSV Header".to_string()),
        }]);
    }

    let mut segments = Vec::new();
    let step = if rows_per_segment == 0 { 20 } else { rows_per_segment };

    for chunk in data_rows.chunks(step) {
        let row_start_num = chunk[0].0 as i64;
        let row_end_num = chunk.last().unwrap().0 as i64;

        let mut lines = vec![format!(
            "[CSV | Kolom Header: {} | Baris {}-{}]",
            headers.join(" | "),
            row_start_num,
            row_end_num
        )];

        for (r_num, row_vals) in chunk {
            let mut pairs = Vec::new();
            for (i, val) in row_vals.iter().enumerate() {
                if !val.is_empty() {
                    let col_name = if i < headers.len() { &headers[i] } else { &format!("Column_{}", i + 1) };
                    pairs.push(format!("{}={}", col_name, val));
                }
            }
            if !pairs.is_empty() {
                lines.push(format!("CSV Baris {}: {}", r_num, pairs.join("; ")));
            }
        }

        segments.push(ParsedSegment {
            text: lines.join("\n"),
            page_number: None,
            sheet_name: Some("CSV".to_string()),
            row_start: Some(row_start_num),
            row_end: Some(row_end_num),
            section_label: Some(format!("CSV Rows {}-{}", row_start_num, row_end_num)),
        });
    }

    Ok(segments)
}

fn infer_value_type(val: &Data) -> &'static str {
    match val {
        Data::Empty => "null",
        Data::String(_) => "string",
        Data::Float(_) => "float",
        Data::Int(_) => "integer",
        Data::Bool(_) => "boolean",
        Data::DateTime(_) => "datetime",
        Data::DateTimeIso(_) => "datetime",
        Data::DurationIso(_) => "duration",
        Data::Error(_) => "error",
    }
}

pub fn parse_xlsx_bytes(raw_bytes: &[u8], rows_per_segment: usize) -> Result<Vec<ParsedSegment>, DocumentParseError> {
    let cursor = Cursor::new(raw_bytes);
    let mut workbook: Xlsx<_> = Xlsx::new(cursor)
        .map_err(|e| DocumentParseError::XlsxCorrupt(e.to_string()))?;

    let sheet_names = workbook.sheet_names().to_vec();
    let mut segments = Vec::new();

    for sheet_name in sheet_names {
        if let Ok(range) = workbook.worksheet_range(&sheet_name) {
            let mut non_empty_rows: Vec<(usize, Vec<Data>)> = Vec::new();
            for (r_idx, row) in range.rows().enumerate() {
                if row.iter().any(|c| !matches!(c, Data::Empty)) {
                    non_empty_rows.push((r_idx + 1, row.to_vec()));
                }
            }

            if non_empty_rows.is_empty() {
                continue;
            }

            let (header_row_idx, raw_headers) = &non_empty_rows[0];
            let headers: Vec<String> = raw_headers
                .iter()
                .enumerate()
                .map(|(i, h)| {
                    let s = h.to_string().trim().to_string();
                    if !s.is_empty() { s } else { format!("Column_{}", i + 1) }
                })
                .collect();

            let data_rows = &non_empty_rows[1..];
            if data_rows.is_empty() {
                segments.push(ParsedSegment {
                    text: format!("[Sheet: {} | Header: {}]", sheet_name, headers.join(", ")),
                    page_number: None,
                    sheet_name: Some(sheet_name.clone()),
                    row_start: Some(*header_row_idx as i64),
                    row_end: Some(*header_row_idx as i64),
                    section_label: Some(format!("Sheet {}", sheet_name)),
                });
                continue;
            }

            let step = if rows_per_segment == 0 { 15 } else { rows_per_segment };
            for chunk in data_rows.chunks(step) {
                let row_start_num = chunk[0].0 as i64;
                let row_end_num = chunk.last().unwrap().0 as i64;

                let mut lines = vec![format!(
                    "[Sheet: {} | Kolom Header: {} | Baris {}-{}]",
                    sheet_name,
                    headers.join(" | "),
                    row_start_num,
                    row_end_num
                )];

                for (excel_row_num, row_tuple) in chunk {
                    let mut col_descriptions = Vec::new();
                    for (col_idx, cell_val) in row_tuple.iter().enumerate() {
                        if matches!(cell_val, Data::Empty) {
                            continue;
                        }
                        let col_name = if col_idx < headers.len() { &headers[col_idx] } else { &format!("Column_{}", col_idx + 1) };
                        let val_type = infer_value_type(cell_val);
                        col_descriptions.push(format!("{}={} ({})", col_name, cell_val, val_type));
                    }
                    if !col_descriptions.is_empty() {
                        lines.push(format!(
                            "Sheet '{}' Baris {}: {}",
                            sheet_name,
                            excel_row_num,
                            col_descriptions.join("; ")
                        ));
                    }
                }

                segments.push(ParsedSegment {
                    text: lines.join("\n"),
                    page_number: None,
                    sheet_name: Some(sheet_name.clone()),
                    row_start: Some(row_start_num),
                    row_end: Some(row_end_num),
                    section_label: Some(format!("Sheet {} (Rows {}-{})", sheet_name, row_start_num, row_end_num)),
                });
            }
        }
    }

    if segments.is_empty() {
        return Err(DocumentParseError::XlsxEmpty);
    }

    Ok(segments)
}

pub fn parse_docx_bytes(raw_bytes: &[u8]) -> Result<Vec<ParsedSegment>, DocumentParseError> {
    let cursor = Cursor::new(raw_bytes);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| DocumentParseError::DocxCorrupt(e.to_string()))?;

    let mut doc_xml = String::new();
    {
        let mut file = archive
            .by_name("word/document.xml")
            .map_err(|e| DocumentParseError::DocxCorrupt(format!("document.xml not found: {}", e)))?;
        file.read_to_string(&mut doc_xml)
            .map_err(|e| DocumentParseError::DocxCorrupt(e.to_string()))?;
    }

    // Extract text from XML nodes: <w:p> paragraphs and <w:tbl> tables
    let mut segments = Vec::new();
    let mut current_section = "Document Body".to_string();
    let mut para_buffer = Vec::new();
    let mut para_group_idx = 1;

    let mut reader = quick_xml::Reader::from_str(&doc_xml);
    reader.config_mut().trim_text(true);

    let mut in_t = false;
    let mut is_heading = false;
    let mut p_text = String::new();

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e)) => {
                let name = e.name();
                if name.as_ref() == b"w:p" {
                    p_text.clear();
                    is_heading = false;
                } else if name.as_ref() == b"w:t" {
                    in_t = true;
                } else if name.as_ref() == b"w:pStyle" {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"w:val" {
                            let val = String::from_utf8_lossy(&attr.value).to_lowercase();
                            if val.starts_with("heading") {
                                is_heading = true;
                            }
                        }
                    }
                }
            }
            Ok(quick_xml::events::Event::Text(ref e)) => {
                if in_t {
                    if let Ok(txt) = e.unescape() {
                        p_text.push_str(&txt);
                    }
                }
            }
            Ok(quick_xml::events::Event::End(ref e)) => {
                let name = e.name();
                if name.as_ref() == b"w:t" {
                    in_t = false;
                } else if name.as_ref() == b"w:p" {
                    let trimmed = p_text.trim().to_string();
                    if !trimmed.is_empty() {
                        if is_heading {
                            if !para_buffer.is_empty() {
                                segments.push(ParsedSegment {
                                    text: para_buffer.join("\n"),
                                    page_number: None,
                                    sheet_name: None,
                                    row_start: None,
                                    row_end: None,
                                    section_label: Some(format!("{} (Part {})", current_section, para_group_idx)),
                                });
                                para_buffer.clear();
                                para_group_idx += 1;
                            }
                            current_section = trimmed.clone();
                        }
                        para_buffer.push(trimmed);
                    }
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => return Err(DocumentParseError::DocxCorrupt(e.to_string())),
            _ => {}
        }
        buf.clear();
    }

    if !para_buffer.is_empty() {
        segments.push(ParsedSegment {
            text: para_buffer.join("\n"),
            page_number: None,
            sheet_name: None,
            row_start: None,
            row_end: None,
            section_label: Some(format!("{} (Part {})", current_section, para_group_idx)),
        });
    }

    if segments.is_empty() {
        return Err(DocumentParseError::DocxEmpty);
    }

    Ok(segments)
}

pub fn parse_pdf_bytes(raw_bytes: &[u8]) -> Result<Vec<ParsedSegment>, DocumentParseError> {
    let doc = lopdf::Document::load_mem(raw_bytes)
        .map_err(|e| DocumentParseError::PdfCorrupt(e.to_string()))?;

    let pages = doc.get_pages();
    if pages.is_empty() {
        return Err(DocumentParseError::PdfNoPages);
    }

    let mut segments = Vec::new();

    for (page_num, _page_id) in pages {
        let page_num = page_num as i64;
        let text = doc.extract_text(&[page_num as u32]).unwrap_or_default();
        let trimmed = text.trim().to_string();
        if !trimmed.is_empty() {
            segments.push(ParsedSegment {
                text: trimmed,
                page_number: Some(page_num),
                sheet_name: None,
                row_start: None,
                row_end: None,
                section_label: Some(format!("Page {}", page_num)),
            });
        }
    }

    if segments.is_empty() {
        return Err(DocumentParseError::PdfScannedOnly);
    }

    Ok(segments)
}

pub fn parse_document_bytes(
    filename: &str,
    raw_bytes: &[u8],
    max_size_bytes: usize,
) -> Result<(SupportedFileType, Vec<ParsedSegment>), DocumentParseError> {
    let file_type = detect_and_validate_file_type(filename, raw_bytes, max_size_bytes)?;
    let segments = match file_type {
        SupportedFileType::Pdf => parse_pdf_bytes(raw_bytes)?,
        SupportedFileType::Docx => parse_docx_bytes(raw_bytes)?,
        SupportedFileType::Xlsx => parse_xlsx_bytes(raw_bytes, 15)?,
        SupportedFileType::Csv => parse_csv_bytes(raw_bytes, 20)?,
    };
    Ok((file_type, segments))
}
