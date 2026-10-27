use regex::{Regex, RegexBuilder};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

use crate::ingestion::parsers::ParsedSegment;

static DOCUMENT_INJECTION_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        RegexBuilder::new(r"ignore\s+(all\s+)?(previous|prior|system)\s+instructions")
            .case_insensitive(true)
            .build()
            .unwrap(),
        RegexBuilder::new(r"abaikan\s+(semua\s+)?instruksi\s+(sebelumnya|sistem)")
            .case_insensitive(true)
            .build()
            .unwrap(),
        RegexBuilder::new(r"system\s*prompt\s*override")
            .case_insensitive(true)
            .build()
            .unwrap(),
        RegexBuilder::new(r"grant\s+admin\s+access")
            .case_insensitive(true)
            .build()
            .unwrap(),
        RegexBuilder::new(r"berikan\s+akses\s+role")
            .case_insensitive(true)
            .build()
            .unwrap(),
        RegexBuilder::new(r"execute\s+(sql|shell|bash|cmd|tool)")
            .case_insensitive(true)
            .build()
            .unwrap(),
    ]
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkCandidate {
    pub chunk_index: i64,
    pub text_content: String,
    pub content_sha256: String,
    pub page_number: Option<i64>,
    pub sheet_name: Option<String>,
    pub row_start: Option<i64>,
    pub row_end: Option<i64>,
    pub section_label: Option<String>,
    pub has_potential_injection: bool,
}

pub fn clean_document_text(raw_text: &str) -> String {
    let without_nulls = raw_text.replace('\x00', "");
    let whitespace_re = Regex::new(r"[ \t]+").unwrap();

    let lines: Vec<String> = without_nulls
        .lines()
        .map(|line| whitespace_re.replace_all(line, " ").trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();

    lines.join("\n")
}

pub fn detect_document_prompt_injection(text: &str) -> bool {
    DOCUMENT_INJECTION_PATTERNS.iter().any(|p| p.is_match(text))
}

fn compute_sha256(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn chunk_parsed_segments(
    segments: &[ParsedSegment],
    chunk_size_chars: usize,
    chunk_overlap_chars: usize,
) -> Result<Vec<ChunkCandidate>, &'static str> {
    if chunk_size_chars <= 50 {
        return Err("chunk_size_chars must be > 50");
    }
    if chunk_overlap_chars >= chunk_size_chars {
        return Err("chunk_overlap_chars must be < chunk_size_chars");
    }

    let mut chunks = Vec::new();
    let mut global_idx = 0i64;
    let step = chunk_size_chars - chunk_overlap_chars;

    for seg in segments {
        let cleaned = clean_document_text(&seg.text);
        if cleaned.is_empty() {
            continue;
        }

        let char_count = cleaned.chars().count();
        if char_count <= chunk_size_chars {
            let sha = compute_sha256(&cleaned);
            chunks.push(ChunkCandidate {
                chunk_index: global_idx,
                text_content: cleaned.clone(),
                content_sha256: sha,
                page_number: seg.page_number,
                sheet_name: seg.sheet_name.clone(),
                row_start: seg.row_start,
                row_end: seg.row_end,
                section_label: seg.section_label.clone(),
                has_potential_injection: detect_document_prompt_injection(&cleaned),
            });
            global_idx += 1;
        } else {
            let chars: Vec<char> = cleaned.chars().collect();
            let mut start = 0;
            while start < chars.len() {
                let end = (start + chunk_size_chars).min(chars.len());
                let slice_text: String = chars[start..end].iter().collect();
                let trimmed = slice_text.trim().to_string();

                if !trimmed.is_empty() {
                    let sha = compute_sha256(&trimmed);
                    chunks.push(ChunkCandidate {
                        chunk_index: global_idx,
                        text_content: trimmed.clone(),
                        content_sha256: sha,
                        page_number: seg.page_number,
                        sheet_name: seg.sheet_name.clone(),
                        row_start: seg.row_start,
                        row_end: seg.row_end,
                        section_label: seg.section_label.clone(),
                        has_potential_injection: detect_document_prompt_injection(&trimmed),
                    });
                    global_idx += 1;
                }

                if start + chunk_size_chars >= chars.len() {
                    break;
                }
                start += step;
            }
        }
    }

    Ok(chunks)
}
