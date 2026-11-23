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

static WHITESPACE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[ \t]+").unwrap());

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

    let lines: Vec<String> = without_nulls
        .lines()
        .map(|line| WHITESPACE_RE.replace_all(line, " ").trim().to_string())
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

fn is_tabular_header_line(line: &str) -> bool {
    (line.starts_with("[CSV |") || line.starts_with("[Sheet:") || line.starts_with("[DOCX Tabel "))
        && line.contains("Kolom Header:")
}

/// Find the best split boundary within `chars[start..max_end]` preferring newline,
/// then sentence termination (`. `, `? `, `! `), then whitespace — never splitting
/// mid-word or mid-number unless a single contiguous token exceeds the window.
fn find_smart_end(chars: &[char], start: usize, max_end: usize) -> usize {
    if max_end >= chars.len() {
        return chars.len();
    }
    let window_len = max_end - start;
    let min_prefer = start + (window_len / 2);

    // 1. Prefer newline in the second half
    for i in (min_prefer..max_end).rev() {
        if chars[i] == '\n' {
            return i + 1;
        }
    }

    // 2. Prefer sentence boundary in the second half
    for i in (min_prefer..max_end).rev() {
        if matches!(chars[i], '.' | '?' | '!') && i + 1 < max_end && chars[i + 1].is_whitespace() {
            return i + 1;
        }
    }

    // 3. Prefer any whitespace boundary so we never cut a word or number in half
    for i in ((start + 1)..max_end).rev() {
        if chars[i].is_whitespace() {
            return i;
        }
    }

    // Fallback: single unbreakable token longer than chunk_size_chars
    max_end
}

/// Find a clean overlap start index <= `end` that begins on a line/word boundary.
fn find_smart_overlap_start(
    chars: &[char],
    prev_start: usize,
    end: usize,
    overlap: usize,
) -> usize {
    if overlap == 0 || end >= chars.len() {
        return end;
    }
    let raw_next = end.saturating_sub(overlap);
    if raw_next <= prev_start {
        return end;
    }

    // Snap forward to the start of the next line or word so we never start mid-word
    let mut candidate = raw_next;
    if candidate > 0 && !chars[candidate - 1].is_whitespace() {
        while candidate < end && !chars[candidate].is_whitespace() {
            candidate += 1;
        }
        while candidate < end && chars[candidate].is_whitespace() {
            candidate += 1;
        }
    }

    if candidate >= end || candidate <= prev_start {
        end
    } else {
        candidate
    }
}

fn split_prose_smart(text: &str, max_chars: usize, overlap_chars: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max_chars {
        return vec![text.to_string()];
    }

    let mut out = Vec::new();
    let mut start = 0usize;

    while start < chars.len() {
        while start < chars.len() && chars[start].is_whitespace() {
            start += 1;
        }
        if start >= chars.len() {
            break;
        }

        let max_end = (start + max_chars).min(chars.len());
        let end = find_smart_end(&chars, start, max_end);
        let piece: String = chars[start..end].iter().collect();
        let trimmed = piece.trim().to_string();
        if !trimmed.is_empty() {
            out.push(trimmed);
        }

        if end >= chars.len() {
            break;
        }

        let next_start = find_smart_overlap_start(&chars, start, end, overlap_chars);
        start = if next_start <= start { end } else { next_start };
    }

    out
}

/// Split tabular segments by row boundaries while prepending the table header line
/// to every continuation chunk so column context is always preserved.
fn split_tabular_with_header(
    header_line: &str,
    data_lines: &[&str],
    chunk_size_chars: usize,
    chunk_overlap_chars: usize,
) -> Vec<String> {
    let header_len = header_line.chars().count() + 1;
    let body_budget = chunk_size_chars.saturating_sub(header_len).max(60);

    let mut chunks = Vec::new();
    let mut current_rows: Vec<String> = Vec::new();
    let mut current_len = 0usize;

    for &row in data_lines {
        let row_len = row.chars().count() + 1;

        if row_len > body_budget {
            // Flush existing buffer first
            if !current_rows.is_empty() {
                chunks.push(format!("{}\n{}", header_line, current_rows.join("\n")));
                current_rows.clear();
                current_len = 0;
            }
            // Split oversized single row on word boundaries and prepend header
            for sub in split_prose_smart(row, body_budget, chunk_overlap_chars.min(body_budget / 2))
            {
                chunks.push(format!("{}\n{}", header_line, sub));
            }
            continue;
        }

        if current_len + row_len > body_budget && !current_rows.is_empty() {
            chunks.push(format!("{}\n{}", header_line, current_rows.join("\n")));

            // Carry over 1 trailing row as overlap if it fits within overlap budget
            let last_row = current_rows.last().cloned();
            current_rows.clear();
            current_len = 0;
            if let Some(prev) = last_row {
                let prev_len = prev.chars().count() + 1;
                if prev_len <= chunk_overlap_chars && prev_len + row_len <= body_budget {
                    current_rows.push(prev);
                    current_len = prev_len;
                }
            }
        }

        current_rows.push(row.to_string());
        current_len += row_len;
    }

    if !current_rows.is_empty() {
        chunks.push(format!("{}\n{}", header_line, current_rows.join("\n")));
    }

    chunks
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

    for seg in segments {
        let cleaned = clean_document_text(&seg.text);
        if cleaned.is_empty() {
            continue;
        }

        let char_count = cleaned.chars().count();
        let pieces: Vec<String> = if char_count <= chunk_size_chars {
            vec![cleaned]
        } else {
            let lines: Vec<&str> = cleaned.lines().collect();
            if lines.len() > 1 && is_tabular_header_line(lines[0]) {
                split_tabular_with_header(
                    lines[0],
                    &lines[1..],
                    chunk_size_chars,
                    chunk_overlap_chars,
                )
            } else {
                split_prose_smart(&cleaned, chunk_size_chars, chunk_overlap_chars)
            }
        };

        for piece in pieces {
            if piece.is_empty() {
                continue;
            }
            let sha = compute_sha256(&piece);
            chunks.push(ChunkCandidate {
                chunk_index: global_idx,
                text_content: piece.clone(),
                content_sha256: sha,
                page_number: seg.page_number,
                sheet_name: seg.sheet_name.clone(),
                row_start: seg.row_start,
                row_end: seg.row_end,
                section_label: seg.section_label.clone(),
                has_potential_injection: detect_document_prompt_injection(&piece),
            });
            global_idx += 1;
        }
    }

    Ok(chunks)
}
