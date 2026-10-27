use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use regex::Regex;

use crate::core::enums::StatementClassification;
use crate::guardrails::engine::UNIFORM_INSUFFICIENT_EVIDENCE_MESSAGE;
use crate::rag::embeddings::SEMANTIC_SYNONYM_MAP;
use crate::schemas::architecture::{CitationItem, ClaimItem, VerifiedChunkContext};

#[derive(Debug, Clone)]
pub struct LLMGenerationResult {
    pub answer: String,
    pub overall_classification: StatementClassification,
    pub claims: Vec<ClaimItem>,
    pub citations: Vec<CitationItem>,
    pub has_source_conflict: bool,
    pub conflict_summary: Option<String>,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub model_name: String,
    pub provider_name: String,
}

pub fn format_location_tag(chunk: &VerifiedChunkContext) -> String {
    let prov = &chunk.provenance;
    let mut parts = vec![
        format!("DocID={}", prov.document_id),
        format!("File={}", prov.source_filename),
    ];
    if let Some(p) = prov.page_number {
        parts.push(format!("Hal={}", p));
    }
    if let Some(s) = &prov.sheet_name {
        parts.push(format!("Sheet={}", s));
    }
    if let Some(rs) = prov.row_start {
        if let Some(re) = prov.row_end {
            if re != rs {
                parts.push(format!("Baris={}-{}", rs, re));
            } else {
                parts.push(format!("Baris={}", rs));
            }
        } else {
            parts.push(format!("Baris={}", rs));
        }
    }
    if let Some(sec) = &prov.section_label {
        parts.push(format!("Bagian={}", sec));
    }
    format!("[{}]", parts.join(" | "))
}

static STOP_WORDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "apa", "apakah", "berapa", "bagaimana", "siapa", "dimana", "kapan",
        "yang", "dan", "atau", "di", "ke", "dari", "untuk", "pada", "adalah",
        "ini", "itu", "dengan", "dalam", "tentang", "tolong", "jelaskan",
        "sebutkan", "berikan", "ringkasan", "ringkas", "analisis", "data",
        "dokumen", "perusahaan", "aturan", "kebijakan", "nilai", "total",
        "kesimpulan", "analisisnya", "beserta", "kedua", "versi", "seluruh",
        "the", "is", "are", "what", "how", "much", "many", "in", "of", "for", "to", "and",
    ]
    .into_iter()
    .collect()
});

static COMPOUND_QUERY_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[a-z0-9_]+").unwrap());
static SUB_QUERY_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[a-z0-9]+").unwrap());

pub fn expand_query_terms(query: &str) -> HashSet<String> {
    let q_lower = query.to_lowercase();

    let mut expanded = HashSet::new();

    for m in COMPOUND_QUERY_RE.find_iter(&q_lower) {
        let t = m.as_str();
        if t.len() >= 3 && !STOP_WORDS.contains(t) {
            expanded.insert(t.to_string());
        }
    }
    for m in SUB_QUERY_RE.find_iter(&q_lower) {
        let t = m.as_str();
        if t.len() >= 3 && !STOP_WORDS.contains(t) {
            expanded.insert(t.to_string());
        }
    }

    let existing_tokens: Vec<String> = expanded.iter().cloned().collect();
    for tok in existing_tokens {
        if let Some(&canon) = SEMANTIC_SYNONYM_MAP.get(tok.as_str()) {
            for sub in canon.split('_') {
                expanded.insert(sub.to_string());
            }
            for (&k, &v) in SEMANTIC_SYNONYM_MAP.iter() {
                if v == canon {
                    expanded.insert(k.to_string());
                }
            }
        }
    }

    expanded
}

static NUM_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d+(?:[.,]\d+)?\b").unwrap());

pub fn detect_conflicting_facts(
    query_terms: &HashSet<String>,
    chunks: &[VerifiedChunkContext],
) -> (bool, Option<String>) {
    if chunks.len() < 2 {
        return (false, None);
    }

    let mut doc_numbers: HashMap<String, (String, Vec<String>)> = HashMap::new();

    for ch in chunks {
        let mut relevant_nums = Vec::new();
        for line in ch.text_content.lines() {
            let lower_line = line.to_lowercase();
            if lower_line.contains("[redacted_untrusted_document_instruction]") {
                continue;
            }
            if query_terms.iter().any(|t| lower_line.contains(t)) {
                for m in NUM_RE.find_iter(line) {
                    let num_str = m.as_str();
                    let small_check = format!("baris {}", num_str);
                    let page_check = format!("page {}", num_str);
                    let hal_check = format!("hal {}", num_str);
                    if lower_line.contains(&small_check) || lower_line.contains(&page_check) || lower_line.contains(&hal_check) {
                        continue;
                    }
                    relevant_nums.push(num_str.to_string());
                }
            }
        }

        if !relevant_nums.is_empty() {
            relevant_nums.sort();
            relevant_nums.dedup();
            doc_numbers.insert(
                ch.document_id.clone(),
                (ch.provenance.source_filename.clone(), relevant_nums),
            );
        }
    }

    if doc_numbers.len() >= 2 {
        let unique_value_sets: HashSet<Vec<String>> = doc_numbers.values().map(|v| v.1.clone()).collect();
        if unique_value_sets.len() >= 2 {
            let mut details = Vec::new();
            for (doc_id, (fname, vals)) in &doc_numbers {
                details.push(format!("{} ({}) mencantumkan nilai {}", fname, doc_id, vals.join(", ")));
            }
            let summary = format!("Konflik sumber terdeteksi: {}.", details.join(" sedangkan "));
            return (true, Some(summary));
        }
    }

    (false, None)
}

static KV_NUM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([A-Za-z0-9_]+)=(\d+(?:\.\d+)?)(?:\s*\((?:integer|float)\))?").unwrap()
});
static RP_NUM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:rp\.?\s*)?(\d{3,}(?:\.\d+)?)").unwrap()
});

static TYPE_ANNOTATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\s*\((?:integer|float|string)\)").unwrap()
});

pub fn try_reproducible_calculation(
    query: &str,
    query_terms: &HashSet<String>,
    chunks: &[VerifiedChunkContext],
) -> Option<(String, String, Vec<String>)> {
    let q_lower = query.to_lowercase();
    let wants_sum = ["total", "jumlahkan", "akumulasi", "sum"].iter().any(|&k| q_lower.contains(k));
    let wants_avg = ["rata-rata", "average", "mean"].iter().any(|&k| q_lower.contains(k));

    if !wants_sum && !wants_avg {
        return None;
    }

    let mut extracted_values: Vec<(f64, String, String)> = Vec::new();
    let mut supporting_chunk_ids: Vec<String> = Vec::new();
    let mut seen_line_signatures: HashSet<String> = HashSet::new();

    for ch in chunks {
        for line in ch.text_content.lines() {
            let lower_line = line.to_lowercase();
            if lower_line.starts_with('[') || lower_line.contains("kolom header:") {
                continue;
            }
            if lower_line.contains("[redacted_untrusted_document_instruction]") {
                continue;
            }

            let line_sig = TYPE_ANNOTATION_RE.replace_all(line, "").trim().to_string();
            if seen_line_signatures.contains(&line_sig) {
                continue;
            }
            seen_line_signatures.insert(line_sig);

            let mut matched_in_line = false;
            for cap in KV_NUM_RE.captures_iter(line) {
                let col_name = &cap[1];
                let num_str = &cap[2];
                if let Ok(val) = num_str.parse::<f64>() {
                    extracted_values.push((val, format!("{}={}", col_name, num_str), ch.chunk_id.clone()));
                    if !supporting_chunk_ids.contains(&ch.chunk_id) {
                        supporting_chunk_ids.push(ch.chunk_id.clone());
                    }
                    matched_in_line = true;
                }
            }

            if !matched_in_line && query_terms.iter().any(|t| lower_line.contains(t)) {
                for cap in RP_NUM_RE.captures_iter(&lower_line) {
                    let num_str = &cap[1];
                    let clean = num_str.replace('.', "");
                    if let Ok(val) = clean.parse::<f64>() {
                        extracted_values.push((val, num_str.to_string(), ch.chunk_id.clone()));
                        if !supporting_chunk_ids.contains(&ch.chunk_id) {
                            supporting_chunk_ids.push(ch.chunk_id.clone());
                        }
                    }
                }
            }
        }
    }

    if extracted_values.len() < 2 {
        return None;
    }

    let nums: Vec<f64> = extracted_values.iter().map(|v| v.0).collect();
    let expr_terms: Vec<String> = nums
        .iter()
        .map(|n| if n.fract() == 0.0 { format!("{:.0}", n) } else { format!("{:.2}", n) })
        .collect();

    if wants_sum {
        let total_val: f64 = nums.iter().sum();
        let total_str = if total_val.fract() == 0.0 { format!("{:.0}", total_val) } else { format!("{:.2}", total_val) };
        let expr = format!("{} = {}", expr_terms.join(" + "), total_str);
        let statement = format!("[PERHITUNGAN_DATA_SUMBER] Hasil penjumlahan aktual dari data sumber: {}.", expr);
        Some((statement, expr, supporting_chunk_ids))
    } else {
        let count = nums.len() as f64;
        let avg_val: f64 = nums.iter().sum::<f64>() / count;
        let avg_str = if avg_val.fract() == 0.0 { format!("{:.0}", avg_val) } else { format!("{:.2}", avg_val) };
        let expr = format!("({}) / {} = {}", expr_terms.join(" + "), nums.len(), avg_str);
        let statement = format!("[PERHITUNGAN_DATA_SUMBER] Hasil rata-rata aktual dari data sumber: {}.", expr);
        Some((statement, expr, supporting_chunk_ids))
    }
}

pub fn chunk_satisfies_query_evidence(
    query: &str,
    query_terms: &HashSet<String>,
    chunk_text: &str,
) -> bool {
    let lower_chunk = chunk_text.to_lowercase();
    let q_lower = query.to_lowercase();

    let compound_in_query: Vec<String> = Regex::new(r"[a-z0-9]+_[a-z0-9_]+")
        .unwrap()
        .find_iter(&q_lower)
        .map(|m| m.as_str().to_string())
        .collect();

    if !compound_in_query.is_empty() {
        return compound_in_query.iter().any(|cid| lower_chunk.contains(cid));
    }

    if query_terms.is_empty() {
        return false;
    }

    let matched_count = query_terms.iter().filter(|t| lower_chunk.contains(t.as_str())).count();
    if query_terms.len() <= 2 {
        return matched_count >= 1;
    }

    matched_count >= 2 && (matched_count as f32 / query_terms.len() as f32) >= 0.30
}

pub struct LocalGroundedExtractiveLLMProvider {
    pub model_name: String,
    pub provider_name: String,
}

impl LocalGroundedExtractiveLLMProvider {
    pub fn new(model_name: &str) -> Self {
        Self {
            model_name: model_name.to_string(),
            provider_name: "local_grounded".to_string(),
        }
    }

    pub fn generate_grounded_response(
        &self,
        query: &str,
        verified_chunks: &[VerifiedChunkContext],
    ) -> LLMGenerationResult {
        if verified_chunks.is_empty() {
            return LLMGenerationResult {
                answer: UNIFORM_INSUFFICIENT_EVIDENCE_MESSAGE.to_string(),
                overall_classification: StatementClassification::InsufficientEvidence,
                claims: vec![ClaimItem {
                    statement: UNIFORM_INSUFFICIENT_EVIDENCE_MESSAGE.to_string(),
                    classification: StatementClassification::InsufficientEvidence,
                    supporting_chunk_ids: vec![],
                    calculation_expression: None,
                }],
                citations: vec![],
                has_source_conflict: false,
                conflict_summary: None,
                prompt_tokens: query.split_whitespace().count() as i64,
                completion_tokens: 18,
                model_name: self.model_name.clone(),
                provider_name: self.provider_name.clone(),
            };
        }

        let query_terms = expand_query_terms(query);
        let mut matched_chunks: Vec<(&VerifiedChunkContext, Vec<String>)> = Vec::new();

        for ch in verified_chunks {
            if !chunk_satisfies_query_evidence(query, &query_terms, &ch.text_content) {
                continue;
            }

            let lines: Vec<&str> = ch
                .text_content
                .lines()
                .map(|ln| ln.trim())
                .filter(|ln| !ln.is_empty() && !ln.contains("[REDACTED_UNTRUSTED_DOCUMENT_INSTRUCTION]"))
                .collect();

            if lines.is_empty() {
                continue;
            }

            let mut matching_lines = Vec::new();
            for ln in lines {
                let lower_ln = ln.to_lowercase();
                if query_terms.iter().any(|t| lower_ln.contains(t.as_str())) {
                    matching_lines.push(ln.to_string());
                }
            }

            if !matching_lines.is_empty() {
                matched_chunks.push((ch, matching_lines));
            }
        }

        if matched_chunks.is_empty() {
            return LLMGenerationResult {
                answer: UNIFORM_INSUFFICIENT_EVIDENCE_MESSAGE.to_string(),
                overall_classification: StatementClassification::InsufficientEvidence,
                claims: vec![ClaimItem {
                    statement: UNIFORM_INSUFFICIENT_EVIDENCE_MESSAGE.to_string(),
                    classification: StatementClassification::InsufficientEvidence,
                    supporting_chunk_ids: vec![],
                    calculation_expression: None,
                }],
                citations: vec![],
                has_source_conflict: false,
                conflict_summary: None,
                prompt_tokens: query.split_whitespace().count() as i64,
                completion_tokens: 18,
                model_name: self.model_name.clone(),
                provider_name: self.provider_name.clone(),
            };
        }

        let relevant_only_chunks: Vec<VerifiedChunkContext> =
            matched_chunks.iter().map(|(ch, _)| (*ch).clone()).collect();
        let (has_conflict, conflict_summary) =
            detect_conflicting_facts(&query_terms, &relevant_only_chunks);

        let mut claims = Vec::new();
        let mut citations = Vec::new();
        let mut answer_sections = Vec::new();

        if has_conflict {
            if let Some(ref sum) = conflict_summary {
                answer_sections.push(format!("⚠️ **KONFLIK SUMBER TERDETEKSI:** {}", sum));
            }
        }

        for (ch, m_lines) in &matched_chunks {
            let excerpt_lines: Vec<&str> = m_lines.iter().take(3).map(|s| s.as_str()).collect();
            let excerpt = excerpt_lines.join(" | ");
            let loc_tag = format_location_tag(ch);
            let fact_text = format!(
                "[FAKTA_SUMBER] Berdasarkan {} {}: {}",
                ch.provenance.title, loc_tag, excerpt
            );

            claims.push(ClaimItem {
                statement: fact_text.clone(),
                classification: StatementClassification::SourceFact,
                supporting_chunk_ids: vec![ch.chunk_id.clone()],
                calculation_expression: None,
            });

            citations.push(CitationItem {
                document_id: ch.document_id.clone(),
                title: ch.provenance.title.clone(),
                source_filename: ch.provenance.source_filename.clone(),
                chunk_id: ch.chunk_id.clone(),
                page_number: ch.provenance.page_number,
                sheet_name: ch.provenance.sheet_name.clone(),
                row_start: ch.provenance.row_start,
                row_end: ch.provenance.row_end,
                section_label: ch.provenance.section_label.clone(),
                excerpt: if excerpt.chars().count() > 350 {
                    excerpt.chars().take(350).collect()
                } else {
                    excerpt
                },
            });

            answer_sections.push(fact_text);
        }

        let mut overall_class = StatementClassification::SourceFact;

        if let Some((calc_stmt, calc_expr, calc_chunk_ids)) =
            try_reproducible_calculation(query, &query_terms, &relevant_only_chunks)
        {
            claims.push(ClaimItem {
                statement: calc_stmt.clone(),
                classification: StatementClassification::ComputedFromSource,
                supporting_chunk_ids: calc_chunk_ids,
                calculation_expression: Some(calc_expr),
            });
            answer_sections.push(calc_stmt);
            overall_class = StatementClassification::ComputedFromSource;
        }

        let q_lower = query.to_lowercase();
        if ["kesimpulan", "inferensi", "implikasi", "analisis"].iter().any(|&w| q_lower.contains(w)) {
            let inf_stmt = format!(
                "[INFERENSI_TERBATAS] Berdasarkan {} bukti sumber terverifikasi di atas, kesimpulan terbatas hanya berlaku pada ruang lingkup dokumen yang disitasi.",
                citations.len()
            );
            claims.push(ClaimItem {
                statement: inf_stmt.clone(),
                classification: StatementClassification::PermittedInference,
                supporting_chunk_ids: citations.iter().map(|c| c.chunk_id.clone()).collect(),
                calculation_expression: None,
            });
            answer_sections.push(inf_stmt);
        }

        let full_answer = answer_sections.join("\n\n");
        let prompt_tokens = (query.split_whitespace().count()
            + relevant_only_chunks.iter().map(|c| c.text_content.split_whitespace().count()).sum::<usize>())
            as i64;
        let completion_tokens = full_answer.split_whitespace().count() as i64;

        LLMGenerationResult {
            answer: full_answer,
            overall_classification: overall_class,
            claims,
            citations,
            has_source_conflict: has_conflict,
            conflict_summary,
            prompt_tokens,
            completion_tokens,
            model_name: self.model_name.clone(),
            provider_name: self.provider_name.clone(),
        }
    }
}
