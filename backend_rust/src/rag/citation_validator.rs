use std::collections::HashMap;
use thiserror::Error;

use crate::core::enums::StatementClassification;
use crate::schemas::architecture::{CitationItem, ClaimItem, VerifiedChunkContext};

#[derive(Debug, Error)]
pub enum CitationValidationError {
    #[error("Sitasi palsu terdeteksi: chunk_id '{0}' tidak ada dalam konteks terotorisasi.")]
    FakeChunkId(String),

    #[error("Ketidakcocokan document_id pada sitasi '{0}': '{1}' != '{2}'.")]
    DocumentIdMismatch(String, String, String),

    #[error("Nomor halaman sitasi tidak valid pada '{0}'.")]
    PageNumberMismatch(String),

    #[error("Nama sheet sitasi tidak valid pada '{0}'.")]
    SheetNameMismatch(String),

    #[error("Rentang baris sitasi tidak valid pada '{0}'.")]
    RowRangeMismatch(String),

    #[error("Kutipan sitasi pada '{0}' tidak ditemukan pada teks sumber asli.")]
    ExcerptNotFound(String),

    #[error("Klaim '{0}' wajib menyertakan minimal satu supporting_chunk_id.")]
    MissingSupportingChunks(String),

    #[error("Klaim merujuk pada chunk_id '{0}' yang tidak terverifikasi.")]
    UnverifiedSupportingChunk(String),

    #[error("Klaim PERHITUNGAN_DATA_SUMBER wajib menyertakan ekspresi perhitungan yang dapat direproduksi.")]
    MissingCalculationExpression,
}

pub struct CitationValidator;

impl CitationValidator {
    pub fn validate_citations_and_claims(
        claims: &[ClaimItem],
        citations: &[CitationItem],
        verified_chunks: &[VerifiedChunkContext],
    ) -> Result<(), CitationValidationError> {
        let chunk_map: HashMap<&str, &VerifiedChunkContext> =
            verified_chunks.iter().map(|c| (c.chunk_id.as_str(), c)).collect();

        for cit in citations {
            let source_chunk = chunk_map
                .get(cit.chunk_id.as_str())
                .ok_or_else(|| CitationValidationError::FakeChunkId(cit.chunk_id.clone()))?;

            if cit.document_id != source_chunk.document_id {
                return Err(CitationValidationError::DocumentIdMismatch(
                    cit.chunk_id.clone(),
                    cit.document_id.clone(),
                    source_chunk.document_id.clone(),
                ));
            }

            if cit.page_number != source_chunk.provenance.page_number {
                return Err(CitationValidationError::PageNumberMismatch(cit.chunk_id.clone()));
            }

            if cit.sheet_name != source_chunk.provenance.sheet_name {
                return Err(CitationValidationError::SheetNameMismatch(cit.chunk_id.clone()));
            }

            if cit.row_start != source_chunk.provenance.row_start || cit.row_end != source_chunk.provenance.row_end {
                return Err(CitationValidationError::RowRangeMismatch(cit.chunk_id.clone()));
            }

            let parts: Vec<&str> = cit.excerpt.split('|').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
            for part in parts {
                if !source_chunk.text_content.contains(part) {
                    return Err(CitationValidationError::ExcerptNotFound(cit.chunk_id.clone()));
                }
            }
        }

        for claim in claims {
            match claim.classification {
                StatementClassification::SourceFact
                | StatementClassification::ComputedFromSource
                | StatementClassification::PermittedInference => {
                    if claim.supporting_chunk_ids.is_empty() {
                        return Err(CitationValidationError::MissingSupportingChunks(
                            claim.classification.as_str().to_string(),
                        ));
                    }
                    for cid in &claim.supporting_chunk_ids {
                        if !chunk_map.contains_key(cid.as_str()) {
                            return Err(CitationValidationError::UnverifiedSupportingChunk(cid.clone()));
                        }
                    }
                }
                _ => {}
            }

            if claim.classification == StatementClassification::ComputedFromSource {
                if claim.calculation_expression.as_deref().unwrap_or("").trim().is_empty() {
                    return Err(CitationValidationError::MissingCalculationExpression);
                }
            }
        }

        Ok(())
    }
}
