use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::core::enums::{
    DocumentScope, GuardrailDecisionType, GuardrailStage, IngestionStatus,
    StatementClassification, SupportedFileType, UserRole,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedPrincipal {
    pub user_id: String,
    pub username: String,
    pub email: String,
    pub role: UserRole,
    #[serde(default)]
    pub explicit_permissions: Vec<String>,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentACLPolicy {
    pub document_id: String,
    pub owner_user_id: String,
    pub scope: DocumentScope,
    pub allowed_roles: Vec<UserRole>,
    #[serde(default)]
    pub allowed_users: Vec<String>,
    #[serde(default = "default_one")]
    pub acl_version: i64,
    #[serde(default = "default_indexed")]
    pub ingestion_status: IngestionStatus,
}

fn default_one() -> i64 {
    1
}

fn default_indexed() -> IngestionStatus {
    IngestionStatus::Indexed
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkProvenance {
    pub document_id: String,
    pub title: String,
    pub source_filename: String,
    pub file_type: SupportedFileType,
    pub chunk_id: String,
    pub chunk_index: i64,
    pub page_number: Option<i64>,
    pub sheet_name: Option<String>,
    pub row_start: Option<i64>,
    pub row_end: Option<i64>,
    pub section_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifiedChunkContext {
    pub chunk_id: String,
    pub document_id: String,
    pub text_content: String,
    pub relevance_score: f32,
    pub provenance: ChunkProvenance,
    pub acl_verified_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CitationItem {
    pub document_id: String,
    pub title: String,
    pub source_filename: String,
    pub chunk_id: String,
    pub page_number: Option<i64>,
    pub sheet_name: Option<String>,
    pub row_start: Option<i64>,
    pub row_end: Option<i64>,
    pub section_label: Option<String>,
    pub excerpt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimItem {
    pub statement: String,
    pub classification: StatementClassification,
    #[serde(default)]
    pub supporting_chunk_ids: Vec<String>,
    pub calculation_expression: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardrailDecision {
    pub stage: GuardrailStage,
    pub decision: GuardrailDecisionType,
    pub rule_id: String,
    pub reason: String,
    #[serde(default)]
    pub triggered_patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RAGQueryResponse {
    pub request_id: String,
    pub session_id: String,
    pub answer: String,
    pub overall_classification: StatementClassification,
    #[serde(default)]
    pub claims: Vec<ClaimItem>,
    #[serde(default)]
    pub citations: Vec<CitationItem>,
    #[serde(default)]
    pub has_source_conflict: bool,
    pub conflict_summary: Option<String>,
    #[serde(default)]
    pub guardrail_decisions: Vec<GuardrailDecision>,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}
