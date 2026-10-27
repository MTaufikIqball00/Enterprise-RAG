use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserRecord {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub explicit_permissions: String, // JSON array string
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RoleChangeAuditRecord {
    pub id: i64,
    pub actor_user_id: String,
    pub target_user_id: String,
    pub previous_role: String,
    pub new_role: String,
    pub previous_permissions: String, // JSON array string
    pub new_permissions: String,      // JSON array string
    pub reason: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DocumentRecord {
    pub document_id: String,
    pub title: String,
    pub source_filename: String,
    pub file_type: String,
    pub file_size_bytes: i64,
    pub content_sha256: String,
    pub owner_user_id: String,
    pub scope: String,
    pub allowed_roles: String, // JSON array string
    pub allowed_users: String, // JSON array string
    pub version: i64,
    pub acl_version: i64,
    pub ingestion_status: String,
    pub ingestion_error: Option<String>,
    pub chunk_count: i64,
    pub storage_path: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DocumentChunkRecord {
    pub chunk_id: String,
    pub document_id: String,
    pub chunk_index: i64,
    pub text_content: String,
    pub content_sha256: String,
    pub page_number: Option<i64>,
    pub sheet_name: Option<String>,
    pub row_start: Option<i64>,
    pub row_end: Option<i64>,
    pub section_label: Option<String>,
    pub has_potential_injection: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ChatSessionRecord {
    pub session_id: String,
    pub user_id: String,
    pub title: String,
    pub role_snapshot: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ChatMessageRecord {
    pub message_id: String,
    pub session_id: String,
    pub user_id: String,
    pub sender: String,
    pub content: String,
    pub citations_json: String, // JSON array string
    pub epistemic_classification: Option<String>,
    pub request_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditLogRecord {
    pub id: i64,
    pub request_id: String,
    pub timestamp: String,
    pub user_id: Option<String>,
    pub user_role: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub authz_decision: String,
    pub guardrail_decisions: String,    // JSON array string
    pub accessed_document_ids: String,  // JSON array string
    pub retrieval_scores: String,       // JSON array string
    pub retrieval_config_version: Option<String>,
    pub llm_provider: Option<String>,
    pub llm_model: Option<String>,
    pub latency_ms: Option<f64>,
    pub prompt_tokens: Option<i64>,
    pub completion_tokens: Option<i64>,
    pub pipeline_status: String,
    pub error_code: Option<String>,
    pub metadata_json: String,          // JSON object string
}
