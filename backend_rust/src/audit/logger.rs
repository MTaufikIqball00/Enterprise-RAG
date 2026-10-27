use regex::{Regex, RegexBuilder};
use serde_json::Value;
use sqlx::SqlitePool;
use std::sync::LazyLock;

use crate::db::models::AuditLogRecord;
use crate::schemas::architecture::{AuthenticatedPrincipal, GuardrailDecision};

static SECRET_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (
            RegexBuilder::new(r"pbkdf2_sha256\$\d+\$[a-f0-9]+\$[a-f0-9]+")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "[REDACTED_PASSWORD_HASH]",
        ),
        (
            RegexBuilder::new(r"Bearer\s+[A-Za-z0-9_\-\.]+")
                .case_insensitive(true)
                .build()
                .unwrap(),
            "Bearer [REDACTED_JWT]",
        ),
        (
            Regex::new(r"sk-[A-Za-z0-9]{16,}").unwrap(),
            "[REDACTED_API_KEY]",
        ),
    ]
});

pub fn redact_sensitive_string(val: &str) -> String {
    let mut res = val.to_string();
    for (pat, repl) in SECRET_PATTERNS.iter() {
        res = pat.replace_all(&res, *repl).to_string();
    }
    res
}

pub fn sanitize_metadata_json(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let forbidden = ["password", "password_hash", "jwt_secret", "api_key", "raw_document_text", "token"];
            let mut sanitized = serde_json::Map::new();
            for (k, v) in map {
                if forbidden.contains(&k.to_lowercase().as_str()) {
                    sanitized.insert(k.clone(), Value::String("[REDACTED]".to_string()));
                } else {
                    sanitized.insert(k.clone(), sanitize_metadata_json(v));
                }
            }
            Value::Object(sanitized)
        }
        Value::String(s) => Value::String(redact_sensitive_string(s)),
        Value::Array(arr) => Value::Array(arr.iter().map(sanitize_metadata_json).collect()),
        other => other.clone(),
    }
}

pub struct AuditLogger;

impl AuditLogger {
    pub async fn record_event(
        pool: &SqlitePool,
        request_id: &str,
        action: &str,
        resource_type: &str,
        authz_decision: &str,
        pipeline_status: &str,
        principal: Option<&AuthenticatedPrincipal>,
        resource_id: Option<&str>,
        guardrail_decisions: &[GuardrailDecision],
        accessed_document_ids: &[String],
        retrieval_scores: &[f32],
        retrieval_config_version: Option<&str>,
        llm_provider: Option<&str>,
        llm_model: Option<&str>,
        latency_ms: Option<f64>,
        prompt_tokens: Option<i64>,
        completion_tokens: Option<i64>,
        error_code: Option<&str>,
        metadata: Option<&Value>,
    ) -> Result<AuditLogRecord, sqlx::Error> {
        let now_str = chrono::Utc::now().to_rfc3339();
        let guardrails_json = serde_json::to_string(guardrail_decisions).unwrap_or_else(|_| "[]".to_string());
        let docs_json = serde_json::to_string(accessed_document_ids).unwrap_or_else(|_| "[]".to_string());

        let scores_rounded: Vec<f64> = retrieval_scores.iter().map(|&s| (s as f64 * 10000.0).round() / 10000.0).collect();
        let scores_json = serde_json::to_string(&scores_rounded).unwrap_or_else(|_| "[]".to_string());

        let empty_val = Value::Object(serde_json::Map::new());
        let meta_raw = metadata.unwrap_or(&empty_val);
        let meta_sanitized = sanitize_metadata_json(meta_raw);
        let meta_json = serde_json::to_string(&meta_sanitized).unwrap_or_else(|_| "{}".to_string());

        let latency_rounded = latency_ms.map(|l| (l * 100.0).round() / 100.0);

        let user_id = principal.map(|p| p.user_id.clone());
        let user_role = principal.map(|p| p.role.as_str().to_string());

        let insert_res = sqlx::query(
            r#"
            INSERT INTO audit_logs (
                request_id, timestamp, user_id, user_role, action, resource_type,
                resource_id, authz_decision, guardrail_decisions, accessed_document_ids,
                retrieval_scores, retrieval_config_version, llm_provider, llm_model,
                latency_ms, prompt_tokens, completion_tokens, pipeline_status,
                error_code, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(request_id)
        .bind(&now_str)
        .bind(&user_id)
        .bind(&user_role)
        .bind(action)
        .bind(resource_type)
        .bind(resource_id)
        .bind(authz_decision)
        .bind(&guardrails_json)
        .bind(&docs_json)
        .bind(&scores_json)
        .bind(retrieval_config_version)
        .bind(llm_provider)
        .bind(llm_model)
        .bind(latency_rounded)
        .bind(prompt_tokens)
        .bind(completion_tokens)
        .bind(pipeline_status)
        .bind(error_code)
        .bind(&meta_json)
        .execute(pool)
        .await?;

        Ok(AuditLogRecord {
            id: insert_res.last_insert_rowid(),
            request_id: request_id.to_string(),
            timestamp: now_str,
            user_id,
            user_role,
            action: action.to_string(),
            resource_type: resource_type.to_string(),
            resource_id: resource_id.map(|s| s.to_string()),
            authz_decision: authz_decision.to_string(),
            guardrail_decisions: guardrails_json,
            accessed_document_ids: docs_json,
            retrieval_scores: scores_json,
            retrieval_config_version: retrieval_config_version.map(|s| s.to_string()),
            llm_provider: llm_provider.map(|s| s.to_string()),
            llm_model: llm_model.map(|s| s.to_string()),
            latency_ms: latency_rounded,
            prompt_tokens,
            completion_tokens,
            pipeline_status: pipeline_status.to_string(),
            error_code: error_code.map(|s| s.to_string()),
            metadata_json: meta_json,
        })
    }
}
