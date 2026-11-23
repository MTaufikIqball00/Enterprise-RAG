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
            Regex::new(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
                .unwrap(),
            "[REDACTED_JWT]",
        ),
        (
            Regex::new(r"sk-(?:proj-)?[A-Za-z0-9_\-]{16,}").unwrap(),
            "[REDACTED_API_KEY]",
        ),
        (
            Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap(),
            "[REDACTED_GEMINI_KEY]",
        ),
        (
            Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
            "[REDACTED_PRIVATE_KEY]",
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
            let forbidden = [
                "password",
                "password_hash",
                "jwt_secret",
                "api_key",
                "raw_document_text",
                "token",
                "access_token",
            ];
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

pub struct AuditEventInput<'a> {
    pub request_id: &'a str,
    pub action: &'a str,
    pub resource_type: &'a str,
    pub authz_decision: &'a str,
    pub pipeline_status: &'a str,
    pub principal: Option<&'a AuthenticatedPrincipal>,
    pub resource_id: Option<&'a str>,
    pub guardrail_decisions: &'a [GuardrailDecision],
    pub accessed_document_ids: &'a [String],
    pub retrieval_scores: &'a [f32],
    pub retrieval_config_version: Option<&'a str>,
    pub llm_provider: Option<&'a str>,
    pub llm_model: Option<&'a str>,
    pub latency_ms: Option<f64>,
    pub prompt_tokens: Option<i64>,
    pub completion_tokens: Option<i64>,
    pub error_code: Option<&'a str>,
    pub metadata: Option<&'a Value>,
}

impl<'a> AuditEventInput<'a> {
    pub fn minimal(
        request_id: &'a str,
        action: &'a str,
        resource_type: &'a str,
        authz_decision: &'a str,
        pipeline_status: &'a str,
    ) -> Self {
        Self {
            request_id,
            action,
            resource_type,
            authz_decision,
            pipeline_status,
            principal: None,
            resource_id: None,
            guardrail_decisions: &[],
            accessed_document_ids: &[],
            retrieval_scores: &[],
            retrieval_config_version: None,
            llm_provider: None,
            llm_model: None,
            latency_ms: None,
            prompt_tokens: None,
            completion_tokens: None,
            error_code: None,
            metadata: None,
        }
    }
}

pub struct AuditLogger;

impl AuditLogger {
    pub async fn record_event(
        pool: &SqlitePool,
        event: AuditEventInput<'_>,
    ) -> Result<AuditLogRecord, sqlx::Error> {
        let now_str = chrono::Utc::now().to_rfc3339();
        let guardrails_json =
            serde_json::to_string(event.guardrail_decisions).unwrap_or_else(|_| "[]".to_string());
        let docs_json =
            serde_json::to_string(event.accessed_document_ids).unwrap_or_else(|_| "[]".to_string());

        let scores_rounded: Vec<f64> = event
            .retrieval_scores
            .iter()
            .map(|&s| (s as f64 * 10000.0).round() / 10000.0)
            .collect();
        let scores_json =
            serde_json::to_string(&scores_rounded).unwrap_or_else(|_| "[]".to_string());

        let empty_val = Value::Object(serde_json::Map::new());
        let meta_raw = event.metadata.unwrap_or(&empty_val);
        let meta_sanitized = sanitize_metadata_json(meta_raw);
        let meta_json = serde_json::to_string(&meta_sanitized).unwrap_or_else(|_| "{}".to_string());

        let latency_rounded = event.latency_ms.map(|l| (l * 100.0).round() / 100.0);

        let user_id = event.principal.map(|p| p.user_id.clone());
        let user_role = event.principal.map(|p| p.role.as_str().to_string());

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
        .bind(event.request_id)
        .bind(&now_str)
        .bind(&user_id)
        .bind(&user_role)
        .bind(event.action)
        .bind(event.resource_type)
        .bind(event.resource_id)
        .bind(event.authz_decision)
        .bind(&guardrails_json)
        .bind(&docs_json)
        .bind(&scores_json)
        .bind(event.retrieval_config_version)
        .bind(event.llm_provider)
        .bind(event.llm_model)
        .bind(latency_rounded)
        .bind(event.prompt_tokens)
        .bind(event.completion_tokens)
        .bind(event.pipeline_status)
        .bind(event.error_code)
        .bind(&meta_json)
        .execute(pool)
        .await?;

        Ok(AuditLogRecord {
            id: insert_res.last_insert_rowid(),
            request_id: event.request_id.to_string(),
            timestamp: now_str,
            user_id,
            user_role,
            action: event.action.to_string(),
            resource_type: event.resource_type.to_string(),
            resource_id: event.resource_id.map(|s| s.to_string()),
            authz_decision: event.authz_decision.to_string(),
            guardrail_decisions: guardrails_json,
            accessed_document_ids: docs_json,
            retrieval_scores: scores_json,
            retrieval_config_version: event.retrieval_config_version.map(|s| s.to_string()),
            llm_provider: event.llm_provider.map(|s| s.to_string()),
            llm_model: event.llm_model.map(|s| s.to_string()),
            latency_ms: latency_rounded,
            prompt_tokens: event.prompt_tokens,
            completion_tokens: event.completion_tokens,
            pipeline_status: event.pipeline_status.to_string(),
            error_code: event.error_code.map(|s| s.to_string()),
            metadata_json: meta_json,
        })
    }
}
