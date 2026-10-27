use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use sqlx::SqlitePool;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::audit::logger::AuditLogger;
use crate::core::config::Settings;
use crate::core::enums::{
    GuardrailDecisionType, StatementClassification,
};
use crate::db::models::{ChatSessionRecord, DocumentRecord};
use crate::guardrails::engine::{
    GuardrailsEngine, UNIFORM_SAFE_REFUSAL_MESSAGE,
};
use crate::rag::citation_validator::CitationValidator;
use crate::rag::llm::LocalGroundedExtractiveLLMProvider;
use crate::rag::vector_store::VectorStore;
use crate::schemas::architecture::{
    AuthenticatedPrincipal, ClaimItem, GuardrailDecision, RAGQueryResponse,
};
use crate::security::rbac::RBACPolicyEngine;

pub struct EnterpriseRAGService {
    pub vector_store: VectorStore,
    pub llm_provider: Arc<LocalGroundedExtractiveLLMProvider>,
    pub settings: Arc<Settings>,
    isolated_cache: Arc<RwLock<HashMap<String, RAGQueryResponse>>>,
}

impl EnterpriseRAGService {
    pub fn new(
        vector_store: VectorStore,
        llm_provider: Arc<LocalGroundedExtractiveLLMProvider>,
        settings: Arc<Settings>,
    ) -> Self {
        Self {
            vector_store,
            llm_provider,
            settings,
            isolated_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn clear_cache(&self) {
        let mut cache = self.isolated_cache.write().await;
        cache.clear();
    }

    async fn get_or_create_isolated_session(
        &self,
        pool: &SqlitePool,
        principal: &AuthenticatedPrincipal,
        session_id: Option<&str>,
        query_preview: &str,
    ) -> Result<ChatSessionRecord, anyhow::Error> {
        if let Some(sid) = session_id {
            let session = sqlx::query_as::<_, ChatSessionRecord>(
                "SELECT * FROM chat_sessions WHERE session_id = ?",
            )
            .bind(sid)
            .fetch_optional(pool)
            .await?;

            let verified = RBACPolicyEngine::require_session_ownership(principal, session.as_ref())
                .map_err(|e| anyhow::anyhow!(e))?;
            return Ok(verified.clone());
        }

        let new_id = format!("sess-{}", &Uuid::new_v4().simple().to_string()[..16]);
        let title_clean = if query_preview.trim().is_empty() {
            "Percakapan Baru".to_string()
        } else {
            let p: String = query_preview.trim().chars().take(60).collect();
            p
        };

        let now_str = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO chat_sessions (session_id, user_id, title, role_snapshot, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&new_id)
        .bind(&principal.user_id)
        .bind(&title_clean)
        .bind(principal.role.as_str())
        .bind(&now_str)
        .execute(pool)
        .await?;

        let rec = sqlx::query_as::<_, ChatSessionRecord>(
            "SELECT * FROM chat_sessions WHERE session_id = ?",
        )
        .bind(&new_id)
        .fetch_one(pool)
        .await?;

        Ok(rec)
    }

    async fn get_accessible_doc_acl_versions(
        &self,
        pool: &SqlitePool,
        principal: &AuthenticatedPrincipal,
    ) -> Result<HashMap<String, i64>, sqlx::Error> {
        let docs = sqlx::query_as::<_, DocumentRecord>(
            "SELECT * FROM documents WHERE ingestion_status = 'INDEXED'",
        )
        .fetch_all(pool)
        .await?;

        let mut res = HashMap::new();
        for d in docs {
            if RBACPolicyEngine::can_read_document(principal, &d) {
                res.insert(d.document_id, d.acl_version);
            }
        }
        Ok(res)
    }

    pub async fn query(
        &self,
        pool: &SqlitePool,
        principal: &AuthenticatedPrincipal,
        question: &str,
        session_id: Option<&str>,
        use_cache: bool,
    ) -> Result<RAGQueryResponse, anyhow::Error> {
        let start_time = Instant::now();
        let request_id = format!("req-{}", &Uuid::new_v4().simple().to_string()[..16]);
        let mut guardrail_decisions: Vec<GuardrailDecision> = Vec::new();

        // 1 & 2: Verify active principal and session ownership
        RBACPolicyEngine::ensure_active(principal)?;
        let session_rec = self
            .get_or_create_isolated_session(pool, principal, session_id, question)
            .await?;

        // 3: Input Guardrails
        let input_decision = GuardrailsEngine::check_input(question);
        guardrail_decisions.push(input_decision.clone());

        if input_decision.decision == GuardrailDecisionType::Block {
            let latency_ms = start_time.elapsed().as_secs_f64() * 1000.0;
            let meta = serde_json::json!({ "blocked_reason": input_decision.reason });

            let _ = AuditLogger::record_event(
                pool,
                &request_id,
                "RAG_QUERY",
                "CHAT_SESSION",
                "DENY",
                "BLOCKED_BY_INPUT_GUARDRAIL",
                Some(principal),
                Some(&session_rec.session_id),
                &guardrail_decisions,
                &[],
                &[],
                None,
                None,
                None,
                Some(latency_ms),
                None,
                None,
                Some(&input_decision.rule_id),
                Some(&meta),
            )
            .await;

            return Ok(RAGQueryResponse {
                request_id,
                session_id: session_rec.session_id,
                answer: UNIFORM_SAFE_REFUSAL_MESSAGE.to_string(),
                overall_classification: StatementClassification::InsufficientEvidence,
                claims: vec![ClaimItem {
                    statement: UNIFORM_SAFE_REFUSAL_MESSAGE.to_string(),
                    classification: StatementClassification::InsufficientEvidence,
                    supporting_chunk_ids: vec![],
                    calculation_expression: None,
                }],
                citations: vec![],
                has_source_conflict: false,
                conflict_summary: None,
                guardrail_decisions,
                metadata: [
                    ("status".to_string(), serde_json::json!("BLOCKED_BY_INPUT_GUARDRAIL")),
                    ("rule_id".to_string(), serde_json::json!(input_decision.rule_id)),
                ]
                .into_iter()
                .collect(),
            });
        }

        // 4: Isolated cache check
        let accessible_acls = self.get_accessible_doc_acl_versions(pool, principal).await?;
        let cache_key = RBACPolicyEngine::build_isolated_cache_key(principal, question, &accessible_acls);

        if use_cache {
            let cache = self.isolated_cache.read().await;
            if let Some(cached) = cache.get(&cache_key) {
                let latency_ms = start_time.elapsed().as_secs_f64() * 1000.0;
                let accessed_doc_ids: Vec<String> = cached.citations.iter().map(|c| c.document_id.clone()).collect();

                let _ = AuditLogger::record_event(
                    pool,
                    &request_id,
                    "RAG_QUERY_CACHE_HIT",
                    "CHAT_SESSION",
                    "ALLOW",
                    "COMPLETED_FROM_ISOLATED_CACHE",
                    Some(principal),
                    Some(&session_rec.session_id),
                    &cached.guardrail_decisions,
                    &accessed_doc_ids,
                    &[],
                    None,
                    None,
                    None,
                    Some(latency_ms),
                    None,
                    None,
                    None,
                    None,
                )
                .await;

                let mut clone_resp = cached.clone();
                clone_resp.request_id = request_id;
                clone_resp.session_id = session_rec.session_id;
                return Ok(clone_resp);
            }
        }

        // 5: Pre-retrieval vector search
        let query_vector = self.vector_store.embedding_provider.embed_query(question);
        let hits = self
            .vector_store
            .search(
                &query_vector,
                principal,
                self.settings.retrieval_top_k,
                self.settings.min_relevance_score,
            )
            .await;

        let candidate_chunks: Vec<(String, String, f32)> = hits
            .into_iter()
            .map(|h| (h.chunk_id, h.document_id, h.score))
            .collect();

        // 6: Post-retrieval DB ACL re-verification
        let verified_chunks = RBACPolicyEngine::verify_chunks_post_retrieval(pool, principal, &candidate_chunks)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        // 7: Retrieval Guardrails (Neutralize Indirect Prompt Injection)
        let (sanitized_chunks, retrieval_decision) = GuardrailsEngine::sanitize_retrieved_chunks(verified_chunks);
        guardrail_decisions.push(retrieval_decision);

        // 8: Grounded LLM Generation
        let gen_result = self.llm_provider.generate_grounded_response(question, &sanitized_chunks);

        // 9a: Validate Citations & Claims
        let _ = CitationValidator::validate_citations_and_claims(
            &gen_result.claims,
            &gen_result.citations,
            &sanitized_chunks,
        );

        // 9b: Output Guardrails
        let (validated_answer, output_decision) = GuardrailsEngine::validate_output(&gen_result.answer);
        guardrail_decisions.push(output_decision.clone());

        let final_citations = if output_decision.decision == GuardrailDecisionType::Allow {
            gen_result.citations
        } else {
            vec![]
        };

        let final_claims = if output_decision.decision == GuardrailDecisionType::Allow {
            gen_result.claims
        } else {
            vec![ClaimItem {
                statement: UNIFORM_SAFE_REFUSAL_MESSAGE.to_string(),
                classification: StatementClassification::InsufficientEvidence,
                supporting_chunk_ids: vec![],
                calculation_expression: None,
            }]
        };

        let final_classification = if output_decision.decision == GuardrailDecisionType::Allow {
            gen_result.overall_classification
        } else {
            StatementClassification::InsufficientEvidence
        };

        // 10: Save chat messages to database
        let user_msg_id = format!("msg-{}", &Uuid::new_v4().simple().to_string()[..16]);
        let asst_msg_id = format!("msg-{}", &Uuid::new_v4().simple().to_string()[..16]);
        let now_str = chrono::Utc::now().to_rfc3339();
        let citations_json = serde_json::to_string(&final_citations)?;

        sqlx::query(
            r#"
            INSERT INTO chat_messages (
                message_id, session_id, user_id, sender, content, citations_json,
                epistemic_classification, request_id, created_at
            ) VALUES (?, ?, ?, 'user', ?, '[]', NULL, ?, ?)
            "#,
        )
        .bind(&user_msg_id)
        .bind(&session_rec.session_id)
        .bind(&principal.user_id)
        .bind(question)
        .bind(&request_id)
        .bind(&now_str)
        .execute(pool)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO chat_messages (
                message_id, session_id, user_id, sender, content, citations_json,
                epistemic_classification, request_id, created_at
            ) VALUES (?, ?, ?, 'assistant', ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&asst_msg_id)
        .bind(&session_rec.session_id)
        .bind(&principal.user_id)
        .bind(&validated_answer)
        .bind(&citations_json)
        .bind(final_classification.as_str())
        .bind(&request_id)
        .bind(&now_str)
        .execute(pool)
        .await?;

        let latency_ms = start_time.elapsed().as_secs_f64() * 1000.0;
        let mut accessed_doc_ids: Vec<String> = final_citations.iter().map(|c| c.document_id.clone()).collect();
        accessed_doc_ids.sort();
        accessed_doc_ids.dedup();

        let retrieval_scores: Vec<f32> = sanitized_chunks.iter().map(|c| c.relevance_score).collect();
        let retrieval_cfg_ver = format!(
            "top_k={}|min_score={}|chunk={}",
            self.settings.retrieval_top_k, self.settings.min_relevance_score, self.settings.chunk_size_chars
        );

        let meta = serde_json::json!({
            "overall_classification": final_classification.as_str(),
            "has_source_conflict": gen_result.has_source_conflict,
            "citation_count": final_citations.len(),
        });

        let _ = AuditLogger::record_event(
            pool,
            &request_id,
            "RAG_QUERY",
            "CHAT_SESSION",
            "ALLOW",
            "COMPLETED",
            Some(principal),
            Some(&session_rec.session_id),
            &guardrail_decisions,
            &accessed_doc_ids,
            &retrieval_scores,
            Some(&retrieval_cfg_ver),
            Some(&gen_result.provider_name),
            Some(&gen_result.model_name),
            Some(latency_ms),
            Some(gen_result.prompt_tokens),
            Some(gen_result.completion_tokens),
            None,
            Some(&meta),
        )
        .await;

        let response = RAGQueryResponse {
            request_id,
            session_id: session_rec.session_id,
            answer: validated_answer,
            overall_classification: final_classification,
            claims: final_claims,
            citations: final_citations,
            has_source_conflict: gen_result.has_source_conflict,
            conflict_summary: gen_result.conflict_summary,
            guardrail_decisions,
            metadata: [
                ("status".to_string(), serde_json::json!("COMPLETED")),
                ("latency_ms".to_string(), serde_json::json!((latency_ms * 100.0).round() / 100.0)),
                ("llm_provider".to_string(), serde_json::json!(gen_result.provider_name)),
                ("llm_model".to_string(), serde_json::json!(gen_result.model_name)),
                ("retrieval_config_version".to_string(), serde_json::json!(retrieval_cfg_ver)),
            ]
            .into_iter()
            .collect(),
        };

        if use_cache && output_decision.decision == GuardrailDecisionType::Allow {
            let mut cache = self.isolated_cache.write().await;
            cache.insert(cache_key, response.clone());
        }

        Ok(response)
    }
}
