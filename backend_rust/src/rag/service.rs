use moka::future::Cache;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::audit::logger::{AuditEventInput, AuditLogger};
use crate::core::config::Settings;
use crate::core::enums::{GuardrailDecisionType, GuardrailStage, StatementClassification};
use crate::db::models::{ChatMessageRecord, ChatSessionRecord, DocumentRecord};
use crate::guardrails::engine::{
    GuardrailsEngine, UNIFORM_INSUFFICIENT_EVIDENCE_MESSAGE, UNIFORM_SAFE_REFUSAL_MESSAGE,
};
use crate::rag::citation_validator::CitationValidator;
use crate::rag::llm::{expand_query_terms, LLMProvider};
use crate::rag::vector_store::VectorStore;
use crate::schemas::architecture::{
    AuthenticatedPrincipal, CitationItem, ClaimItem, GuardrailDecision, RAGQueryResponse,
};
use crate::security::rbac::RBACPolicyEngine;

pub struct EnterpriseRAGService {
    pub vector_store: VectorStore,
    pub llm_provider: Arc<dyn LLMProvider>,
    pub settings: Arc<Settings>,
    isolated_cache: Cache<String, RAGQueryResponse>,
}

impl EnterpriseRAGService {
    pub fn new(
        vector_store: VectorStore,
        llm_provider: Arc<dyn LLMProvider>,
        settings: Arc<Settings>,
    ) -> Self {
        let isolated_cache = Cache::builder()
            .max_capacity(settings.cache_max_capacity)
            .time_to_live(Duration::from_secs(settings.cache_ttl_secs))
            .build();

        Self {
            vector_store,
            llm_provider,
            settings,
            isolated_cache,
        }
    }

    pub async fn clear_cache(&self) {
        self.isolated_cache.invalidate_all();
        self.isolated_cache.run_pending_tasks().await;
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
            query_preview.trim().chars().take(60).collect()
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

    async fn fetch_recent_history(
        &self,
        pool: &SqlitePool,
        session_id: &str,
        user_id: &str,
        limit: i64,
    ) -> Vec<(String, String)> {
        let rows = sqlx::query_as::<_, ChatMessageRecord>(
            "SELECT * FROM chat_messages WHERE session_id = ? AND user_id = ? ORDER BY rowid DESC LIMIT ?",
        )
        .bind(session_id)
        .bind(user_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .unwrap_or_default();

        let mut history: Vec<(String, String)> =
            rows.into_iter().map(|r| (r.sender, r.content)).collect();
        history.reverse();
        history
    }

    #[allow(clippy::too_many_arguments)]
    async fn save_chat_turn(
        &self,
        pool: &SqlitePool,
        session_id: &str,
        user_id: &str,
        request_id: &str,
        question: &str,
        answer: &str,
        citations: &[CitationItem],
        classification: StatementClassification,
    ) -> Result<(), sqlx::Error> {
        let user_msg_id = format!("msg-{}", &Uuid::new_v4().simple().to_string()[..16]);
        let asst_msg_id = format!("msg-{}", &Uuid::new_v4().simple().to_string()[..16]);
        let now_str = chrono::Utc::now().to_rfc3339();
        let citations_json = serde_json::to_string(citations).unwrap_or_else(|_| "[]".to_string());

        sqlx::query(
            r#"
            INSERT INTO chat_messages (
                message_id, session_id, user_id, sender, content, citations_json,
                epistemic_classification, request_id, created_at
            ) VALUES (?, ?, ?, 'user', ?, '[]', NULL, ?, ?)
            "#,
        )
        .bind(&user_msg_id)
        .bind(session_id)
        .bind(user_id)
        .bind(question)
        .bind(request_id)
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
        .bind(session_id)
        .bind(user_id)
        .bind(answer)
        .bind(&citations_json)
        .bind(classification.as_str())
        .bind(request_id)
        .bind(&now_str)
        .execute(pool)
        .await?;

        Ok(())
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

    fn build_history_fingerprint(history: &[(String, String)]) -> String {
        if history.is_empty() {
            return String::new();
        }
        let mut hasher = Sha256::new();
        for (sender, content) in history {
            hasher.update(sender.as_bytes());
            hasher.update(b":");
            hasher.update(content.as_bytes());
            hasher.update(b"\n");
        }
        let full = hex::encode(hasher.finalize());
        full[..16].to_string()
    }

    fn build_effective_retrieval_query(question: &str, history: &[(String, String)]) -> String {
        let current_terms = expand_query_terms(question);
        if current_terms.len() < 2 {
            if let Some((_, prev_q)) = history.iter().rev().find(|(s, _)| s == "user") {
                return format!("{} {}", prev_q, question);
            }
        }
        question.to_string()
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

            let mut audit = AuditEventInput::minimal(
                &request_id,
                "RAG_QUERY",
                "CHAT_SESSION",
                "DENY",
                "BLOCKED_BY_INPUT_GUARDRAIL",
            );
            audit.principal = Some(principal);
            audit.resource_id = Some(&session_rec.session_id);
            audit.guardrail_decisions = &guardrail_decisions;
            audit.latency_ms = Some(latency_ms);
            audit.error_code = Some(&input_decision.rule_id);
            audit.metadata = Some(&meta);
            let _ = AuditLogger::record_event(pool, audit).await;

            let _ = self
                .save_chat_turn(
                    pool,
                    &session_rec.session_id,
                    &principal.user_id,
                    &request_id,
                    question,
                    UNIFORM_SAFE_REFUSAL_MESSAGE,
                    &[],
                    StatementClassification::InsufficientEvidence,
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
                    (
                        "status".to_string(),
                        serde_json::json!("BLOCKED_BY_INPUT_GUARDRAIL"),
                    ),
                    (
                        "rule_id".to_string(),
                        serde_json::json!(input_decision.rule_id),
                    ),
                ]
                .into_iter()
                .collect(),
            });
        }

        // Load recent multi-turn conversation history for this isolated session
        let conversation_history = self
            .fetch_recent_history(pool, &session_rec.session_id, &principal.user_id, 4)
            .await;
        let history_fp = Self::build_history_fingerprint(&conversation_history);

        // 4: Bounded Isolated Cache check (User + Role + Perms + Doc ACL Versions + History Context)
        let accessible_acls = self
            .get_accessible_doc_acl_versions(pool, principal)
            .await?;
        let cache_key = RBACPolicyEngine::build_isolated_cache_key_with_context(
            principal,
            question,
            &accessible_acls,
            &history_fp,
        );

        if use_cache {
            if let Some(cached) = self.isolated_cache.get(&cache_key).await {
                let latency_ms = start_time.elapsed().as_secs_f64() * 1000.0;
                let accessed_doc_ids: Vec<String> = cached
                    .citations
                    .iter()
                    .map(|c| c.document_id.clone())
                    .collect();

                // Persist user & assistant messages for the active session even on cache-hit
                self.save_chat_turn(
                    pool,
                    &session_rec.session_id,
                    &principal.user_id,
                    &request_id,
                    question,
                    &cached.answer,
                    &cached.citations,
                    cached.overall_classification,
                )
                .await?;

                let mut audit = AuditEventInput::minimal(
                    &request_id,
                    "RAG_QUERY_CACHE_HIT",
                    "CHAT_SESSION",
                    "ALLOW",
                    "COMPLETED_FROM_ISOLATED_CACHE",
                );
                audit.principal = Some(principal);
                audit.resource_id = Some(&session_rec.session_id);
                audit.guardrail_decisions = &cached.guardrail_decisions;
                audit.accessed_document_ids = &accessed_doc_ids;
                audit.latency_ms = Some(latency_ms);
                let _ = AuditLogger::record_event(pool, audit).await;

                let mut clone_resp = cached;
                clone_resp.request_id = request_id;
                clone_resp.session_id = session_rec.session_id;
                clone_resp
                    .metadata
                    .insert("cache_hit".to_string(), serde_json::json!(true));
                return Ok(clone_resp);
            }
        }

        // 5: Hybrid Pre-Retrieval Search (ACL-Filtered Vector Similarity + SQLite FTS5 BM25 + RRF)
        let effective_query =
            Self::build_effective_retrieval_query(question, &conversation_history);
        let query_vector = self
            .vector_store
            .embedding_provider
            .embed_query(&effective_query)
            .await?;

        let hits = self
            .vector_store
            .hybrid_search(
                pool,
                &effective_query,
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
        let verified_chunks =
            RBACPolicyEngine::verify_chunks_post_retrieval(pool, principal, &candidate_chunks)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

        // 7: Retrieval Guardrails (Neutralize Indirect Prompt Injection)
        let (sanitized_chunks, retrieval_decision) =
            GuardrailsEngine::sanitize_retrieved_chunks(verified_chunks);
        guardrail_decisions.push(retrieval_decision);

        // 8: Grounded LLM Generation (multi-provider trait + multi-turn context)
        let gen_result = self
            .llm_provider
            .generate_grounded_response(question, &sanitized_chunks, &conversation_history)
            .await;

        for tool_dec in gen_result.tool_guardrail_decisions {
            guardrail_decisions.push(tool_dec);
        }

        // 9a: Strict CitationValidator Enforcement
        let mut working_answer = gen_result.answer;
        let mut working_claims = gen_result.claims;
        let mut working_citations = gen_result.citations;
        let mut working_classification = gen_result.overall_classification;
        let mut pipeline_status = "COMPLETED".to_string();
        let mut error_code: Option<String> = None;
        let mut citation_failed = false;

        if let Err(cit_err) = CitationValidator::validate_citations_and_claims(
            &working_claims,
            &working_citations,
            &sanitized_chunks,
        ) {
            citation_failed = true;
            pipeline_status = "CITATION_VALIDATION_FAILED".to_string();
            error_code = Some("CIT-001".to_string());
            guardrail_decisions.push(GuardrailDecision {
                stage: GuardrailStage::Output,
                decision: GuardrailDecisionType::Block,
                rule_id: "CIT-001".to_string(),
                reason: format!("Validasi sitasi gagal: {}", cit_err),
                triggered_patterns: vec!["citation_validation_failed".to_string()],
            });

            working_answer = UNIFORM_INSUFFICIENT_EVIDENCE_MESSAGE.to_string();
            working_classification = StatementClassification::InsufficientEvidence;
            working_citations.clear();
            working_claims = vec![ClaimItem {
                statement: UNIFORM_INSUFFICIENT_EVIDENCE_MESSAGE.to_string(),
                classification: StatementClassification::InsufficientEvidence,
                supporting_chunk_ids: vec![],
                calculation_expression: None,
            }];
        }

        // 9b: Output Guardrails
        let (validated_answer, output_decision) =
            GuardrailsEngine::validate_output(&working_answer);
        guardrail_decisions.push(output_decision.clone());

        let output_allowed = output_decision.decision == GuardrailDecisionType::Allow;
        if !output_allowed {
            pipeline_status = "BLOCKED_BY_OUTPUT_GUARDRAIL".to_string();
            error_code = Some(output_decision.rule_id.clone());
        }

        let final_citations = if output_allowed && !citation_failed {
            working_citations
        } else {
            vec![]
        };

        let final_claims = if output_allowed {
            working_claims
        } else {
            vec![ClaimItem {
                statement: UNIFORM_SAFE_REFUSAL_MESSAGE.to_string(),
                classification: StatementClassification::InsufficientEvidence,
                supporting_chunk_ids: vec![],
                calculation_expression: None,
            }]
        };

        let final_classification = if output_allowed {
            working_classification
        } else {
            StatementClassification::InsufficientEvidence
        };

        // 10: Save chat messages to database
        self.save_chat_turn(
            pool,
            &session_rec.session_id,
            &principal.user_id,
            &request_id,
            question,
            &validated_answer,
            &final_citations,
            final_classification,
        )
        .await?;

        let latency_ms = start_time.elapsed().as_secs_f64() * 1000.0;
        let mut accessed_doc_ids: Vec<String> = final_citations
            .iter()
            .map(|c| c.document_id.clone())
            .collect();
        accessed_doc_ids.sort();
        accessed_doc_ids.dedup();

        let retrieval_scores: Vec<f32> =
            sanitized_chunks.iter().map(|c| c.relevance_score).collect();
        let retrieval_cfg_ver = format!(
            "hybrid_rrf|top_k={}|min_score={}|chunk={}",
            self.settings.retrieval_top_k,
            self.settings.min_relevance_score,
            self.settings.chunk_size_chars
        );

        let meta = serde_json::json!({
            "overall_classification": final_classification.as_str(),
            "has_source_conflict": gen_result.has_source_conflict && !citation_failed && output_allowed,
            "citation_count": final_citations.len(),
            "history_turns_used": conversation_history.len(),
        });

        let authz_dec = if output_allowed && !citation_failed {
            "ALLOW"
        } else {
            "DENY"
        };

        let mut audit = AuditEventInput::minimal(
            &request_id,
            "RAG_QUERY",
            "CHAT_SESSION",
            authz_dec,
            &pipeline_status,
        );
        audit.principal = Some(principal);
        audit.resource_id = Some(&session_rec.session_id);
        audit.guardrail_decisions = &guardrail_decisions;
        audit.accessed_document_ids = &accessed_doc_ids;
        audit.retrieval_scores = &retrieval_scores;
        audit.retrieval_config_version = Some(&retrieval_cfg_ver);
        audit.llm_provider = Some(&gen_result.provider_name);
        audit.llm_model = Some(&gen_result.model_name);
        audit.latency_ms = Some(latency_ms);
        audit.prompt_tokens = Some(gen_result.prompt_tokens);
        audit.completion_tokens = Some(gen_result.completion_tokens);
        audit.error_code = error_code.as_deref();
        audit.metadata = Some(&meta);
        let _ = AuditLogger::record_event(pool, audit).await;

        let response = RAGQueryResponse {
            request_id,
            session_id: session_rec.session_id,
            answer: validated_answer,
            overall_classification: final_classification,
            claims: final_claims,
            citations: final_citations,
            has_source_conflict: gen_result.has_source_conflict
                && !citation_failed
                && output_allowed,
            conflict_summary: if citation_failed || !output_allowed {
                None
            } else {
                gen_result.conflict_summary
            },
            guardrail_decisions,
            metadata: [
                ("status".to_string(), serde_json::json!(pipeline_status)),
                (
                    "latency_ms".to_string(),
                    serde_json::json!((latency_ms * 100.0).round() / 100.0),
                ),
                (
                    "llm_provider".to_string(),
                    serde_json::json!(gen_result.provider_name),
                ),
                (
                    "llm_model".to_string(),
                    serde_json::json!(gen_result.model_name),
                ),
                (
                    "retrieval_config_version".to_string(),
                    serde_json::json!(retrieval_cfg_ver),
                ),
                ("cache_hit".to_string(), serde_json::json!(false)),
            ]
            .into_iter()
            .collect(),
        };

        if use_cache && output_allowed && !citation_failed {
            self.isolated_cache
                .insert(cache_key, response.clone())
                .await;
        }

        Ok(response)
    }
}
