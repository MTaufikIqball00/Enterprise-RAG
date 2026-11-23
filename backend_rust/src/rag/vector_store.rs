use regex::Regex;
use sqlx::SqlitePool;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};
use tokio::sync::RwLock;
use tracing::warn;

use crate::core::enums::{IngestionStatus, UserRole};
use crate::db::models::DocumentRecord;
use crate::rag::embeddings::EmbeddingProvider;
use crate::schemas::architecture::AuthenticatedPrincipal;
use crate::security::rbac::RBACPolicyEngine;

static FTS_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[a-zA-Z0-9_]{2,}").unwrap());

#[derive(Debug, Clone)]
pub struct VectorPoint {
    pub chunk_id: String,
    pub document_id: String,
    pub title: String,
    pub source_filename: String,
    pub file_type: String,
    pub scope: String,
    pub allowed_roles: Vec<String>,
    pub allowed_users: Vec<String>,
    pub acl_version: i64,
    pub version: i64,
    pub ingestion_status: String,
    pub page_number: Option<i64>,
    pub sheet_name: Option<String>,
    pub row_start: Option<i64>,
    pub row_end: Option<i64>,
    pub section_label: Option<String>,
    pub has_potential_injection: bool,
    pub vector: Vec<f32>,
}

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub chunk_id: String,
    pub document_id: String,
    pub score: f32,
}

#[derive(Clone)]
pub struct VectorStore {
    points: Arc<RwLock<HashMap<String, VectorPoint>>>,
    pub embedding_provider: Arc<dyn EmbeddingProvider>,
    qdrant_url: Option<String>,
    qdrant_collection: String,
    http_client: reqwest::Client,
}

fn cosine_similarity(v1: &[f32], v2: &[f32]) -> f32 {
    if v1.len() != v2.len() || v1.is_empty() {
        return 0.0;
    }
    v1.iter().zip(v2.iter()).map(|(a, b)| a * b).sum()
}

fn build_safe_fts5_query(raw_query: &str) -> Option<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut seen = HashSet::new();

    for m in FTS_TOKEN_RE.find_iter(raw_query) {
        let tok = m.as_str().to_lowercase();
        if ["and", "or", "not", "near"].contains(&tok.as_str()) {
            continue;
        }
        if seen.insert(tok.clone()) {
            tokens.push(format!("\"{}\"", tok));
        }
        // Also split snake_case into sub-tokens for better BM25 recall
        if tok.contains('_') {
            for sub in tok.split('_').filter(|s| s.len() >= 2) {
                if !["and", "or", "not", "near"].contains(&sub) && seen.insert(sub.to_string()) {
                    tokens.push(format!("\"{}\"", sub));
                }
            }
        }
    }

    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(" OR "))
    }
}

impl VectorStore {
    pub fn new(embedding_provider: Arc<dyn EmbeddingProvider>) -> Self {
        Self::with_qdrant(embedding_provider, None, "enterprise_documents".to_string())
    }

    pub fn with_qdrant(
        embedding_provider: Arc<dyn EmbeddingProvider>,
        qdrant_url: Option<String>,
        qdrant_collection: String,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self {
            points: Arc::new(RwLock::new(HashMap::new())),
            embedding_provider,
            qdrant_url,
            qdrant_collection,
            http_client,
        }
    }

    pub async fn upsert_points(&self, new_points: Vec<VectorPoint>) {
        if let Some(ref base_url) = self.qdrant_url {
            let qdrant_points: Vec<serde_json::Value> = new_points
                .iter()
                .map(|pt| {
                    let point_uuid =
                        uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, pt.chunk_id.as_bytes())
                            .to_string();
                    serde_json::json!({
                        "id": point_uuid,
                        "vector": pt.vector,
                        "payload": {
                            "chunk_id": pt.chunk_id,
                            "document_id": pt.document_id,
                            "scope": pt.scope,
                            "allowed_roles": pt.allowed_roles,
                            "allowed_users": pt.allowed_users,
                            "acl_version": pt.acl_version,
                            "ingestion_status": pt.ingestion_status,
                        }
                    })
                })
                .collect();

            let url = format!(
                "{}/collections/{}/points?wait=true",
                base_url.trim_end_matches('/'),
                self.qdrant_collection
            );
            if let Err(e) = self
                .http_client
                .put(&url)
                .json(&serde_json::json!({ "points": qdrant_points }))
                .send()
                .await
            {
                warn!(
                    "Qdrant external upsert gagal (tetap tersinkron di SQLite): {}",
                    e
                );
            }
        }

        let mut store = self.points.write().await;
        for pt in new_points {
            store.insert(pt.chunk_id.clone(), pt);
        }
    }

    pub async fn delete_by_document_id(&self, document_id: &str) {
        if let Some(ref base_url) = self.qdrant_url {
            let url = format!(
                "{}/collections/{}/points/delete?wait=true",
                base_url.trim_end_matches('/'),
                self.qdrant_collection
            );
            let body = serde_json::json!({
                "filter": {
                    "must": [
                        { "key": "document_id", "match": { "value": document_id } }
                    ]
                }
            });
            if let Err(e) = self.http_client.post(&url).json(&body).send().await {
                warn!("Qdrant external delete gagal: {}", e);
            }
        }

        let mut store = self.points.write().await;
        store.retain(|_, pt| pt.document_id != document_id);
    }

    pub async fn update_document_acl(
        &self,
        document_id: &str,
        allowed_roles: Vec<String>,
        allowed_users: Vec<String>,
        acl_version: i64,
    ) {
        if let Some(ref base_url) = self.qdrant_url {
            let url = format!(
                "{}/collections/{}/points/payload?wait=true",
                base_url.trim_end_matches('/'),
                self.qdrant_collection
            );
            let body = serde_json::json!({
                "payload": {
                    "allowed_roles": allowed_roles,
                    "allowed_users": allowed_users,
                    "acl_version": acl_version,
                },
                "filter": {
                    "must": [
                        { "key": "document_id", "match": { "value": document_id } }
                    ]
                }
            });
            if let Err(e) = self.http_client.post(&url).json(&body).send().await {
                warn!("Qdrant external ACL update gagal: {}", e);
            }
        }

        let mut store = self.points.write().await;
        for pt in store.values_mut() {
            if pt.document_id == document_id {
                pt.allowed_roles = allowed_roles.clone();
                pt.allowed_users = allowed_users.clone();
                pt.acl_version = acl_version;
            }
        }
    }

    /// Pre-Retrieval ACL-filtered vector similarity search.
    pub async fn search(
        &self,
        query_vector: &[f32],
        principal: &AuthenticatedPrincipal,
        top_k: usize,
        min_relevance_score: f32,
    ) -> Vec<SearchHit> {
        let store = self.points.read().await;
        let mut hits = Vec::new();

        if principal.role == UserRole::Admin {
            let explicit_doc_ids: HashSet<String> = principal
                .explicit_permissions
                .iter()
                .filter_map(|p| p.strip_prefix("read_doc:").map(|s| s.to_string()))
                .collect();

            if explicit_doc_ids.is_empty() {
                // Admin has NO access to any business document by default
                return Vec::new();
            }

            for pt in store.values() {
                if pt.ingestion_status != IngestionStatus::Indexed.as_str() {
                    continue;
                }
                if !explicit_doc_ids.contains(&pt.document_id) {
                    continue;
                }
                if !pt.allowed_users.contains(&principal.user_id) {
                    continue;
                }
                let score = cosine_similarity(query_vector, &pt.vector);
                if score >= min_relevance_score {
                    hits.push(SearchHit {
                        chunk_id: pt.chunk_id.clone(),
                        document_id: pt.document_id.clone(),
                        score,
                    });
                }
            }
        } else {
            let allowed_scopes_set = RBACPolicyEngine::allowed_read_scopes(principal.role);
            let mut allowed_scope_names: HashSet<String> = allowed_scopes_set
                .into_iter()
                .map(|s| s.as_str().to_string())
                .collect();

            let explicit_doc_ids: HashSet<String> = principal
                .explicit_permissions
                .iter()
                .filter_map(|p| p.strip_prefix("read_doc:").map(|s| s.to_string()))
                .collect();

            for perm in &principal.explicit_permissions {
                if let Some(scope_name) = perm.strip_prefix("read_scope:") {
                    allowed_scope_names.insert(scope_name.to_string());
                }
            }

            for pt in store.values() {
                if pt.ingestion_status != IngestionStatus::Indexed.as_str() {
                    continue;
                }
                let has_user = pt.allowed_users.contains(&principal.user_id);
                let direct_doc_grant = has_user && explicit_doc_ids.contains(&pt.document_id);

                if !direct_doc_grant {
                    if !allowed_scope_names.contains(&pt.scope) {
                        continue;
                    }
                    let has_role = pt
                        .allowed_roles
                        .contains(&principal.role.as_str().to_string());
                    if !has_role && !has_user {
                        continue;
                    }
                }

                let score = cosine_similarity(query_vector, &pt.vector);
                if score >= min_relevance_score {
                    hits.push(SearchHit {
                        chunk_id: pt.chunk_id.clone(),
                        document_id: pt.document_id.clone(),
                        score,
                    });
                }
            }
        }

        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        hits.truncate(top_k);
        hits
    }

    /// Hybrid Search combining ACL-filtered Vector Similarity + SQLite FTS5 BM25
    /// merged via Reciprocal Rank Fusion (RRF, k=60) with strict Pre-Retrieval ACL.
    pub async fn hybrid_search(
        &self,
        pool: &SqlitePool,
        query_text: &str,
        query_vector: &[f32],
        principal: &AuthenticatedPrincipal,
        top_k: usize,
        min_relevance_score: f32,
    ) -> Vec<SearchHit> {
        let candidate_limit = (top_k * 3).max(15);

        // 1. Vector similarity candidates (Pre-Retrieval ACL enforced)
        let vec_hits = self
            .search(
                query_vector,
                principal,
                candidate_limit,
                min_relevance_score,
            )
            .await;

        // 2. SQLite FTS5 BM25 candidates (Pre-Retrieval ACL enforced via DocumentRecord check)
        let mut fts_hits: Vec<SearchHit> = Vec::new();
        if let Some(fts_query) = build_safe_fts5_query(query_text) {
            // Pre-compute authorized document IDs for this principal
            let indexed_docs = sqlx::query_as::<_, DocumentRecord>(
                "SELECT * FROM documents WHERE ingestion_status = 'INDEXED'",
            )
            .fetch_all(pool)
            .await
            .unwrap_or_default();

            let authorized_doc_ids: HashSet<String> = indexed_docs
                .into_iter()
                .filter(|d| RBACPolicyEngine::can_read_document(principal, d))
                .map(|d| d.document_id)
                .collect();

            if !authorized_doc_ids.is_empty() {
                #[derive(sqlx::FromRow)]
                struct FtsRow {
                    chunk_id: String,
                    document_id: String,
                    bm25_score: f64,
                }

                let rows: Vec<FtsRow> = sqlx::query_as(
                    r#"
                    SELECT chunk_id, document_id, bm25(document_chunks_fts) AS bm25_score
                    FROM document_chunks_fts
                    WHERE document_chunks_fts MATCH ?
                    ORDER BY bm25_score ASC
                    LIMIT ?
                    "#,
                )
                .bind(&fts_query)
                .bind((candidate_limit * 2) as i64)
                .fetch_all(pool)
                .await
                .unwrap_or_default();

                for row in rows {
                    if authorized_doc_ids.contains(&row.document_id) {
                        // bm25 in SQLite FTS5 is more negative for better matches; convert to positive rank score
                        let norm_bm25 = (-row.bm25_score).max(0.01) as f32;
                        fts_hits.push(SearchHit {
                            chunk_id: row.chunk_id,
                            document_id: row.document_id,
                            score: norm_bm25,
                        });
                        if fts_hits.len() >= candidate_limit {
                            break;
                        }
                    }
                }
            }
        }

        // 3. Reciprocal Rank Fusion (RRF, k = 60.0)
        const RRF_K: f32 = 60.0;
        let mut fused: HashMap<String, (String, f32, f32)> = HashMap::new(); // chunk_id -> (doc_id, rrf_score, vec_score)

        for (rank, hit) in vec_hits.into_iter().enumerate() {
            let rrf_contrib = 1.0 / (RRF_K + (rank as f32) + 1.0);
            fused
                .entry(hit.chunk_id)
                .and_modify(|e| {
                    e.1 += rrf_contrib;
                    e.2 = e.2.max(hit.score);
                })
                .or_insert((hit.document_id, rrf_contrib, hit.score));
        }

        for (rank, hit) in fts_hits.into_iter().enumerate() {
            let rrf_contrib = 1.0 / (RRF_K + (rank as f32) + 1.0);
            fused
                .entry(hit.chunk_id)
                .and_modify(|e| {
                    e.1 += rrf_contrib;
                })
                .or_insert((hit.document_id, rrf_contrib, 0.0));
        }

        let mut results: Vec<SearchHit> = fused
            .into_iter()
            .map(
                |(chunk_id, (document_id, rrf_score, _vec_score))| SearchHit {
                    chunk_id,
                    document_id,
                    score: rrf_score,
                },
            )
            .collect();

        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results.truncate(top_k);
        results
    }
}
