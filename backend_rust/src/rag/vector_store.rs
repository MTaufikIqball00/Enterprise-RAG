use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::core::enums::{IngestionStatus, UserRole};
use crate::rag::embeddings::LocalDeterministicEmbeddingProvider;
use crate::schemas::architecture::AuthenticatedPrincipal;
use crate::security::rbac::RBACPolicyEngine;

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
    pub embedding_provider: Arc<LocalDeterministicEmbeddingProvider>,
}

fn cosine_similarity(v1: &[f32], v2: &[f32]) -> f32 {
    let dot: f32 = v1.iter().zip(v2.iter()).map(|(a, b)| a * b).sum();
    // Since vectors are L2-normalized in embedding provider, dot product equals cosine similarity
    dot
}

impl VectorStore {
    pub fn new(embedding_provider: Arc<LocalDeterministicEmbeddingProvider>) -> Self {
        Self {
            points: Arc::new(RwLock::new(HashMap::new())),
            embedding_provider,
        }
    }

    pub async fn upsert_points(&self, new_points: Vec<VectorPoint>) {
        let mut store = self.points.write().await;
        for pt in new_points {
            store.insert(pt.chunk_id.clone(), pt);
        }
    }

    pub async fn delete_by_document_id(&self, document_id: &str) {
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
        let mut store = self.points.write().await;
        for pt in store.values_mut() {
            if pt.document_id == document_id {
                pt.allowed_roles = allowed_roles.clone();
                pt.allowed_users = allowed_users.clone();
                pt.acl_version = acl_version;
            }
        }
    }

    pub async fn search(
        &self,
        query_vector: &[f32],
        principal: &AuthenticatedPrincipal,
        top_k: usize,
        min_relevance_score: f32,
    ) -> Vec<SearchHit> {
        let store = self.points.read().await;

        // Stage 3 & 5: Pre-retrieval authorization filter
        let mut hits = Vec::new();

        if principal.role == UserRole::Admin {
            let explicit_doc_ids: HashSet<String> = principal
                .explicit_permissions
                .iter()
                .filter(|p| p.starts_with("read_doc:"))
                .map(|p| p.trim_start_matches("read_doc:").to_string())
                .collect();

            if explicit_doc_ids.is_empty() {
                // Admin has NO access to any business document by default!
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

            for perm in &principal.explicit_permissions {
                if let Some(scope_name) = perm.strip_prefix("read_scope:") {
                    allowed_scope_names.insert(scope_name.to_string());
                }
            }

            for pt in store.values() {
                if pt.ingestion_status != IngestionStatus::Indexed.as_str() {
                    continue;
                }
                if !allowed_scope_names.contains(&pt.scope) {
                    continue;
                }
                let has_role = pt.allowed_roles.contains(&principal.role.as_str().to_string());
                let has_user = pt.allowed_users.contains(&principal.user_id);
                if !has_role && !has_user {
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
        }

        hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        hits.truncate(top_k);
        hits
    }
}
