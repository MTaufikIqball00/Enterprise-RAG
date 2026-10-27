use std::path::PathBuf;
use std::sync::Arc;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::core::config::Settings;
use crate::core::enums::{DocumentScope, IngestionStatus, UserRole};
use crate::db::models::DocumentRecord;
use crate::ingestion::chunker::chunk_parsed_segments;
use crate::ingestion::parsers::parse_document_bytes;
use crate::rag::vector_store::{VectorPoint, VectorStore};
use crate::schemas::architecture::AuthenticatedPrincipal;
use crate::security::rbac::RBACPolicyEngine;

pub struct DocumentIngestionService {
    pub vector_store: VectorStore,
    pub settings: Arc<Settings>,
}

impl DocumentIngestionService {
    pub fn new(vector_store: VectorStore, settings: Arc<Settings>) -> Self {
        Self {
            vector_store,
            settings,
        }
    }

    pub async fn ingest_document(
        &self,
        pool: &SqlitePool,
        principal: &AuthenticatedPrincipal,
        title: &str,
        filename: &str,
        raw_bytes: &[u8],
        scope: DocumentScope,
        allowed_roles: &[UserRole],
        allowed_users: &[String],
        version: i64,
    ) -> Result<DocumentRecord, anyhow::Error> {
        // 1. Verify uploader permission for target scope (Deny-by-default)
        RBACPolicyEngine::require_upload_permission(principal, scope)?;

        // Ensure admin role is never silently injected into allowed_roles
        let mut normalized_roles: Vec<String> = allowed_roles
            .iter()
            .filter(|&&r| r != UserRole::Admin)
            .map(|r| r.as_str().to_string())
            .collect();
        normalized_roles.sort();
        normalized_roles.dedup();

        if normalized_roles.is_empty() {
            return Err(anyhow::anyhow!(
                "Document ACL harus menyertakan minimal satu role non-admin yang diizinkan."
            ));
        }

        let mut normalized_users: Vec<String> = allowed_users.to_vec();
        normalized_users.sort();
        normalized_users.dedup();

        // 2. Idempotency check via SHA-256
        let mut hasher = Sha256::new();
        hasher.update(raw_bytes);
        let content_sha256 = hex::encode(hasher.finalize());

        let existing_doc = sqlx::query_as::<_, DocumentRecord>(
            "SELECT * FROM documents WHERE content_sha256 = ? AND scope = ? AND version = ?",
        )
        .bind(&content_sha256)
        .bind(scope.as_str())
        .bind(version)
        .fetch_optional(pool)
        .await?;

        if let Some(doc) = &existing_doc {
            if doc.ingestion_status == IngestionStatus::Indexed.as_str() {
                return Ok(doc.clone());
            }
        }

        // 3. Create or reuse document record in PROCESSING state
        let doc_id = existing_doc
            .as_ref()
            .map(|d| d.document_id.clone())
            .unwrap_or_else(|| format!("doc-{}", &Uuid::new_v4().simple().to_string()[..16]));

        let storage_dir = PathBuf::from(&self.settings.raw_document_storage_path);
        let _ = tokio::fs::create_dir_all(&storage_dir).await;
        let safe_filename = PathBuf::from(filename)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "uploaded_file".to_string());
        let storage_path = storage_dir.join(format!("{}_{}", doc_id, safe_filename));

        let now_str = chrono::Utc::now().to_rfc3339();
        let allowed_roles_json = serde_json::to_string(&normalized_roles)?;
        let allowed_users_json = serde_json::to_string(&normalized_users)?;

        let doc_title = if title.trim().is_empty() {
            &safe_filename
        } else {
            title.trim()
        };

        let file_type_str = PathBuf::from(&safe_filename)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("unknown")
            .to_lowercase();

        if existing_doc.is_none() {
            sqlx::query(
                r#"
                INSERT INTO documents (
                    document_id, title, source_filename, file_type, file_size_bytes,
                    content_sha256, owner_user_id, scope, allowed_roles, allowed_users,
                    version, acl_version, ingestion_status, chunk_count, storage_path,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'PROCESSING', 0, ?, ?, ?)
                "#,
            )
            .bind(&doc_id)
            .bind(doc_title)
            .bind(&safe_filename)
            .bind(&file_type_str)
            .bind(raw_bytes.len() as i64)
            .bind(&content_sha256)
            .bind(&principal.user_id)
            .bind(scope.as_str())
            .bind(&allowed_roles_json)
            .bind(&allowed_users_json)
            .bind(version)
            .bind(storage_path.to_str())
            .bind(&now_str)
            .bind(&now_str)
            .execute(pool)
            .await?;
        } else {
            sqlx::query(
                r#"
                UPDATE documents SET
                    ingestion_status = 'PROCESSING',
                    ingestion_error = NULL,
                    allowed_roles = ?,
                    allowed_users = ?,
                    updated_at = ?
                WHERE document_id = ?
                "#,
            )
            .bind(&allowed_roles_json)
            .bind(&allowed_users_json)
            .bind(&now_str)
            .bind(&doc_id)
            .execute(pool)
            .await?;
        }

        // 4. Parse, chunk, embed, and index
        match parse_document_bytes(&safe_filename, raw_bytes, self.settings.max_upload_size_bytes) {
            Ok((parsed_file_type, parsed_segments)) => {
                let chunk_candidates = chunk_parsed_segments(
                    &parsed_segments,
                    self.settings.chunk_size_chars,
                    self.settings.chunk_overlap_chars,
                )
                .map_err(|e| anyhow::anyhow!(e))?;

                if chunk_candidates.is_empty() {
                    let err_msg = "Tidak ada potongan teks (chunk) valid yang dihasilkan dari dokumen.";
                    self.mark_failed(pool, &doc_id, err_msg).await?;
                    return Err(anyhow::anyhow!(err_msg));
                }

                // Write raw file to disk
                tokio::fs::write(&storage_path, raw_bytes).await?;

                // Delete any old chunks for this document
                sqlx::query("DELETE FROM document_chunks WHERE document_id = ?")
                    .bind(&doc_id)
                    .execute(pool)
                    .await?;

                // Embed all chunk texts
                let chunk_texts: Vec<String> = chunk_candidates.iter().map(|c| c.text_content.clone()).collect();
                let vectors = self.vector_store.embedding_provider.embed_texts(&chunk_texts);

                let mut vector_points = Vec::new();

                for (candidate, vector) in chunk_candidates.iter().zip(vectors.into_iter()) {
                    let chunk_id = format!("{}-chk-{:04}", doc_id, candidate.chunk_index);

                    sqlx::query(
                        r#"
                        INSERT INTO document_chunks (
                            chunk_id, document_id, chunk_index, text_content, content_sha256,
                            page_number, sheet_name, row_start, row_end, section_label,
                            has_potential_injection, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        "#,
                    )
                    .bind(&chunk_id)
                    .bind(&doc_id)
                    .bind(candidate.chunk_index)
                    .bind(&candidate.text_content)
                    .bind(&candidate.content_sha256)
                    .bind(candidate.page_number)
                    .bind(&candidate.sheet_name)
                    .bind(candidate.row_start)
                    .bind(candidate.row_end)
                    .bind(&candidate.section_label)
                    .bind(candidate.has_potential_injection)
                    .bind(&now_str)
                    .execute(pool)
                    .await?;

                    vector_points.push(VectorPoint {
                        chunk_id,
                        document_id: doc_id.clone(),
                        title: doc_title.to_string(),
                        source_filename: safe_filename.clone(),
                        file_type: parsed_file_type.as_str().to_string(),
                        scope: scope.as_str().to_string(),
                        allowed_roles: normalized_roles.clone(),
                        allowed_users: normalized_users.clone(),
                        acl_version: 1,
                        version,
                        ingestion_status: IngestionStatus::Indexed.as_str().to_string(),
                        page_number: candidate.page_number,
                        sheet_name: candidate.sheet_name.clone(),
                        row_start: candidate.row_start,
                        row_end: candidate.row_end,
                        section_label: candidate.section_label.clone(),
                        has_potential_injection: candidate.has_potential_injection,
                        vector,
                    });
                }

                // Upsert to in-memory/retrieval vector index
                self.vector_store.upsert_points(vector_points).await;

                // Update document to INDEXED status
                sqlx::query(
                    r#"
                    UPDATE documents SET
                        file_type = ?,
                        chunk_count = ?,
                        ingestion_status = 'INDEXED',
                        ingestion_error = NULL,
                        updated_at = ?
                    WHERE document_id = ?
                    "#,
                )
                .bind(parsed_file_type.as_str())
                .bind(chunk_candidates.len() as i64)
                .bind(&now_str)
                .bind(&doc_id)
                .execute(pool)
                .await?;

                let doc = sqlx::query_as::<_, DocumentRecord>(
                    "SELECT * FROM documents WHERE document_id = ?",
                )
                .bind(&doc_id)
                .fetch_one(pool)
                .await?;

                Ok(doc)
            }
            Err(e) => {
                let err_msg = e.to_string();
                self.mark_failed(pool, &doc_id, &err_msg).await?;
                Err(anyhow::anyhow!(err_msg))
            }
        }
    }

    async fn mark_failed(&self, pool: &SqlitePool, doc_id: &str, error_msg: &str) -> Result<(), sqlx::Error> {
        let now_str = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            "UPDATE documents SET ingestion_status = 'FAILED', ingestion_error = ?, updated_at = ? WHERE document_id = ?",
        )
        .bind(error_msg)
        .bind(&now_str)
        .bind(doc_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn update_document_acl(
        &self,
        pool: &SqlitePool,
        principal: &AuthenticatedPrincipal,
        document_id: &str,
        allowed_roles: &[UserRole],
        allowed_users: &[String],
    ) -> Result<DocumentRecord, anyhow::Error> {
        let doc = sqlx::query_as::<_, DocumentRecord>(
            "SELECT * FROM documents WHERE document_id = ?",
        )
        .bind(document_id)
        .fetch_optional(pool)
        .await?;

        let doc = match doc {
            Some(d) if RBACPolicyEngine::can_manage_document(principal, &d) => d,
            _ => return Err(anyhow::anyhow!("Akses ditolak untuk mengubah ACL dokumen ini.")),
        };

        let mut normalized_roles: Vec<String> = allowed_roles
            .iter()
            .filter(|&&r| r != UserRole::Admin)
            .map(|r| r.as_str().to_string())
            .collect();
        normalized_roles.sort();
        normalized_roles.dedup();

        let mut normalized_users: Vec<String> = allowed_users.to_vec();
        normalized_users.sort();
        normalized_users.dedup();

        let new_acl_version = doc.acl_version + 1;
        let roles_json = serde_json::to_string(&normalized_roles)?;
        let users_json = serde_json::to_string(&normalized_users)?;
        let now_str = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "UPDATE documents SET allowed_roles = ?, allowed_users = ?, acl_version = ?, updated_at = ? WHERE document_id = ?",
        )
        .bind(&roles_json)
        .bind(&users_json)
        .bind(new_acl_version)
        .bind(&now_str)
        .bind(document_id)
        .execute(pool)
        .await?;

        self.vector_store
            .update_document_acl(document_id, normalized_roles, normalized_users, new_acl_version)
            .await;

        let updated_doc = sqlx::query_as::<_, DocumentRecord>(
            "SELECT * FROM documents WHERE document_id = ?",
        )
        .bind(document_id)
        .fetch_one(pool)
        .await?;

        Ok(updated_doc)
    }

    pub async fn delete_document(
        &self,
        pool: &SqlitePool,
        principal: &AuthenticatedPrincipal,
        document_id: &str,
    ) -> Result<DocumentRecord, anyhow::Error> {
        let doc = sqlx::query_as::<_, DocumentRecord>(
            "SELECT * FROM documents WHERE document_id = ?",
        )
        .bind(document_id)
        .fetch_optional(pool)
        .await?;

        let doc = match doc {
            Some(d) if RBACPolicyEngine::can_manage_document(principal, &d) => d,
            _ => return Err(anyhow::anyhow!("Akses ditolak untuk menghapus dokumen ini.")),
        };

        // 1. Remove from vector index
        self.vector_store.delete_by_document_id(document_id).await;

        // 2. Delete chunks from SQLite and mark document as DELETED
        sqlx::query("DELETE FROM document_chunks WHERE document_id = ?")
            .bind(document_id)
            .execute(pool)
            .await?;

        let new_acl_version = doc.acl_version + 1;
        let now_str = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "UPDATE documents SET ingestion_status = 'DELETED', chunk_count = 0, acl_version = ?, updated_at = ? WHERE document_id = ?",
        )
        .bind(new_acl_version)
        .bind(&now_str)
        .bind(document_id)
        .execute(pool)
        .await?;

        // 3. Remove physical file if exists
        if let Some(path_str) = &doc.storage_path {
            let path = PathBuf::from(path_str);
            if path.exists() {
                let _ = tokio::fs::remove_file(path).await;
            }
        }

        let updated = sqlx::query_as::<_, DocumentRecord>(
            "SELECT * FROM documents WHERE document_id = ?",
        )
        .bind(document_id)
        .fetch_one(pool)
        .await?;

        Ok(updated)
    }
}
