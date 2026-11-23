use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::collections::{HashMap, HashSet};

use crate::core::enums::{DocumentScope, IngestionStatus, SupportedFileType, UserRole};
use crate::db::models::{
    ChatSessionRecord, DocumentChunkRecord, DocumentRecord, RoleChangeAuditRecord, UserRecord,
};
use crate::schemas::architecture::{AuthenticatedPrincipal, ChunkProvenance, VerifiedChunkContext};

#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {
    #[error("Akses ditolak: identitas pengguna tidak aktif.")]
    InactiveUser,

    #[error("Akses ditolak: role '{0}' tidak diizinkan mengunggah dokumen pada scope '{1}'.")]
    UploadDenied(String, String),

    #[error("Akses ditolak atau dokumen tidak tersedia untuk peran Anda.")]
    DocumentReadDenied,

    #[error("Akses ditolak untuk mengubah ACL dokumen ini.")]
    DocumentAclUpdateDenied,

    #[error("Akses ditolak untuk menghapus dokumen ini.")]
    DocumentDeleteDenied,

    #[error("Akses ditolak: sesi percakapan tidak ditemukan atau milik pengguna lain.")]
    SessionAccessDenied,

    #[error("Akses ditolak: hanya Administrator atau pemegang izin policy:manage yang dapat mengubah role pengguna.")]
    NonAdminRoleChange,

    #[error("Pelanggaran keamanan: pengguna tidak diizinkan mengubah atau meningkatkan role/permission milik sendiri.")]
    SelfRoleChangeBlocked,

    #[error("Akses ditolak: hanya Administrator atau pemegang izin audit:read yang dapat melihat audit log.")]
    AuditAccessDenied,

    #[error("{0}")]
    Other(String),
}

pub struct RBACPolicyEngine;

impl RBACPolicyEngine {
    pub fn ensure_active(principal: &AuthenticatedPrincipal) -> Result<(), AuthorizationError> {
        if !principal.is_active {
            return Err(AuthorizationError::InactiveUser);
        }
        Ok(())
    }

    pub fn has_explicit_permission(principal: &AuthenticatedPrincipal, perm: &str) -> bool {
        principal.explicit_permissions.iter().any(|p| p == perm)
    }

    pub fn can_read_audit_logs(principal: &AuthenticatedPrincipal) -> bool {
        if Self::ensure_active(principal).is_err() {
            return false;
        }
        principal.role == UserRole::Admin || Self::has_explicit_permission(principal, "audit:read")
    }

    pub fn can_run_evaluation(principal: &AuthenticatedPrincipal) -> bool {
        if Self::ensure_active(principal).is_err() {
            return false;
        }
        principal.role == UserRole::Admin || Self::has_explicit_permission(principal, "eval:run")
    }

    pub fn can_manage_policies(principal: &AuthenticatedPrincipal) -> bool {
        if Self::ensure_active(principal).is_err() {
            return false;
        }
        principal.role == UserRole::Admin
            || Self::has_explicit_permission(principal, "policy:manage")
    }

    pub fn allowed_read_scopes(role: UserRole) -> HashSet<DocumentScope> {
        match role {
            UserRole::Employee => [DocumentScope::General].into_iter().collect(),
            UserRole::Hr => [DocumentScope::General, DocumentScope::Hr]
                .into_iter()
                .collect(),
            UserRole::Finance => [DocumentScope::General, DocumentScope::Finance]
                .into_iter()
                .collect(),
            UserRole::Executive => [
                DocumentScope::General,
                DocumentScope::Hr,
                DocumentScope::Finance,
                DocumentScope::Executive,
            ]
            .into_iter()
            .collect(),
            UserRole::Admin => HashSet::new(),
        }
    }

    pub fn allowed_upload_scopes(role: UserRole) -> HashSet<DocumentScope> {
        match role {
            UserRole::Employee => HashSet::new(),
            UserRole::Hr => [DocumentScope::General, DocumentScope::Hr]
                .into_iter()
                .collect(),
            UserRole::Finance => [DocumentScope::General, DocumentScope::Finance]
                .into_iter()
                .collect(),
            UserRole::Executive => [
                DocumentScope::General,
                DocumentScope::Hr,
                DocumentScope::Finance,
                DocumentScope::Executive,
            ]
            .into_iter()
            .collect(),
            UserRole::Admin => HashSet::new(),
        }
    }

    pub fn can_upload_to_scope(
        principal: &AuthenticatedPrincipal,
        target_scope: DocumentScope,
    ) -> bool {
        if Self::ensure_active(principal).is_err() {
            return false;
        }
        // Admin separation of duties: never uploads business documents unless granted explicit scope token
        let explicit_scope_token = format!("upload:{}", target_scope.as_str());
        if Self::has_explicit_permission(principal, &explicit_scope_token) {
            return true;
        }
        if principal.role == UserRole::Admin {
            return false;
        }
        let allowed = Self::allowed_upload_scopes(principal.role);
        if allowed.contains(&target_scope) {
            return true;
        }
        // Granular `doc:upload` grants upload capability for scopes the user is allowed to read
        if Self::has_explicit_permission(principal, "doc:upload") {
            let read_scopes = Self::allowed_read_scopes(principal.role);
            let read_scope_token = format!("read_scope:{}", target_scope.as_str());
            if read_scopes.contains(&target_scope)
                || Self::has_explicit_permission(principal, &read_scope_token)
            {
                return true;
            }
        }
        false
    }

    pub fn require_upload_permission(
        principal: &AuthenticatedPrincipal,
        target_scope: DocumentScope,
    ) -> Result<(), AuthorizationError> {
        if !Self::can_upload_to_scope(principal, target_scope) {
            return Err(AuthorizationError::UploadDenied(
                principal.role.as_str().to_string(),
                target_scope.as_str().to_string(),
            ));
        }
        Ok(())
    }

    pub fn can_read_document(principal: &AuthenticatedPrincipal, doc: &DocumentRecord) -> bool {
        if Self::ensure_active(principal).is_err() {
            return false;
        }
        if doc.ingestion_status != IngestionStatus::Indexed.as_str() {
            return false;
        }
        let doc_scope = match DocumentScope::from_str_opt(&doc.scope) {
            Some(s) => s,
            None => return false,
        };

        let allowed_users: HashSet<String> =
            serde_json::from_str(&doc.allowed_users).unwrap_or_default();
        let allowed_roles: HashSet<String> =
            serde_json::from_str(&doc.allowed_roles).unwrap_or_default();

        // Strict rule for Admin: no auto-read unless explicitly granted both allowed_users AND read_doc:<id>
        if principal.role == UserRole::Admin {
            let has_user_access = allowed_users.contains(&principal.user_id);
            let read_token = format!("read_doc:{}", doc.document_id);
            return has_user_access && Self::has_explicit_permission(principal, &read_token);
        }

        // Direct explicit document permission
        let read_doc_token = format!("read_doc:{}", doc.document_id);
        if allowed_users.contains(&principal.user_id)
            && Self::has_explicit_permission(principal, &read_doc_token)
        {
            return true;
        }

        // Direct user-level ACL grant within authorized scope
        if allowed_users.contains(&principal.user_id) {
            let role_scopes = Self::allowed_read_scopes(principal.role);
            let read_scope_token = format!("read_scope:{}", doc_scope.as_str());
            if role_scopes.contains(&doc_scope)
                || Self::has_explicit_permission(principal, &read_scope_token)
            {
                return true;
            }
        }

        // Role-level check (with optional explicit read_scope:<scope> expansion)
        let role_scopes = Self::allowed_read_scopes(principal.role);
        let read_scope_token = format!("read_scope:{}", doc_scope.as_str());
        (role_scopes.contains(&doc_scope)
            || Self::has_explicit_permission(principal, &read_scope_token))
            && allowed_roles.contains(principal.role.as_str())
    }

    pub fn require_document_read_access<'a>(
        principal: &AuthenticatedPrincipal,
        doc: Option<&'a DocumentRecord>,
    ) -> Result<&'a DocumentRecord, AuthorizationError> {
        match doc {
            Some(d) if Self::can_read_document(principal, d) => Ok(d),
            _ => Err(AuthorizationError::DocumentReadDenied),
        }
    }

    /// Strict document management/deletion authority:
    /// Restricted strictly to the document owner (`owner_user_id`), OR a non-admin user holding
    /// explicit `doc:delete` / `manage_doc:<id>` permission with scope access.
    pub fn can_manage_document(principal: &AuthenticatedPrincipal, doc: &DocumentRecord) -> bool {
        if Self::ensure_active(principal).is_err() {
            return false;
        }
        if principal.role == UserRole::Admin {
            return false;
        }
        let doc_scope = match DocumentScope::from_str_opt(&doc.scope) {
            Some(s) => s,
            None => return false,
        };

        // 1. Document owner can manage/delete their own document
        if doc.owner_user_id == principal.user_id {
            return true;
        }

        // 2. Explicit document-level manage token
        let manage_doc_token = format!("manage_doc:{}", doc.document_id);
        if Self::has_explicit_permission(principal, &manage_doc_token) {
            return true;
        }

        // 3. Explicit `doc:delete` permission within an authorized scope
        Self::has_explicit_permission(principal, "doc:delete")
            && (Self::can_upload_to_scope(principal, doc_scope)
                || Self::can_read_document(principal, doc))
    }

    /// Document ACL update authority:
    /// Document owner, OR non-admin with explicit `policy:manage`, `doc:delete`, or `manage_doc:<id>`
    /// who has scope access to the document.
    pub fn can_edit_document_acl(principal: &AuthenticatedPrincipal, doc: &DocumentRecord) -> bool {
        if Self::can_manage_document(principal, doc) {
            return true;
        }
        if Self::ensure_active(principal).is_err() || principal.role == UserRole::Admin {
            return false;
        }
        let doc_scope = match DocumentScope::from_str_opt(&doc.scope) {
            Some(s) => s,
            None => return false,
        };
        Self::has_explicit_permission(principal, "policy:manage")
            && (Self::can_upload_to_scope(principal, doc_scope)
                || Self::can_read_document(principal, doc))
    }

    pub fn require_session_ownership<'a>(
        principal: &AuthenticatedPrincipal,
        session: Option<&'a ChatSessionRecord>,
    ) -> Result<&'a ChatSessionRecord, AuthorizationError> {
        Self::ensure_active(principal)?;
        match session {
            Some(s) if s.user_id == principal.user_id => Ok(s),
            _ => Err(AuthorizationError::SessionAccessDenied),
        }
    }

    pub fn build_isolated_cache_key(
        principal: &AuthenticatedPrincipal,
        query_text: &str,
        accessible_doc_acl_versions: &HashMap<String, i64>,
    ) -> String {
        Self::build_isolated_cache_key_with_context(
            principal,
            query_text,
            accessible_doc_acl_versions,
            "",
        )
    }

    pub fn build_isolated_cache_key_with_context(
        principal: &AuthenticatedPrincipal,
        query_text: &str,
        accessible_doc_acl_versions: &HashMap<String, i64>,
        context_fingerprint: &str,
    ) -> String {
        let mut sorted_perms = principal.explicit_permissions.clone();
        sorted_perms.sort();
        let perms_str = sorted_perms.join(",");

        let mut acls_entries: Vec<String> = accessible_doc_acl_versions
            .iter()
            .map(|(id, ver)| format!("{}:v{}", id, ver))
            .collect();
        acls_entries.sort();
        let acls_str = acls_entries.join(",");

        let normalized_query = query_text
            .trim()
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let raw = format!(
            "uid={}|role={}|perms={}|acls={}|ctx={}|q={}",
            principal.user_id,
            principal.role.as_str(),
            perms_str,
            acls_str,
            context_fingerprint,
            normalized_query
        );

        let mut hasher = Sha256::new();
        hasher.update(raw.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub async fn verify_chunks_post_retrieval(
        pool: &SqlitePool,
        principal: &AuthenticatedPrincipal,
        candidate_chunks: &[(String, String, f32)],
    ) -> Result<Vec<VerifiedChunkContext>, sqlx::Error> {
        let mut verified = Vec::new();

        for (chunk_id, doc_id, score) in candidate_chunks {
            let doc = sqlx::query_as::<_, DocumentRecord>(
                "SELECT * FROM documents WHERE document_id = ?",
            )
            .bind(doc_id)
            .fetch_optional(pool)
            .await?;

            let doc = match doc {
                Some(d) if Self::can_read_document(principal, &d) => d,
                _ => continue,
            };

            let chunk_rec = sqlx::query_as::<_, DocumentChunkRecord>(
                "SELECT * FROM document_chunks WHERE chunk_id = ? AND document_id = ?",
            )
            .bind(chunk_id)
            .bind(&doc.document_id)
            .fetch_optional(pool)
            .await?;

            let chunk_rec = match chunk_rec {
                Some(c) => c,
                None => continue,
            };

            let file_type =
                SupportedFileType::from_str_opt(&doc.file_type).unwrap_or(SupportedFileType::Pdf);

            let provenance = ChunkProvenance {
                document_id: doc.document_id.clone(),
                title: doc.title.clone(),
                source_filename: doc.source_filename.clone(),
                file_type,
                chunk_id: chunk_rec.chunk_id.clone(),
                chunk_index: chunk_rec.chunk_index,
                page_number: chunk_rec.page_number,
                sheet_name: chunk_rec.sheet_name,
                row_start: chunk_rec.row_start,
                row_end: chunk_rec.row_end,
                section_label: chunk_rec.section_label,
            };

            verified.push(VerifiedChunkContext {
                chunk_id: chunk_rec.chunk_id,
                document_id: doc.document_id,
                text_content: chunk_rec.text_content,
                relevance_score: *score,
                provenance,
                acl_verified_at: chrono::Utc::now(),
            });
        }

        Ok(verified)
    }

    pub async fn change_user_role_and_permissions(
        pool: &SqlitePool,
        actor: &AuthenticatedPrincipal,
        target_user_id: &str,
        new_role: UserRole,
        new_permissions: &[String],
        reason: &str,
    ) -> Result<RoleChangeAuditRecord, AuthorizationError> {
        Self::ensure_active(actor)?;
        if !Self::can_manage_policies(actor) {
            return Err(AuthorizationError::NonAdminRoleChange);
        }
        if actor.user_id == target_user_id {
            return Err(AuthorizationError::SelfRoleChangeBlocked);
        }
        if reason.trim().len() < 5 {
            return Err(AuthorizationError::Other(
                "Alasan perubahan role wajib diisi minimal 5 karakter untuk keperluan audit."
                    .to_string(),
            ));
        }

        let target_user = sqlx::query_as::<_, UserRecord>("SELECT * FROM users WHERE id = ?")
            .bind(target_user_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| AuthorizationError::Other(e.to_string()))?
            .ok_or_else(|| {
                AuthorizationError::Other("Pengguna target tidak ditemukan.".to_string())
            })?;

        let prev_role = target_user.role;
        let prev_perms = target_user.explicit_permissions;
        let new_perms_json =
            serde_json::to_string(new_permissions).unwrap_or_else(|_| "[]".to_string());

        let now_str = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "UPDATE users SET role = ?, explicit_permissions = ?, updated_at = ? WHERE id = ?",
        )
        .bind(new_role.as_str())
        .bind(&new_perms_json)
        .bind(&now_str)
        .bind(target_user_id)
        .execute(pool)
        .await
        .map_err(|e| AuthorizationError::Other(e.to_string()))?;

        let audit_res = sqlx::query(
            r#"
            INSERT INTO role_change_audits (
                actor_user_id, target_user_id, previous_role, new_role,
                previous_permissions, new_permissions, reason, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&actor.user_id)
        .bind(target_user_id)
        .bind(&prev_role)
        .bind(new_role.as_str())
        .bind(&prev_perms)
        .bind(&new_perms_json)
        .bind(reason.trim())
        .bind(&now_str)
        .execute(pool)
        .await
        .map_err(|e| AuthorizationError::Other(e.to_string()))?;

        let audit_id = audit_res.last_insert_rowid();

        Ok(RoleChangeAuditRecord {
            id: audit_id,
            actor_user_id: actor.user_id.clone(),
            target_user_id: target_user_id.to_string(),
            previous_role: prev_role,
            new_role: new_role.as_str().to_string(),
            previous_permissions: prev_perms,
            new_permissions: new_perms_json,
            reason: reason.trim().to_string(),
            created_at: now_str,
        })
    }
}
