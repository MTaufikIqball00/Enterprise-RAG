use axum::response::{Html, IntoResponse};
use axum::Json;
use utoipa::OpenApi;

use crate::api::routes::{
    AuthConfigResponse, ChatQueryRequest, CreateUserRequest, DocumentAclUpdateRequest,
    LoginRequest, RoleUpdateRequest, TokenResponse, UserStatusUpdateRequest,
};
use crate::core::enums::{
    DocumentScope, GuardrailDecisionType, GuardrailStage, IngestionStatus, StatementClassification,
    SupportedFileType, UserRole,
};
use crate::schemas::architecture::{
    AuthenticatedPrincipal, CitationItem, ClaimItem, GuardrailDecision, RAGQueryResponse,
};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Enterprise RAG System API (Rust Axum)",
        version = "0.2.0",
        description = "Enterprise Retrieval-Augmented Generation API dengan RBAC Deny-by-Default, Document-Level ACL, Hybrid Retrieval (FTS5 BM25 + Vector RRF), Multi-Stage Guardrails, Citation Validator, dan Redacted Audit Trail."
    ),
    paths(
        crate::api::routes::health_check,
        crate::api::routes::auth_config_handler,
        crate::api::routes::login_handler,
        crate::api::routes::logout_handler,
        crate::api::routes::get_me_handler,
        crate::api::routes::list_documents_handler,
        crate::api::routes::get_document_detail_handler,
        crate::api::routes::update_document_acl_handler,
        crate::api::routes::delete_document_handler,
        crate::api::routes::get_citation_detail_handler,
        crate::api::routes::chat_query_handler,
        crate::api::routes::list_my_chat_sessions_handler,
        crate::api::routes::get_session_messages_handler,
        crate::api::routes::list_users_admin_handler,
        crate::api::routes::create_user_admin_handler,
        crate::api::routes::change_user_role_handler,
        crate::api::routes::update_user_status_handler,
        crate::api::routes::get_audit_logs_admin_handler,
        crate::api::routes::get_role_change_audits_handler,
        crate::api::routes::trigger_evaluation_suite_handler,
    ),
    components(schemas(
        LoginRequest,
        TokenResponse,
        AuthConfigResponse,
        ChatQueryRequest,
        DocumentAclUpdateRequest,
        CreateUserRequest,
        RoleUpdateRequest,
        UserStatusUpdateRequest,
        AuthenticatedPrincipal,
        CitationItem,
        ClaimItem,
        GuardrailDecision,
        RAGQueryResponse,
        UserRole,
        DocumentScope,
        SupportedFileType,
        IngestionStatus,
        StatementClassification,
        GuardrailStage,
        GuardrailDecisionType,
    )),
    tags(
        (name = "Health", description = "Pemeriksaan kesiapan layanan"),
        (name = "Auth", description = "Autentikasi JWT HS256, konfigurasi login, dan revokasi logout"),
        (name = "Documents", description = "Ingestion PDF/DOCX/XLSX/CSV dan Document-Level ACL"),
        (name = "Chat & RAG", description = "Tanya jawab ber-sitasi dengan Hybrid Retrieval & Guardrails"),
        (name = "Admin & Governance", description = "Manajemen pengguna CRUD, RBAC, Audit Log, dan Evaluasi 11 Kategori"),
    )
)]
pub struct ApiDoc;

pub async fn openapi_json_handler() -> impl IntoResponse {
    Json(ApiDoc::openapi())
}

pub async fn swagger_ui_handler() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Enterprise RAG API — OpenAPI / Swagger Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  <style>body { margin: 0; background: #fafafa; }</style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui.js"></script>
  <script>
    window.onload = function() {
      window.ui = SwaggerUIBundle({
        url: '/api-docs/openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis]
      });
    };
  </script>
</body>
</html>"#,
    )
}
