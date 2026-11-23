use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

use backend_rust::api::build_app;
use backend_rust::api::rate_limit::RateLimiter;
use backend_rust::api::routes::{
    build_synthetic_docx_bytes, seed_synthetic_fixtures_impl, AppState,
};
use backend_rust::core::config::Settings;
use backend_rust::db::init_db;
use backend_rust::ingestion::pipeline::DocumentIngestionService;
use backend_rust::rag::embeddings::LocalDeterministicEmbeddingProvider;
use backend_rust::rag::llm::LocalGroundedExtractiveLLMProvider;
use backend_rust::rag::service::EnterpriseRAGService;
use backend_rust::rag::vector_store::VectorStore;

async fn setup_test_app(login_rate_limit: u32) -> (axum::Router, AppState) {
    let mut settings = Settings::from_env();
    settings.app_env = "development".to_string();
    settings.database_url = "sqlite://:memory:".to_string();
    settings.enable_demo_accounts = true;
    settings.rate_limit_login_per_min = login_rate_limit;
    settings.rate_limit_chat_per_min = 200;
    settings.cors_allowed_origins = vec!["http://localhost:5173".to_string()];

    let temp_dir = std::env::temp_dir().join(format!(
        "enterprise_rag_test_{}",
        uuid::Uuid::new_v4().simple()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    settings.raw_document_storage_path = temp_dir.to_string_lossy().to_string();

    let pool = init_db(&settings.database_url, true)
        .await
        .expect("Failed to init in-memory SQLite DB");

    let shared_settings = Arc::new(settings);
    let embedding_provider = Arc::new(LocalDeterministicEmbeddingProvider::new(
        shared_settings.embedding_dimension,
        &shared_settings.embedding_model_name,
    ));
    let vector_store = VectorStore::new(embedding_provider);
    let ingestion_service = Arc::new(DocumentIngestionService::new(
        vector_store.clone(),
        shared_settings.clone(),
    ));
    let llm_provider = Arc::new(LocalGroundedExtractiveLLMProvider::new(
        &shared_settings.llm_model_name,
    ));
    let rag_service = Arc::new(EnterpriseRAGService::new(
        vector_store,
        llm_provider,
        shared_settings.clone(),
    ));
    let rate_limiter = Arc::new(RateLimiter::new(1000, 60));

    let state = AppState {
        pool,
        settings: shared_settings,
        ingestion_service,
        rag_service,
        rate_limiter,
    };

    seed_synthetic_fixtures_impl(&state)
        .await
        .expect("Failed to seed synthetic fixtures");

    let app = build_app(state.clone());
    (app, state)
}

async fn response_json(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let val: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}));
    (status, val)
}

async fn login_as(app: &axum::Router, username: &str, password: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "username": username, "password": password }).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    response_json(resp).await
}

fn build_multipart_upload(
    boundary: &str,
    title: &str,
    scope: &str,
    allowed_roles: &str,
    filename: &str,
    file_bytes: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    let fields = [
        ("title", title),
        ("scope", scope),
        ("allowed_roles", allowed_roles),
        ("allowed_users", ""),
    ];
    for (name, val) in fields {
        body.extend_from_slice(
            format!(
                "--{}\r\nContent-Disposition: form-data; name=\"{}\"\r\n\r\n{}\r\n",
                boundary, name, val
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(
        format!(
            "--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\nContent-Type: application/octet-stream\r\n\r\n",
            boundary, filename
        )
        .as_bytes(),
    );
    body.extend_from_slice(file_bytes);
    body.extend_from_slice(format!("\r\n--{}--\r\n", boundary).as_bytes());
    body
}

#[tokio::test]
async fn test_http_health_openapi_and_strict_cors() {
    let (app, _state) = setup_test_app(100).await;

    // 1. Health check with allowed origin -> ACAO header present
    let req = Request::builder()
        .uri("/api/v1/health")
        .header(header::ORIGIN, "http://localhost:5173")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
        Some("http://localhost:5173")
    );

    // 2. Disallowed origin must NOT receive Access-Control-Allow-Origin
    let evil_req = Request::builder()
        .uri("/api/v1/health")
        .header(header::ORIGIN, "https://evil-site.example.com")
        .body(Body::empty())
        .unwrap();
    let evil_resp = app.clone().oneshot(evil_req).await.unwrap();
    assert!(
        evil_resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "Disallowed CORS origin must not be reflected"
    );

    // 3. Swagger /docs & OpenAPI JSON spec
    let docs_resp = app
        .clone()
        .oneshot(Request::builder().uri("/docs").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(docs_resp.status(), StatusCode::OK);

    let spec_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api-docs/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let (spec_status, spec_json) = response_json(spec_resp).await;
    assert_eq!(spec_status, StatusCode::OK);
    assert!(spec_json["paths"]["/api/v1/auth/login"].is_object());
    assert!(spec_json["paths"]["/api/v1/documents/{document_id}/acl"].is_object());
}

#[tokio::test]
async fn test_http_auth_logout_jti_revocation_and_rate_limiting() {
    let (app, _state) = setup_test_app(3).await;

    // Login succeeds
    let (status, login_body) = login_as(&app, "budi.employee", "EmpPass#2026!").await;
    assert_eq!(status, StatusCode::OK);
    let token = login_body["access_token"].as_str().unwrap().to_string();

    // /auth/me works before logout
    let me_ok = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(me_ok.status(), StatusCode::OK);

    // Logout revokes token JTI
    let logout_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/logout")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout_resp.status(), StatusCode::OK);

    // Reusing revoked JWT must return 401 Unauthorized
    let me_revoked = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/me")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(me_revoked.status(), StatusCode::UNAUTHORIZED);

    // Rate limit enforcement on /auth/login (use non-existent username to avoid debug PBKDF2 60s window drift)
    let _ = login_as(&app, "ratelimit.probe", "WrongPass!").await; // 1st -> 401
    let _ = login_as(&app, "ratelimit.probe", "WrongPass!").await; // 2nd -> 401
    let _ = login_as(&app, "ratelimit.probe", "WrongPass!").await; // 3rd -> 401
    let (rl_status, _) = login_as(&app, "ratelimit.probe", "WrongPass!").await; // 4th -> 429
    assert_eq!(rl_status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_http_cache_hit_persists_chat_history_and_multiturn_context() {
    let (app, _state) = setup_test_app(100).await;
    let (_, login_body) = login_as(&app, "budi.employee", "EmpPass#2026!").await;
    let token = login_body["access_token"].as_str().unwrap();

    // 1st query (cache miss)
    let q1 = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/chat/query")
        .header(header::AUTHORIZATION, format!("Bearer {}", token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "question": "Apa aturan jam operasional kantor?",
                "use_cache": true
            })
            .to_string(),
        ))
        .unwrap();
    let (s1, b1) = response_json(app.clone().oneshot(q1).await.unwrap()).await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(b1["metadata"]["cache_hit"], false);
    let sess1 = b1["session_id"].as_str().unwrap().to_string();

    // 2nd identical query on a NEW session (same user + same empty history fingerprint -> guaranteed cache hit!)
    let q2 = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/chat/query")
        .header(header::AUTHORIZATION, format!("Bearer {}", token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "question": "Apa aturan jam operasional kantor?",
                "use_cache": true
            })
            .to_string(),
        ))
        .unwrap();
    let (s2, b2) = response_json(app.clone().oneshot(q2).await.unwrap()).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(
        b2["metadata"]["cache_hit"], true,
        "Expected second identical request to hit isolated bounded cache"
    );
    let sess2 = b2["session_id"].as_str().unwrap().to_string();

    // Verify cache-hit session STILL persisted both user and assistant messages!
    let hist_req = Request::builder()
        .uri(format!("/api/v1/chat/sessions/{}/messages", sess2))
        .header(header::AUTHORIZATION, format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();
    let (hs, hbody) = response_json(app.clone().oneshot(hist_req).await.unwrap()).await;
    assert_eq!(hs, StatusCode::OK);
    let msgs = hbody.as_array().unwrap();
    assert_eq!(
        msgs.len(),
        2,
        "Cache-hit must persist both user and assistant messages in chat_messages"
    );
    assert_eq!(msgs[0]["sender"], "user");
    assert_eq!(msgs[1]["sender"], "assistant");
    assert!(msgs[1]["content"].as_str().unwrap().contains("08:30"));

    // Verify cross-user session IDOR is blocked with 403
    let (_, fin_login) = login_as(&app, "andi.finance", "FinPass#2026!").await;
    let fin_token = fin_login["access_token"].as_str().unwrap();
    let idor_req = Request::builder()
        .uri(format!("/api/v1/chat/sessions/{}/messages", sess1))
        .header(header::AUTHORIZATION, format!("Bearer {}", fin_token))
        .body(Body::empty())
        .unwrap();
    let idor_resp = app.clone().oneshot(idor_req).await.unwrap();
    assert_eq!(idor_resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_http_document_upload_acl_update_owner_delete_and_idor() {
    let (app, _state) = setup_test_app(100).await;
    let (_, hr_login) = login_as(&app, "siti.hr", "HrPass#2026!").await;
    let hr_token = hr_login["access_token"].as_str().unwrap();
    let (_, emp_login) = login_as(&app, "budi.employee", "EmpPass#2026!").await;
    let emp_token = emp_login["access_token"].as_str().unwrap();
    let (_, exec_login) = login_as(&app, "dian.exec", "ExecPass#2026!").await;
    let exec_token = exec_login["access_token"].as_str().unwrap();

    // 1. HR uploads a structured DOCX document restricted initially to HR only
    let docx_bytes = build_synthetic_docx_bytes(
        "Bonus Tahunan Khusus",
        &["Level", "Bonus_Persen"],
        &[&["Senior", "15"]],
    );
    let boundary = "----TestBoundary7MA4YWxkTrZu0gW";
    let mp_body = build_multipart_upload(
        boundary,
        "Dokumen Bonus HR",
        "hr",
        "hr",
        "bonus_hr.docx",
        &docx_bytes,
    );
    let up_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/documents/upload")
        .header(header::AUTHORIZATION, format!("Bearer {}", hr_token))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={}", boundary),
        )
        .body(Body::from(mp_body))
        .unwrap();
    let (up_status, up_json) = response_json(app.clone().oneshot(up_req).await.unwrap()).await;
    assert_eq!(up_status, StatusCode::OK);
    let doc_id = up_json["document_id"].as_str().unwrap().to_string();
    assert_eq!(up_json["can_manage"], true);

    // 2. Employee IDOR read attempt -> 403 Forbidden
    let idor_doc = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/documents/{}", doc_id))
                .header(header::AUTHORIZATION, format!("Bearer {}", emp_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(idor_doc.status(), StatusCode::FORBIDDEN);

    // 3. Executive (non-owner without doc:delete) tries to delete HR's document -> 403 Forbidden!
    let exec_del = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/api/v1/documents/{}", doc_id))
                .header(header::AUTHORIZATION, format!("Bearer {}", exec_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        exec_del.status(),
        StatusCode::FORBIDDEN,
        "Non-owner without explicit doc:delete must not delete another user's document"
    );

    // 4. Owner HR updates document ACL via PATCH /documents/:id/acl to include executive
    let acl_req = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/api/v1/documents/{}/acl", doc_id))
        .header(header::AUTHORIZATION, format!("Bearer {}", hr_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "allowed_roles": ["hr", "executive"], "allowed_users": [] }).to_string(),
        ))
        .unwrap();
    let (acl_status, acl_json) = response_json(app.clone().oneshot(acl_req).await.unwrap()).await;
    assert_eq!(acl_status, StatusCode::OK);
    assert_eq!(acl_json["acl_version"], 2);

    // Executive can now read document detail after ACL grant
    let exec_read = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/documents/{}", doc_id))
                .header(header::AUTHORIZATION, format!("Bearer {}", exec_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exec_read.status(), StatusCode::OK);

    // 5. Owner HR deletes document -> 200 OK
    let hr_del = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/api/v1/documents/{}", doc_id))
                .header(header::AUTHORIZATION, format!("Bearer {}", hr_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(hr_del.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_http_admin_crud_explicit_permissions_audit_redaction_and_11_category_eval() {
    let (app, _state) = setup_test_app(100).await;
    let (_, adm_login) = login_as(&app, "rudi.admin", "AdmPass#2026!").await;
    let adm_token = adm_login["access_token"].as_str().unwrap();

    // 1. Admin creates a new auditor user with explicit `audit:read` and `eval:run` permissions
    let create_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/admin/users")
        .header(header::AUTHORIZATION, format!("Bearer {}", adm_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "username": "rina.auditor",
                "email": "rina@synthetic.test",
                "password": "AuditPass#2026!",
                "role": "employee",
                "explicit_permissions": ["audit:read", "eval:run"]
            })
            .to_string(),
        ))
        .unwrap();
    let (c_status, c_json) = response_json(app.clone().oneshot(create_req).await.unwrap()).await;
    assert_eq!(c_status, StatusCode::CREATED);
    let new_uid = c_json["user_id"].as_str().unwrap().to_string();

    // 2. New auditor (role=employee, perms=[audit:read, eval:run]) can read audit logs!
    let (_, aud_login) = login_as(&app, "rina.auditor", "AuditPass#2026!").await;
    let aud_token = aud_login["access_token"].as_str().unwrap();

    let audit_req = Request::builder()
        .uri("/api/v1/admin/audit-logs?limit=50")
        .header(header::AUTHORIZATION, format!("Bearer {}", aud_token))
        .body(Body::empty())
        .unwrap();
    let (a_status, a_json) = response_json(app.clone().oneshot(audit_req).await.unwrap()).await;
    assert_eq!(a_status, StatusCode::OK);
    let audit_str = a_json.to_string();
    assert!(
        !audit_str.contains("pbkdf2_sha256"),
        "Audit logs must never leak password hashes"
    );
    assert!(
        !audit_str.contains("AuditPass#2026!"),
        "Audit logs must never leak raw passwords"
    );

    // 3. Admin self-deactivation is blocked with 403
    let self_deact = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/api/v1/admin/users/usr-adm-1/status")
                .header(header::AUTHORIZATION, format!("Bearer {}", adm_token))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "is_active": false, "reason": "Self deactivation test" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(self_deact.status(), StatusCode::FORBIDDEN);

    // 4. Admin deactivates rina.auditor -> subsequent login denied
    let deact_req = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/api/v1/admin/users/{}/status", new_uid))
        .header(header::AUTHORIZATION, format!("Bearer {}", adm_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "is_active": false, "reason": "Audit contract ended" }).to_string(),
        ))
        .unwrap();
    let (d_status, _) = response_json(app.clone().oneshot(deact_req).await.unwrap()).await;
    assert_eq!(d_status, StatusCode::OK);

    let (deact_login_status, _) = login_as(&app, "rina.auditor", "AuditPass#2026!").await;
    assert_eq!(deact_login_status, StatusCode::UNAUTHORIZED);

    // 5. Run full 11-category evaluation benchmark suite via HTTP API -> MUST achieve 100% pass rate (11/11)!
    let eval_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/admin/run-evaluation")
        .header(header::AUTHORIZATION, format!("Bearer {}", adm_token))
        .body(Body::empty())
        .unwrap();
    let (e_status, e_json) = response_json(app.clone().oneshot(eval_req).await.unwrap()).await;
    assert_eq!(e_status, StatusCode::OK);
    assert_eq!(
        e_json["total_cases"], 11,
        "Evaluation suite must cover all 11 categories"
    );
    assert_eq!(
        e_json["failed_cases"],
        0,
        "All 11 evaluation categories must pass, got failures: {}",
        serde_json::to_string_pretty(&e_json["cases"]).unwrap()
    );
    assert_eq!(e_json["passed_cases"], 11);
    assert_eq!(e_json["pass_rate_percent"], 100.0);
}
