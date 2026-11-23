use std::sync::Arc;
use tracing::{error, info};

use backend_rust::api::build_app;
use backend_rust::api::rate_limit::RateLimiter;
use backend_rust::api::routes::AppState;
use backend_rust::core::config::Settings;
use backend_rust::db::init_db;
use backend_rust::ingestion::pipeline::DocumentIngestionService;
use backend_rust::rag::embeddings::build_embedding_provider;
use backend_rust::rag::llm::build_llm_provider;
use backend_rust::rag::service::EnterpriseRAGService;
use backend_rust::rag::vector_store::{VectorPoint, VectorStore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=info,sqlx=warn".into()),
        )
        .init();

    let settings = Settings::from_env();
    if let Err(err) = settings.validate() {
        error!("{}", err);
        return Err(err.into());
    }
    settings.ensure_storage_dirs();

    info!(
        "Starting {} v{} (env={})",
        settings.app_name, settings.app_version, settings.app_env
    );
    info!("Database URL: {}", settings.database_url);
    info!("CORS Allowed Origins: {:?}", settings.cors_allowed_origins);
    info!("Demo Accounts Enabled: {}", settings.enable_demo_accounts);

    // Initialize SQLite database (with PRAGMA foreign_keys=ON and WAL mode)
    let pool = init_db(&settings.database_url, settings.enable_demo_accounts).await?;

    // Build configured Embedding & LLM providers (defaults to offline deterministic local providers)
    let embedding_provider = build_embedding_provider(&settings);
    let llm_provider = build_llm_provider(&settings);
    info!(
        "Embedding Provider: {} ({})",
        embedding_provider.provider_name(),
        embedding_provider.model_name()
    );
    info!(
        "LLM Provider: {} ({})",
        llm_provider.provider_name(),
        llm_provider.model_name()
    );

    let vector_store = VectorStore::with_qdrant(
        embedding_provider.clone(),
        settings.qdrant_url.clone(),
        settings.qdrant_collection_name.clone(),
    );

    #[derive(sqlx::FromRow)]
    struct SyncChunkRow {
        chunk_id: String,
        document_id: String,
        title: String,
        source_filename: String,
        file_type: String,
        scope: String,
        allowed_roles: String,
        allowed_users: String,
        acl_version: i64,
        version: i64,
        ingestion_status: String,
        page_number: Option<i64>,
        sheet_name: Option<String>,
        row_start: Option<i64>,
        row_end: Option<i64>,
        section_label: Option<String>,
        has_potential_injection: bool,
        text_content: String,
        embedding_json: Option<String>,
    }

    // Synchronize persistent embeddings & FTS5 index with existing indexed chunks in SQLite
    let rows: Vec<SyncChunkRow> = sqlx::query_as(
        r#"
        SELECT c.chunk_id, c.document_id, d.title, d.source_filename, d.file_type, d.scope,
               d.allowed_roles, d.allowed_users, d.acl_version, d.version, d.ingestion_status,
               c.page_number, c.sheet_name, c.row_start, c.row_end, c.section_label,
               c.has_potential_injection, c.text_content, e.embedding_json
        FROM document_chunks c
        JOIN documents d ON c.document_id = d.document_id
        LEFT JOIN document_chunk_embeddings e ON c.chunk_id = e.chunk_id
        WHERE d.ingestion_status = 'INDEXED'
        "#,
    )
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    if !rows.is_empty() {
        info!(
            "Synchronizing {} indexed chunks into hybrid vector + FTS5 index...",
            rows.len()
        );
        let now_str = chrono::Utc::now().to_rfc3339();
        let mut points = Vec::with_capacity(rows.len());

        // Rebuild FTS5 index cleanly to stay 100% consistent with INDEXED chunks
        let _ = sqlx::query("DELETE FROM document_chunks_fts")
            .execute(&pool)
            .await;

        for r in rows {
            let allowed_roles: Vec<String> =
                serde_json::from_str(&r.allowed_roles).unwrap_or_default();
            let allowed_users: Vec<String> =
                serde_json::from_str(&r.allowed_users).unwrap_or_default();

            let vector: Vec<f32> = match r
                .embedding_json
                .as_deref()
                .and_then(|j| serde_json::from_str::<Vec<f32>>(j).ok())
                .filter(|v| v.len() == embedding_provider.dimension())
            {
                Some(stored) => stored,
                None => {
                    let computed = embedding_provider.embed_query(&r.text_content).await?;
                    let emb_json = serde_json::to_string(&computed)?;
                    let _ = sqlx::query(
                        "INSERT OR REPLACE INTO document_chunk_embeddings (chunk_id, document_id, embedding_json, updated_at) VALUES (?, ?, ?, ?)",
                    )
                    .bind(&r.chunk_id)
                    .bind(&r.document_id)
                    .bind(&emb_json)
                    .bind(&now_str)
                    .execute(&pool)
                    .await;
                    computed
                }
            };

            let _ = sqlx::query(
                "INSERT INTO document_chunks_fts (chunk_id, document_id, text_content) VALUES (?, ?, ?)",
            )
            .bind(&r.chunk_id)
            .bind(&r.document_id)
            .bind(&r.text_content)
            .execute(&pool)
            .await;

            points.push(VectorPoint {
                chunk_id: r.chunk_id,
                document_id: r.document_id,
                title: r.title,
                source_filename: r.source_filename,
                file_type: r.file_type,
                scope: r.scope,
                allowed_roles,
                allowed_users,
                acl_version: r.acl_version,
                version: r.version,
                ingestion_status: r.ingestion_status,
                page_number: r.page_number,
                sheet_name: r.sheet_name,
                row_start: r.row_start,
                row_end: r.row_end,
                section_label: r.section_label,
                has_potential_injection: r.has_potential_injection,
                vector,
            });
        }
        vector_store.upsert_points(points).await;
        info!("Hybrid vector + FTS5 synchronization completed.");
    }

    let shared_settings = Arc::new(settings.clone());

    let ingestion_service = Arc::new(DocumentIngestionService::new(
        vector_store.clone(),
        shared_settings.clone(),
    ));

    let rag_service = Arc::new(EnterpriseRAGService::new(
        vector_store,
        llm_provider,
        shared_settings.clone(),
    ));

    let rate_limiter = Arc::new(RateLimiter::new(10_000, 60));

    let app_state = AppState {
        pool,
        settings: shared_settings,
        ingestion_service,
        rag_service,
        rate_limiter,
    };

    let app = build_app(app_state);

    let addr = format!("{}:{}", settings.host, settings.port);
    info!("Enterprise RAG Rust Backend listening on http://{}", addr);
    info!("Swagger OpenAPI UI available at http://{}/docs", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
