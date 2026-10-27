#![allow(dead_code)]

use std::sync::Arc;
use axum::{
    extract::Extension,
    http::{header, Method},
    Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

use backend_rust::api::routes::{create_router, AppState};
use backend_rust::core::config::Settings;
use backend_rust::db::init_db;
use backend_rust::ingestion::pipeline::DocumentIngestionService;
use backend_rust::rag::embeddings::LocalDeterministicEmbeddingProvider;
use backend_rust::rag::llm::LocalGroundedExtractiveLLMProvider;
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
    settings.ensure_storage_dirs();

    info!("Starting {} v{}", settings.app_name, settings.app_version);
    info!("Database URL: {}", settings.database_url);
    info!("Target Port: {}", settings.port);

    // Initialize SQLite database
    let pool = init_db(&settings.database_url).await?;

    // Initialize Embedding Provider & Vector Store
    let embedding_provider = Arc::new(LocalDeterministicEmbeddingProvider::new(
        settings.embedding_dimension,
        &settings.embedding_model_name,
    ));
    let vector_store = VectorStore::new(embedding_provider.clone());

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
    }

    // Synchronize vector store with existing indexed chunks in SQLite
    let rows: Vec<SyncChunkRow> = sqlx::query_as(
        r#"
        SELECT c.chunk_id, c.document_id, d.title, d.source_filename, d.file_type, d.scope,
               d.allowed_roles, d.allowed_users, d.acl_version, d.version, d.ingestion_status,
               c.page_number, c.sheet_name, c.row_start, c.row_end, c.section_label,
               c.has_potential_injection, c.text_content
        FROM document_chunks c
        JOIN documents d ON c.document_id = d.document_id
        WHERE d.ingestion_status = 'INDEXED'
        "#,
    )
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    if !rows.is_empty() {
        info!("Synchronizing {} indexed chunks into vector index...", rows.len());
        let mut points = Vec::new();
        for r in rows {
            let allowed_roles: Vec<String> = serde_json::from_str(&r.allowed_roles).unwrap_or_default();
            let allowed_users: Vec<String> = serde_json::from_str(&r.allowed_users).unwrap_or_default();
            let vector = embedding_provider.embed_single(&r.text_content);

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
        info!("Vector store synchronization completed.");
    }

    let shared_settings = Arc::new(settings.clone());

    let ingestion_service = Arc::new(DocumentIngestionService::new(
        vector_store.clone(),
        shared_settings.clone(),
    ));

    let llm_provider = Arc::new(LocalGroundedExtractiveLLMProvider::new(&settings.llm_model_name));

    let rag_service = Arc::new(EnterpriseRAGService::new(
        vector_store,
        llm_provider,
        shared_settings.clone(),
    ));

    let app_state = AppState {
        pool: pool.clone(),
        settings: shared_settings.clone(),
        ingestion_service,
        rag_service,
    };

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |_, _| true)) // Allow configured origins
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT])
        .allow_credentials(true);

    let api_router = create_router(app_state);

    let app = Router::new()
        .nest("/api/v1", api_router)
        .layer(Extension(settings.clone()))
        .layer(Extension(pool))
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let addr = format!("{}:{}", settings.host, settings.port);
    info!("Enterprise RAG Rust Backend listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
