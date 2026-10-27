use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Settings {
    pub app_name: String,
    pub app_env: String,
    pub app_version: String,
    pub debug: bool,

    pub host: String,
    pub port: u16,

    pub jwt_secret_key: String,
    pub jwt_algorithm: String,
    pub access_token_expire_minutes: i64,

    pub database_url: String,
    pub qdrant_storage_path: String,
    pub qdrant_collection_name: String,
    pub embedding_dimension: usize,

    pub raw_document_storage_path: String,
    pub max_upload_size_bytes: usize,

    pub chunk_size_chars: usize,
    pub chunk_overlap_chars: usize,
    pub retrieval_top_k: usize,
    pub min_relevance_score: f32,

    pub llm_provider: String,
    pub llm_model_name: String,
    pub embedding_provider: String,
    pub embedding_model_name: String,

    pub openai_api_key: String,
    pub gemini_api_key: String,

    pub cors_allowed_origins: Vec<String>,
}

fn resolve_path(relative_or_abs: &str) -> String {
    let p = Path::new(relative_or_abs);
    if p.is_absolute() || p.exists() {
        return relative_or_abs.to_string();
    }
    // Check parent directory if run from subfolder
    let parent_p = PathBuf::from("..").join(p);
    if parent_p.exists() {
        return parent_p.to_string_lossy().to_string();
    }
    relative_or_abs.to_string()
}

impl Settings {
    pub fn from_env() -> Self {
        // Try loading .env from current dir or parent dir
        let _ = dotenvy::dotenv();
        if !Path::new(".env").exists() && Path::new("../.env").exists() {
            let _ = dotenvy::from_path("../.env");
        }

        let app_name = std::env::var("APP_NAME").unwrap_or_else(|_| "Enterprise RAG System".to_string());
        let app_env = std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
        let app_version = std::env::var("APP_VERSION").unwrap_or_else(|_| "0.1.0".to_string());
        let debug = std::env::var("DEBUG")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port = std::env::var("BACKEND_PORT")
            .or_else(|_| std::env::var("PORT"))
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8010);

        let jwt_secret_key = std::env::var("JWT_SECRET_KEY")
            .unwrap_or_else(|_| "CHANGE_ME_IN_LOCAL_ENV_WITH_CRYPTOGRAPHICALLY_RANDOM_SECRET".to_string());
        let jwt_algorithm = std::env::var("JWT_ALGORITHM").unwrap_or_else(|_| "HS256".to_string());
        let access_token_expire_minutes = std::env::var("ACCESS_TOKEN_EXPIRE_MINUTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        let raw_db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:///./storage/enterprise_rag.db".to_string());
        let database_url = if raw_db_url.starts_with("sqlite:///") {
            let path_part = raw_db_url.trim_start_matches("sqlite:///");
            let resolved = resolve_path(path_part);
            format!("sqlite://{}", resolved)
        } else if raw_db_url.starts_with("sqlite://") {
            let path_part = raw_db_url.trim_start_matches("sqlite://");
            let resolved = resolve_path(path_part);
            format!("sqlite://{}", resolved)
        } else {
            raw_db_url
        };

        let raw_qdrant_path = std::env::var("QDRANT_STORAGE_PATH").unwrap_or_else(|_| "./storage/qdrant".to_string());
        let qdrant_storage_path = resolve_path(&raw_qdrant_path);
        let qdrant_collection_name = std::env::var("QDRANT_COLLECTION_NAME").unwrap_or_else(|_| "enterprise_documents".to_string());
        let embedding_dimension = std::env::var("EMBEDDING_DIMENSION")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(256);

        let raw_doc_path = std::env::var("RAW_DOCUMENT_STORAGE_PATH").unwrap_or_else(|_| "./storage/documents".to_string());
        let raw_document_storage_path = resolve_path(&raw_doc_path);
        let max_upload_size_bytes = std::env::var("MAX_UPLOAD_SIZE_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10 * 1024 * 1024);

        let chunk_size_chars = std::env::var("CHUNK_SIZE_CHARS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(800);
        let chunk_overlap_chars = std::env::var("CHUNK_OVERLAP_CHARS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120);
        let retrieval_top_k = std::env::var("RETRIEVAL_TOP_K")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);
        let min_relevance_score = std::env::var("MIN_RELEVANCE_SCORE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.05);

        let llm_provider = std::env::var("LLM_PROVIDER").unwrap_or_else(|_| "local_grounded".to_string());
        let llm_model_name = std::env::var("LLM_MODEL_NAME").unwrap_or_else(|_| "local-extractive-grounded-v1".to_string());
        let embedding_provider = std::env::var("EMBEDDING_PROVIDER").unwrap_or_else(|_| "local_deterministic".to_string());
        let embedding_model_name = std::env::var("EMBEDDING_MODEL_NAME").unwrap_or_else(|_| "local-hash-ngram-256d-v1".to_string());

        let openai_api_key = std::env::var("OPENAI_API_KEY").unwrap_or_default();
        let gemini_api_key = std::env::var("GEMINI_API_KEY").unwrap_or_default();

        let cors_str = std::env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:5173,http://127.0.0.1:5173".to_string());
        let cors_allowed_origins = cors_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Self {
            app_name,
            app_env,
            app_version,
            debug,
            host,
            port,
            jwt_secret_key,
            jwt_algorithm,
            access_token_expire_minutes,
            database_url,
            qdrant_storage_path,
            qdrant_collection_name,
            embedding_dimension,
            raw_document_storage_path,
            max_upload_size_bytes,
            chunk_size_chars,
            chunk_overlap_chars,
            retrieval_top_k,
            min_relevance_score,
            llm_provider,
            llm_model_name,
            embedding_provider,
            embedding_model_name,
            openai_api_key,
            gemini_api_key,
            cors_allowed_origins,
        }
    }

    pub fn ensure_storage_dirs(&self) {
        let _ = std::fs::create_dir_all(&self.qdrant_storage_path);
        let _ = std::fs::create_dir_all(&self.raw_document_storage_path);
        if let Some(db_path) = self.database_url.strip_prefix("sqlite://") {
            if db_path != ":memory:" {
                if let Some(parent) = Path::new(db_path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
        }
    }
}
