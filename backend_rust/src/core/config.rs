use std::path::{Path, PathBuf};

pub const DEFAULT_INSECURE_JWT_SECRET: &str =
    "CHANGE_ME_IN_LOCAL_ENV_WITH_CRYPTOGRAPHICALLY_RANDOM_SECRET";

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
    pub enable_demo_accounts: bool,

    pub database_url: String,
    pub qdrant_url: Option<String>,
    pub qdrant_storage_path: String,
    pub qdrant_collection_name: String,
    pub embedding_dimension: usize,

    pub raw_document_storage_path: String,
    pub max_upload_size_bytes: usize,

    pub chunk_size_chars: usize,
    pub chunk_overlap_chars: usize,
    pub retrieval_top_k: usize,
    pub min_relevance_score: f32,

    pub cache_max_capacity: u64,
    pub cache_ttl_secs: u64,
    pub rate_limit_login_per_min: u32,
    pub rate_limit_chat_per_min: u32,

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

        let app_name =
            std::env::var("APP_NAME").unwrap_or_else(|_| "Enterprise RAG System".to_string());
        let app_env = std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
        let app_version = std::env::var("APP_VERSION").unwrap_or_else(|_| "0.2.0".to_string());
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
            .unwrap_or_else(|_| DEFAULT_INSECURE_JWT_SECRET.to_string());
        let jwt_algorithm = std::env::var("JWT_ALGORITHM").unwrap_or_else(|_| "HS256".to_string());
        let access_token_expire_minutes = std::env::var("ACCESS_TOKEN_EXPIRE_MINUTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        let default_demo = app_env.eq_ignore_ascii_case("development");
        let enable_demo_accounts = std::env::var("ENABLE_DEMO_ACCOUNTS")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(default_demo);

        let raw_db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "sqlite:///./storage/enterprise_rag.db".to_string());
        let database_url = if raw_db_url.starts_with("sqlite:///") {
            let path_part = raw_db_url.trim_start_matches("sqlite:///");
            let resolved = resolve_path(path_part);
            format!("sqlite://{}", resolved)
        } else if raw_db_url.starts_with("sqlite://") {
            let path_part = raw_db_url.trim_start_matches("sqlite://");
            if path_part == ":memory:" {
                raw_db_url
            } else {
                let resolved = resolve_path(path_part);
                format!("sqlite://{}", resolved)
            }
        } else {
            raw_db_url
        };

        let qdrant_url = std::env::var("QDRANT_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let raw_qdrant_path =
            std::env::var("QDRANT_STORAGE_PATH").unwrap_or_else(|_| "./storage/qdrant".to_string());
        let qdrant_storage_path = resolve_path(&raw_qdrant_path);
        let qdrant_collection_name = std::env::var("QDRANT_COLLECTION_NAME")
            .unwrap_or_else(|_| "enterprise_documents".to_string());
        let embedding_dimension = std::env::var("EMBEDDING_DIMENSION")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(256);

        let raw_doc_path = std::env::var("RAW_DOCUMENT_STORAGE_PATH")
            .unwrap_or_else(|_| "./storage/documents".to_string());
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

        let cache_max_capacity = std::env::var("CACHE_MAX_CAPACITY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(500);
        let cache_ttl_secs = std::env::var("CACHE_TTL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);
        let rate_limit_login_per_min = std::env::var("RATE_LIMIT_LOGIN_PER_MIN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20);
        let rate_limit_chat_per_min = std::env::var("RATE_LIMIT_CHAT_PER_MIN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        let llm_provider =
            std::env::var("LLM_PROVIDER").unwrap_or_else(|_| "local_grounded".to_string());
        let llm_model_name = std::env::var("LLM_MODEL_NAME")
            .unwrap_or_else(|_| "local-extractive-grounded-v1".to_string());
        let embedding_provider = std::env::var("EMBEDDING_PROVIDER")
            .unwrap_or_else(|_| "local_deterministic".to_string());
        let embedding_model_name = std::env::var("EMBEDDING_MODEL_NAME")
            .unwrap_or_else(|_| "local-hash-ngram-256d-v1".to_string());

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
            enable_demo_accounts,
            database_url,
            qdrant_url,
            qdrant_storage_path,
            qdrant_collection_name,
            embedding_dimension,
            raw_document_storage_path,
            max_upload_size_bytes,
            chunk_size_chars,
            chunk_overlap_chars,
            retrieval_top_k,
            min_relevance_score,
            cache_max_capacity,
            cache_ttl_secs,
            rate_limit_login_per_min,
            rate_limit_chat_per_min,
            llm_provider,
            llm_model_name,
            embedding_provider,
            embedding_model_name,
            openai_api_key,
            gemini_api_key,
            cors_allowed_origins,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        let is_dev = self.app_env.eq_ignore_ascii_case("development");
        let secret_trimmed = self.jwt_secret_key.trim();
        let is_placeholder = secret_trimmed == DEFAULT_INSECURE_JWT_SECRET
            || secret_trimmed.to_uppercase().contains("CHANGE_ME");

        if !is_dev && (is_placeholder || secret_trimmed.len() < 32) {
            return Err(format!(
                "SECURITY BOOT FAILURE: APP_ENV='{}' membutuhkan JWT_SECRET_KEY unik minimal 32 byte dan tidak boleh menggunakan nilai placeholder default.",
                self.app_env
            ));
        }

        if self.chunk_size_chars <= 50 {
            return Err("CHUNK_SIZE_CHARS harus > 50.".to_string());
        }
        if self.chunk_overlap_chars >= self.chunk_size_chars {
            return Err("CHUNK_OVERLAP_CHARS harus < CHUNK_SIZE_CHARS.".to_string());
        }
        if self.cors_allowed_origins.is_empty() {
            return Err("CORS_ALLOWED_ORIGINS tidak boleh kosong.".to_string());
        }

        Ok(())
    }

    pub fn ensure_storage_dirs(&self) {
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
