pub mod models;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::str::FromStr;


pub async fn init_db(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    let clean_url = database_url.trim_start_matches("sqlite://");
    let options = SqliteConnectOptions::from_str(clean_url)?
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await?;

    // Create tables if they do not exist
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id VARCHAR(64) PRIMARY KEY,
            username VARCHAR(120) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(32) NOT NULL,
            explicit_permissions JSON NOT NULL DEFAULT '[]',
            is_active BOOLEAN NOT NULL DEFAULT 1,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS ix_users_username ON users (username);
        CREATE INDEX IF NOT EXISTS ix_users_email ON users (email);
        CREATE INDEX IF NOT EXISTS ix_users_role ON users (role);

        CREATE TABLE IF NOT EXISTS role_change_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id VARCHAR(64) NOT NULL,
            target_user_id VARCHAR(64) NOT NULL,
            previous_role VARCHAR(32) NOT NULL,
            new_role VARCHAR(32) NOT NULL,
            previous_permissions JSON NOT NULL DEFAULT '[]',
            new_permissions JSON NOT NULL DEFAULT '[]',
            reason VARCHAR(500) NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS ix_role_change_audits_actor ON role_change_audits (actor_user_id);
        CREATE INDEX IF NOT EXISTS ix_role_change_audits_target ON role_change_audits (target_user_id);

        CREATE TABLE IF NOT EXISTS documents (
            document_id VARCHAR(64) PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            source_filename VARCHAR(255) NOT NULL,
            file_type VARCHAR(16) NOT NULL,
            file_size_bytes INTEGER NOT NULL,
            content_sha256 VARCHAR(64) NOT NULL,
            owner_user_id VARCHAR(64) NOT NULL REFERENCES users(id),
            scope VARCHAR(32) NOT NULL,
            allowed_roles JSON NOT NULL DEFAULT '[]',
            allowed_users JSON NOT NULL DEFAULT '[]',
            version INTEGER NOT NULL DEFAULT 1,
            acl_version INTEGER NOT NULL DEFAULT 1,
            ingestion_status VARCHAR(32) NOT NULL,
            ingestion_error TEXT,
            chunk_count INTEGER NOT NULL DEFAULT 0,
            storage_path VARCHAR(512),
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT uq_document_content_scope_version UNIQUE (content_sha256, scope, version)
        );
        CREATE INDEX IF NOT EXISTS ix_documents_content_sha256 ON documents (content_sha256);
        CREATE INDEX IF NOT EXISTS ix_documents_owner ON documents (owner_user_id);
        CREATE INDEX IF NOT EXISTS ix_documents_scope ON documents (scope);
        CREATE INDEX IF NOT EXISTS ix_documents_status ON documents (ingestion_status);

        CREATE TABLE IF NOT EXISTS document_chunks (
            chunk_id VARCHAR(64) PRIMARY KEY,
            document_id VARCHAR(64) NOT NULL REFERENCES documents(document_id) ON DELETE CASCADE,
            chunk_index INTEGER NOT NULL,
            text_content TEXT NOT NULL,
            content_sha256 VARCHAR(64) NOT NULL,
            page_number INTEGER,
            sheet_name VARCHAR(128),
            row_start INTEGER,
            row_end INTEGER,
            section_label VARCHAR(255),
            has_potential_injection BOOLEAN NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS ix_document_chunks_doc_id ON document_chunks (document_id);

        CREATE TABLE IF NOT EXISTS chat_sessions (
            session_id VARCHAR(64) PRIMARY KEY,
            user_id VARCHAR(64) NOT NULL REFERENCES users(id),
            title VARCHAR(255) NOT NULL,
            role_snapshot VARCHAR(32) NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS ix_chat_sessions_user ON chat_sessions (user_id);

        CREATE TABLE IF NOT EXISTS chat_messages (
            message_id VARCHAR(64) PRIMARY KEY,
            session_id VARCHAR(64) NOT NULL REFERENCES chat_sessions(session_id) ON DELETE CASCADE,
            user_id VARCHAR(64) NOT NULL,
            sender VARCHAR(16) NOT NULL,
            content TEXT NOT NULL,
            citations_json JSON NOT NULL DEFAULT '[]',
            epistemic_classification VARCHAR(64),
            request_id VARCHAR(64) NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS ix_chat_messages_session ON chat_messages (session_id);
        CREATE INDEX IF NOT EXISTS ix_chat_messages_user ON chat_messages (user_id);
        CREATE INDEX IF NOT EXISTS ix_chat_messages_req ON chat_messages (request_id);

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id VARCHAR(64) NOT NULL,
            timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            user_id VARCHAR(64),
            user_role VARCHAR(32),
            action VARCHAR(64) NOT NULL,
            resource_type VARCHAR(64) NOT NULL,
            resource_id VARCHAR(128),
            authz_decision VARCHAR(16) NOT NULL,
            guardrail_decisions JSON NOT NULL DEFAULT '[]',
            accessed_document_ids JSON NOT NULL DEFAULT '[]',
            retrieval_scores JSON NOT NULL DEFAULT '[]',
            retrieval_config_version VARCHAR(64),
            llm_provider VARCHAR(64),
            llm_model VARCHAR(64),
            latency_ms REAL,
            prompt_tokens INTEGER,
            completion_tokens INTEGER,
            pipeline_status VARCHAR(32) NOT NULL,
            error_code VARCHAR(64),
            metadata_json JSON NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS ix_audit_logs_req ON audit_logs (request_id);
        CREATE INDEX IF NOT EXISTS ix_audit_logs_ts ON audit_logs (timestamp);
        CREATE INDEX IF NOT EXISTS ix_audit_logs_user ON audit_logs (user_id);
        CREATE INDEX IF NOT EXISTS ix_audit_logs_role ON audit_logs (user_role);
        CREATE INDEX IF NOT EXISTS ix_audit_logs_action ON audit_logs (action);
        "#,
    )
    .execute(&pool)
    .await?;

    // Seed default synthetic users if not present
    let default_users = [
        ("usr-emp-1", "budi.employee", "budi@synthetic.test", "pbkdf2_sha256$200000$72f55050a87feb79dddd6c1b2d75cee2$94815b80dbd71776b716d04bea924b53dda02e660b5a58f9176c9643365f5801", "employee"),
        ("usr-hr-1", "siti.hr", "siti@synthetic.test", "pbkdf2_sha256$200000$1e11de9a5e5d1d1a4860d9d56ed023e4$633572beed005f4ddbd7849c05bde6039513f9100d68248d8536b04c84a3cd69", "hr"),
        ("usr-fin-1", "andi.finance", "andi@synthetic.test", "pbkdf2_sha256$200000$fcb0a2a0ad1571737765c2d13f1cdf4b$5ec0299ccf812a068a266e94148421becf9928b4ee7c6c078432a18a30f2e2bb", "finance"),
        ("usr-exec-1", "dian.exec", "dian@synthetic.test", "pbkdf2_sha256$200000$e9df6158496d04a711d66bba97442a50$e834c9a3c06585a9bfb74892ee803524e59d477f72c530b911405c9e22fe1b6c", "executive"),
        ("usr-adm-1", "rudi.admin", "rudi@synthetic.test", "pbkdf2_sha256$200000$4ca63b8d4ce36dfbd6d9da12918de1bf$212c2fc340f31cd4cac4ea57cf537b75ce71783ce24d9a38add7e54088a03bd9", "admin"),
    ];

    for (uid, uname, email, pwd_hash, role) in default_users {
        sqlx::query(
            "INSERT OR IGNORE INTO users (id, username, email, password_hash, role, explicit_permissions, is_active) VALUES (?, ?, ?, ?, ?, '[]', 1)"
        )
        .bind(uid)
        .bind(uname)
        .bind(email)
        .bind(pwd_hash)
        .bind(role)
        .execute(&pool)
        .await?;
    }

    Ok(pool)
}
