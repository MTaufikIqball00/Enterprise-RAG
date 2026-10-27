use std::time::{SystemTime, UNIX_EPOCH};
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use subtle::ConstantTimeEq;

use crate::core::config::Settings;
use crate::core::enums::UserRole;
use crate::db::models::UserRecord;
use crate::schemas::architecture::AuthenticatedPrincipal;

pub const PBKDF2_ITERATIONS: u32 = 200_000;

pub fn hash_password(plain_password: &str) -> Result<String, String> {
    if plain_password.len() < 8 {
        return Err("Password must be at least 8 characters long.".to_string());
    }
    let mut salt_raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt_raw);
    let salt = hex::encode(salt_raw);

    let mut derived = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
        plain_password.as_bytes(),
        salt.as_bytes(),
        PBKDF2_ITERATIONS,
        &mut derived,
    );
    let derived_hex = hex::encode(derived);

    Ok(format!("pbkdf2_sha256${}${}${}", PBKDF2_ITERATIONS, salt, derived_hex))
}

pub fn verify_password(plain_password: &str, stored_hash: &str) -> bool {
    let parts: Vec<&str> = stored_hash.split('$').collect();
    if parts.len() != 4 {
        return false;
    }
    if parts[0] != "pbkdf2_sha256" {
        return false;
    }
    let iterations: u32 = match parts[1].parse() {
        Ok(i) => i,
        Err(_) => return false,
    };
    let salt = parts[2];
    let expected_hex = parts[3];

    let mut derived = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
        plain_password.as_bytes(),
        salt.as_bytes(),
        iterations,
        &mut derived,
    );
    let candidate_hex = hex::encode(derived);

    candidate_hex.as_bytes().ct_eq(expected_hex.as_bytes()).into()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub role: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

pub fn create_access_token(user: &UserRecord, settings: &Settings) -> Result<String, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;
    let exp = now + (settings.access_token_expire_minutes * 60);

    let mut jti_raw = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut jti_raw);
    let jti = hex::encode(jti_raw);

    let claims = Claims {
        sub: user.id.clone(),
        username: user.username.clone(),
        role: user.role.clone(),
        iat: now,
        exp,
        jti,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(settings.jwt_secret_key.as_bytes()),
    )
    .map_err(|e| e.to_string())
}

pub fn decode_access_token(token: &str, settings: &Settings) -> Result<Claims, (StatusCode, &'static str)> {
    let mut validation = Validation::default();
    validation.validate_exp = true;

    match decode::<Claims>(
        token,
        &DecodingKey::from_secret(settings.jwt_secret_key.as_bytes()),
        &validation,
    ) {
        Ok(data) => Ok(data.claims),
        Err(err) => match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                Err((StatusCode::UNAUTHORIZED, "Token telah kedaluwarsa."))
            }
            _ => Err((StatusCode::UNAUTHORIZED, "Token autentikasi tidak valid.")),
        },
    }
}

pub async fn authenticate_user(
    pool: &SqlitePool,
    username: &str,
    password: &str,
) -> Result<Option<UserRecord>, sqlx::Error> {
    let user = sqlx::query_as::<_, UserRecord>(
        "SELECT id, username, email, password_hash, role, explicit_permissions, is_active, created_at, updated_at FROM users WHERE username = ?",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    if let Some(u) = user {
        if !u.is_active {
            return Ok(None);
        }
        if verify_password(password, &u.password_hash) {
            return Ok(Some(u));
        }
    }
    Ok(None)
}

pub async fn resolve_principal_from_db(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<AuthenticatedPrincipal, (StatusCode, &'static str)> {
    let user = sqlx::query_as::<_, UserRecord>(
        "SELECT id, username, email, password_hash, role, explicit_permissions, is_active, created_at, updated_at FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
    .ok_or((StatusCode::UNAUTHORIZED, "Identitas pengguna tidak ditemukan atau tidak aktif."))?;

    if !user.is_active {
        return Err((StatusCode::UNAUTHORIZED, "Identitas pengguna tidak ditemukan atau tidak aktif."));
    }

    let role = UserRole::from_str_opt(&user.role)
        .ok_or((StatusCode::FORBIDDEN, "Role pengguna tidak dikenali oleh kebijakan keamanan."))?;

    let explicit_permissions: Vec<String> = serde_json::from_str(&user.explicit_permissions)
        .unwrap_or_default();

    Ok(AuthenticatedPrincipal {
        user_id: user.id,
        username: user.username,
        email: user.email,
        role,
        explicit_permissions,
        is_active: user.is_active,
    })
}

// Axum custom extractor for AuthenticatedPrincipal
#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedPrincipal
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());

        let token = match auth_header {
            Some(h) if h.starts_with("Bearer ") => &h[7..],
            _ => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "detail": "Autentikasi diperlukan (Bearer token tidak ditemukan)."
                    })),
                )
                    .into_response());
            }
        };

        // Extract settings and pool from request extensions
        let settings = parts
            .extensions
            .get::<Settings>()
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "detail": "Missing settings extension" })),
                )
                    .into_response()
            })?;

        let pool = parts
            .extensions
            .get::<SqlitePool>()
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "detail": "Missing database pool extension" })),
                )
                    .into_response()
            })?;

        let claims = decode_access_token(token, settings).map_err(|(code, msg)| {
            (code, Json(serde_json::json!({ "detail": msg }))).into_response()
        })?;

        let principal = resolve_principal_from_db(pool, &claims.sub)
            .await
            .map_err(|(code, msg)| {
                (code, Json(serde_json::json!({ "detail": msg }))).into_response()
            })?;

        Ok(principal)
    }
}
