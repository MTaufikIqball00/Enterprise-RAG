pub mod openapi;
pub mod rate_limit;
pub mod routes;

use axum::{
    extract::Extension,
    http::{header, HeaderValue, Method},
    routing::get,
    Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::api::openapi::{openapi_json_handler, swagger_ui_handler};
use crate::api::routes::{create_router, AppState};

pub fn build_app(state: AppState) -> Router {
    let settings = (*state.settings).clone();
    let pool = state.pool.clone();

    let allowed_origins: Vec<HeaderValue> = settings
        .cors_allowed_origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin.trim()).ok())
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins))
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

    let api_router = create_router(state);

    Router::new()
        .route("/docs", get(swagger_ui_handler))
        .route("/api-docs/openapi.json", get(openapi_json_handler))
        .nest("/api/v1", api_router)
        .layer(Extension(settings))
        .layer(Extension(pool))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
}
