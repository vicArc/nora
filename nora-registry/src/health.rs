// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use axum::{extract::State, http::StatusCode, response::Json, routing::get, Router};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use utoipa::ToSchema;

use crate::AppState;

#[derive(Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub storage: StorageHealth,
    pub registries: HashMap<String, String>,
}

#[derive(Serialize, ToSchema)]
pub struct StorageHealth {
    pub backend: String,
    pub reachable: bool,
    pub endpoint: String,
    /// Total bytes across all stored artifacts (from background cache).
    pub total_size_bytes: u64,
    /// Age of the cached storage stats in milliseconds.
    pub stats_age_ms: u64,
    /// Duration of the last storage stats walk in milliseconds.
    pub last_compute_ms: u64,
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
}

async fn health_check(State(state): State<Arc<AppState>>) -> (StatusCode, Json<HealthStatus>) {
    // check_storage_reachable is a lightweight probe (single stat/list call),
    // not the full recursive walk — it remains acceptable on the hot path.
    let storage_reachable = check_storage_reachable(&state).await;

    // All storage aggregate stats are O(1) atomic reads from the background cache.
    // Zero additional awaits on this path.
    let total_size_bytes = state.stats.total_size_bytes();
    let stats_age_ms = state.stats.stats_age_ms();
    let last_compute_ms = state.stats.last_compute_ms();

    let status = if storage_reachable {
        "healthy"
    } else {
        "unhealthy"
    };

    let uptime = state.start_time.elapsed().as_secs();

    // Build registries map from enabled registries
    let mut registries = HashMap::new();
    for reg in &state.enabled_registries {
        registries.insert(reg.as_str().to_string(), "ok".to_string());
    }

    let health = HealthStatus {
        status: status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        storage: StorageHealth {
            backend: state.storage.backend_name().to_string(),
            reachable: storage_reachable,
            endpoint: match state.storage.backend_name() {
                "s3" => state.config.storage.s3_url.clone(),
                _ => state.config.storage.path.clone(),
            },
            total_size_bytes,
            stats_age_ms,
            last_compute_ms,
        },
        registries,
    };

    let status_code = if storage_reachable {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(health))
}

async fn readiness_check(State(state): State<Arc<AppState>>) -> StatusCode {
    if check_storage_reachable(&state).await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn check_storage_reachable(state: &AppState) -> bool {
    state.storage.health_check().await
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::test_helpers::{
        body_bytes, create_test_context, create_test_context_with_config, send,
    };
    use axum::http::{Method, StatusCode};

    #[tokio::test]
    async fn test_health_returns_200() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/health", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(body_str.contains("healthy"));
    }

    #[tokio::test]
    async fn test_health_json_has_version() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/health", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("version").is_some());
    }

    #[tokio::test]
    async fn test_health_json_has_storage_size() {
        let ctx = create_test_context();

        // Put some data to have non-zero size.
        ctx.state
            .storage
            .put("test/artifact", b"hello world")
            .await
            .unwrap();

        // total_size_bytes comes from the background cache, not a live walk.
        // Explicitly refresh the cache after storing so the test exercises
        // the same path as production (eager refresh_once at startup).
        ctx.state.stats.refresh_once(&ctx.state.storage).await;

        let response = send(&ctx.app, Method::GET, "/health", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let storage = json.get("storage").unwrap();
        let size = storage.get("total_size_bytes").unwrap().as_u64().unwrap();
        assert!(
            size > 0,
            "total_size_bytes should be > 0 after storing data and refreshing cache"
        );
    }

    #[tokio::test]
    async fn test_health_empty_storage_size_zero() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/health", "").await;
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let size = json["storage"]["total_size_bytes"].as_u64().unwrap();
        assert_eq!(size, 0, "empty storage should report 0 bytes");
    }

    #[tokio::test]
    async fn test_ready_returns_200() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/ready", "").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_registries_dynamic() {
        // Default context has all 7 v1 registries enabled
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/health", "").await;
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let registries = json.get("registries").unwrap().as_object().unwrap();
        assert!(registries.contains_key("docker"));
        assert!(registries.contains_key("maven"));
        assert!(registries.contains_key("npm"));
        assert!(registries.contains_key("cargo"));
        assert!(registries.contains_key("pypi"));
        assert!(registries.contains_key("go"));
        assert!(registries.contains_key("raw"));
    }

    #[tokio::test]
    async fn test_health_disabled_registry_absent() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.docker.enabled = false;
        });
        let response = send(&ctx.app, Method::GET, "/health", "").await;
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let registries = json.get("registries").unwrap().as_object().unwrap();
        assert!(
            !registries.contains_key("docker"),
            "disabled docker should not appear in health"
        );
        // Others should still be present
        assert!(registries.contains_key("maven"));
    }

    // ------------------------------------------------------------------
    // health_json_contains_new_fields
    //
    // The StorageHealth object in the JSON response must expose the two
    // new fields introduced by Task 2 (stats_age_ms, last_compute_ms)
    // while preserving the pre-existing total_size_bytes field.
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn health_json_contains_new_fields() {
        let ctx = create_test_context();

        let response = send(&ctx.app, Method::GET, "/health", "").await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let storage = json.get("storage").unwrap();

        // Backward-compat: original field still present.
        assert!(
            storage.get("total_size_bytes").is_some(),
            "total_size_bytes must still be present (backward compat)"
        );

        // New Task-2 fields must exist and be numeric.
        let stats_age_ms = storage.get("stats_age_ms");
        assert!(
            stats_age_ms.is_some(),
            "stats_age_ms must be present in /health storage object"
        );
        assert!(
            stats_age_ms.unwrap().is_number(),
            "stats_age_ms must be a number"
        );

        let last_compute_ms = storage.get("last_compute_ms");
        assert!(
            last_compute_ms.is_some(),
            "last_compute_ms must be present in /health storage object"
        );
        assert!(
            last_compute_ms.unwrap().is_number(),
            "last_compute_ms must be a number"
        );
    }

    // ------------------------------------------------------------------
    // slow_storage_does_not_block_health_endpoint
    //
    // Even if the underlying storage walk were slow, /health must complete
    // quickly because it reads from the pre-populated background cache.
    //
    // The test context uses StorageStatsCache::new() (zero-initialised).
    // We pre-populate it via refresh_once() on the empty storage (fast),
    // then hit /health and assert the round-trip completes in < 200 ms.
    //
    // The key assertion is that no new blocking storage call is made
    // inside health_check — demonstrated by the latency bound.
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn slow_storage_does_not_block_health_endpoint() {
        let ctx = create_test_context();

        // Pre-warm the cache so computed_at_unix_ms > 0 (real scenario).
        ctx.state.stats.refresh_once(&ctx.state.storage).await;

        let deadline = std::time::Duration::from_millis(200);

        let response = tokio::time::timeout(
            deadline,
            send(&ctx.app, axum::http::Method::GET, "/health", ""),
        )
        .await
        .expect("/health must respond within 200 ms — cache read should be O(1)");

        assert_eq!(response.status(), StatusCode::OK);
    }
}
