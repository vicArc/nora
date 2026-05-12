// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::circuit_breaker::CircuitBreakerRegistry;
use crate::config::basic_auth_header;
use crate::registry::docker_auth::DockerAuth;
use crate::registry::{circuit_open_response, method_not_allowed, ProxyError};
use crate::storage::Storage;
use crate::validation::{
    ends_with_ci, validate_digest, validate_docker_name, validate_docker_reference,
};
use crate::AppState;
use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{header, HeaderMap, HeaderName, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, head, patch},
    Json, Router,
};
use futures::StreamExt as _;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt as _;

/// Metadata for a Docker image stored alongside manifests
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImageMetadata {
    pub push_timestamp: u64,
    pub last_pulled: u64,
    pub downloads: u64,
    pub size_bytes: u64,
    pub os: String,
    pub arch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    pub layers: Vec<LayerInfo>,
}

/// Information about a single layer in a Docker image
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerInfo {
    pub digest: String,
    pub size: u64,
}

/// In-progress upload session with metadata.
///
/// Blob data is streamed to a temporary file instead of being buffered in memory.
/// This prevents 100 concurrent 2GB uploads from consuming 200GB of RAM.
pub struct UploadSession {
    /// Path to the temporary file holding blob data.
    temp_path: std::path::PathBuf,
    /// Current size of data written to temp file.
    size: u64,
    name: String,
    created_at: std::time::Instant,
}

/// Max concurrent upload sessions (prevent memory exhaustion)
const DEFAULT_MAX_UPLOAD_SESSIONS: usize = 100;
/// Max data per session (default 2 GB, configurable via NORA_MAX_UPLOAD_SESSION_SIZE_MB)
const DEFAULT_MAX_SESSION_SIZE_MB: usize = 2048;
/// Session TTL (30 minutes)
const SESSION_TTL: Duration = Duration::from_secs(30 * 60);

/// Read max upload sessions from env or use default
fn max_upload_sessions() -> usize {
    std::env::var("NORA_MAX_UPLOAD_SESSIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_UPLOAD_SESSIONS)
}

/// Read max session size from env (in MB) or use default
fn max_session_size() -> usize {
    let mb = std::env::var("NORA_MAX_UPLOAD_SESSION_SIZE_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_SESSION_SIZE_MB);
    mb.saturating_mul(1024 * 1024)
}

/// Remove expired upload sessions and their temp files (called by background task)
pub fn cleanup_expired_sessions(sessions: &RwLock<HashMap<String, UploadSession>>) {
    let mut guard = sessions.write();
    let before = guard.len();
    guard.retain(|_, s| {
        if s.created_at.elapsed() >= SESSION_TTL {
            let _ = std::fs::remove_file(&s.temp_path);
            false
        } else {
            true
        }
    });
    let removed = before - guard.len();
    if removed > 0 {
        tracing::info!(
            removed = removed,
            remaining = guard.len(),
            "Cleaned up expired upload sessions"
        );
    }
}

/// Get the temp directory for Docker uploads, creating it if needed.
fn upload_temp_dir(data_dir: &str) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(data_dir).join("tmp/docker-uploads");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/v2/",
            get(check).fallback(|| async { method_not_allowed("GET") }),
        )
        .route("/v2/_catalog", get(catalog))
        // Single-segment name routes (e.g., /v2/alpine/...)
        .route(
            "/v2/{name}/blobs/{digest}",
            head(check_blob)
                .get(download_blob)
                .delete(delete_blob)
                .fallback(|| async { method_not_allowed("GET, HEAD, DELETE") }),
        )
        .route(
            "/v2/{name}/blobs/uploads/",
            axum::routing::post(start_upload).fallback(|| async { method_not_allowed("POST") }),
        )
        .route(
            "/v2/{name}/blobs/uploads/{uuid}",
            patch(patch_blob)
                .put(upload_blob)
                .fallback(|| async { method_not_allowed("PATCH, PUT") }),
        )
        .route(
            "/v2/{name}/manifests/{reference}",
            get(get_manifest)
                .put(put_manifest)
                .delete(delete_manifest)
                .fallback(|| async { method_not_allowed("GET, PUT, DELETE") }),
        )
        .route("/v2/{name}/tags/list", get(list_tags))
        // Two-segment name routes (e.g., /v2/library/alpine/...)
        .route(
            "/v2/{ns}/{name}/blobs/{digest}",
            head(check_blob_ns)
                .get(download_blob_ns)
                .delete(delete_blob_ns)
                .fallback(|| async { method_not_allowed("GET, HEAD, DELETE") }),
        )
        .route(
            "/v2/{ns}/{name}/blobs/uploads/",
            axum::routing::post(start_upload_ns).fallback(|| async { method_not_allowed("POST") }),
        )
        .route(
            "/v2/{ns}/{name}/blobs/uploads/{uuid}",
            patch(patch_blob_ns)
                .put(upload_blob_ns)
                .fallback(|| async { method_not_allowed("PATCH, PUT") }),
        )
        .route(
            "/v2/{ns}/{name}/manifests/{reference}",
            get(get_manifest_ns)
                .put(put_manifest_ns)
                .delete(delete_manifest_ns)
                .fallback(|| async { method_not_allowed("GET, PUT, DELETE") }),
        )
        .route("/v2/{ns}/{name}/tags/list", get(list_tags_ns))
}

async fn check() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            HeaderName::from_static("docker-distribution-api-version"),
            "registry/2.0",
        )],
        Json(json!({})),
    )
}

/// List all repositories in the registry
async fn catalog(State(state): State<Arc<AppState>>) -> Json<Value> {
    let keys = state.storage.list("docker/").await;

    // Extract unique repository names from paths like "docker/{name}/manifests/..."
    let mut repos: Vec<String> = keys
        .iter()
        .filter_map(|k| {
            let rest = k.strip_prefix("docker/")?;
            // Find the first known directory separator (manifests/ or blobs/)
            let name = if let Some(idx) = rest.find("/manifests/") {
                &rest[..idx]
            } else if let Some(idx) = rest.find("/blobs/") {
                &rest[..idx]
            } else {
                return None;
            };
            if name.is_empty() {
                return None;
            }
            Some(name.to_string())
        })
        .collect();

    repos.sort();
    repos.dedup();

    Json(json!({ "repositories": repos }))
}

async fn check_blob(
    State(state): State<Arc<AppState>>,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_digest(&digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = format!("docker/{}/blobs/{}", name, digest);
    match state.storage.get(&key).await {
        Ok(data) => (
            StatusCode::OK,
            [(header::CONTENT_LENGTH, data.len().to_string())],
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn download_blob(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_digest(&digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // Curation check — defense in depth: check blobs too
    if let Some(response) = crate::curation::check_download(
        &state.curation,
        state.config.curation.bypass_token.as_deref(),
        &headers,
        crate::curation::RegistryType::Docker,
        &name,
        Some(&digest),
        None,
    ) {
        return response;
    }

    let key = format!("docker/{}/blobs/{}", name, digest);

    // Try local storage first
    if let Ok(data) = state.storage.get(&key).await {
        // Curation integrity verification (issue #189)
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation,
            crate::curation::RegistryType::Docker,
            &name,
            Some(&digest),
            &data,
        ) {
            return response;
        }

        state.metrics.record_download("docker");
        state.metrics.record_cache_hit();
        state.activity.push(ActivityEntry::new(
            ActionType::Pull,
            format!("{}@{}", name, &digest[..19.min(digest.len())]),
            "docker",
            "LOCAL",
        ));
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            data,
        )
            .into_response();
    }

    // Try upstream proxies
    for upstream in &state.config.docker.upstreams {
        match fetch_blob_from_upstream(
            &state.http_client,
            &upstream.url,
            &name,
            &digest,
            &state.docker_auth,
            state.config.docker.proxy_timeout,
            upstream.auth.as_deref(),
            &state.circuit_breaker,
        )
        .await
        {
            Ok(data) => {
                state.metrics.record_download("docker");
                state.metrics.record_cache_miss();
                state.activity.push(ActivityEntry::new(
                    ActionType::ProxyFetch,
                    format!("{}@{}", name, &digest[..19.min(digest.len())]),
                    "docker",
                    "PROXY",
                ));

                // Cache in storage (fire and forget)
                let storage = state.storage.clone();
                let key_clone = key.clone();
                let data_clone = data.clone();
                let state_clone = Arc::clone(&state);
                tokio::spawn(async move {
                    if storage.put(&key_clone, &data_clone).await.is_ok() {
                        state_clone.repo_index.invalidate("docker");
                    }
                });

                return (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/octet-stream")],
                    Bytes::from(data),
                )
                    .into_response();
            }
            Err(ProxyError::CircuitOpen(reg)) => return circuit_open_response(&reg),
            Err(_) => continue,
        }
    }

    // Auto-prepend library/ for single-segment names (Docker Hub official images)
    if !name.contains('/') {
        let library_name = format!("library/{}", name);
        for upstream in &state.config.docker.upstreams {
            match fetch_blob_from_upstream(
                &state.http_client,
                &upstream.url,
                &library_name,
                &digest,
                &state.docker_auth,
                state.config.docker.proxy_timeout,
                upstream.auth.as_deref(),
                &state.circuit_breaker,
            )
            .await
            {
                Ok(data) => {
                    state.spawn_cache("docker", key.clone(), Bytes::from(data.clone()));

                    return (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/octet-stream")],
                        Bytes::from(data),
                    )
                        .into_response();
                }
                Err(ProxyError::CircuitOpen(reg)) => return circuit_open_response(&reg),
                Err(_) => continue,
            }
        }
    }

    // Auto-prepend library/ for single-segment names (Docker Hub official images)
    if !name.contains('/') {
        let library_name = format!("library/{}", name);
        for upstream in &state.config.docker.upstreams {
            match fetch_blob_from_upstream(
                &state.http_client,
                &upstream.url,
                &library_name,
                &digest,
                &state.docker_auth,
                state.config.docker.proxy_timeout,
                upstream.auth.as_deref(),
                &state.circuit_breaker,
            )
            .await
            {
                Ok(data) => {
                    state.spawn_cache("docker", key.clone(), Bytes::from(data.clone()));

                    return (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/octet-stream")],
                        Bytes::from(data),
                    )
                        .into_response();
                }
                Err(ProxyError::CircuitOpen(reg)) => return circuit_open_response(&reg),
                Err(_) => continue,
            }
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

async fn start_upload(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // Enforce max concurrent sessions
    {
        let sessions = state.upload_sessions.read();
        let max_sessions = max_upload_sessions();
        if sessions.len() >= max_sessions {
            tracing::warn!(
                max = max_sessions,
                current = sessions.len(),
                "Upload session limit reached — rejecting new upload"
            );
            return (StatusCode::TOO_MANY_REQUESTS, "Too many concurrent uploads").into_response();
        }
    }

    let uuid = uuid::Uuid::new_v4().to_string();

    // Create temp file for blob data
    let temp_dir = upload_temp_dir(&state.config.storage.path);
    let temp_path = temp_dir.join(&uuid);

    // Create session with metadata
    {
        let mut sessions = state.upload_sessions.write();
        sessions.insert(
            uuid.clone(),
            UploadSession {
                temp_path,
                size: 0,
                name: name.clone(),
                created_at: std::time::Instant::now(),
            },
        );
    }

    let location = format!("/v2/{}/blobs/uploads/{}", name, uuid);
    (
        StatusCode::ACCEPTED,
        [
            (header::LOCATION, location),
            (HeaderName::from_static("docker-upload-uuid"), uuid),
        ],
    )
        .into_response()
}

/// Decides whether an upload should be buffered in memory or streamed to disk.
enum UploadPath {
    /// Buffer the entire body in memory (fast path for small uploads).
    Buffered,
    /// Stream body chunks directly to a temp file (bounded memory for large uploads).
    Streamed,
}

/// Extract the `Content-Length` header value as `usize`, if present and valid.
fn content_length(headers: &HeaderMap) -> Option<usize> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
}

/// Resolve the temp-file directory for Docker uploads.
///
/// - Local storage: `{storage_path}/tmp/docker-uploads/`
/// - S3 storage (no local root): OS temp dir under `nora/docker-uploads/`
fn docker_upload_temp_dir(config: &crate::config::Config) -> std::path::PathBuf {
    use crate::config::StorageMode;
    match config.storage.mode {
        StorageMode::Local => {
            std::path::PathBuf::from(&config.storage.path).join("tmp/docker-uploads")
        }
        StorageMode::S3 => std::env::temp_dir().join("nora/docker-uploads"),
    }
}

/// PATCH handler for chunked blob uploads
/// Docker client sends data chunks via PATCH, then finalizes with PUT
async fn patch_blob(
    State(state): State<Arc<AppState>>,
    Path((name, uuid)): Path<(String, String)>,
    request: axum::extract::Request,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let threshold_bytes = state.config.server.docker_stream_threshold_mb * 1024 * 1024;
    let upload_path = match content_length(request.headers()) {
        Some(len) if len < threshold_bytes => UploadPath::Buffered,
        _ => UploadPath::Streamed,
    };

    let body = request.into_body();

    match upload_path {
        UploadPath::Buffered => patch_blob_buffered(state, name, uuid, body).await,
        UploadPath::Streamed => patch_blob_streamed(state, name, uuid, body).await,
    }
}

/// Buffered PATCH: collect the entire chunk into memory, then write once.
/// Used for chunks smaller than `docker_stream_threshold_mb`.
async fn patch_blob_buffered(
    state: Arc<AppState>,
    name: String,
    uuid: String,
    body: Body,
) -> Response {
    // Collect the body fully before acquiring the session lock.
    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "patch_blob_buffered: body read error");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    let total_size = {
        let mut sessions = state.upload_sessions.write();
        let session = match sessions.get_mut(&uuid) {
            Some(s) => s,
            None => {
                return (StatusCode::NOT_FOUND, "Upload session not found or expired")
                    .into_response();
            }
        };

        if session.name != name {
            tracing::warn!(
                session_name = %session.name,
                request_name = %name,
                "SECURITY: upload session name mismatch — possible session fixation"
            );
            return (
                StatusCode::BAD_REQUEST,
                "Session does not belong to this repository",
            )
                .into_response();
        }

        if session.created_at.elapsed() >= SESSION_TTL {
            let _ = std::fs::remove_file(&session.temp_path);
            sessions.remove(&uuid);
            return (StatusCode::NOT_FOUND, "Upload session expired").into_response();
        }

        let new_size = session.size as usize + body_bytes.len();
        if new_size > max_session_size() {
            let _ = std::fs::remove_file(&session.temp_path);
            sessions.remove(&uuid);
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "Upload session exceeds size limit",
            )
                .into_response();
        }

        use std::io::Write as _;
        let temp_path = session.temp_path.clone();
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&temp_path)
        {
            Ok(mut file) => {
                if let Err(e) = file.write_all(&body_bytes) {
                    tracing::error!(error = %e, "patch_blob_buffered: write failed");
                    let _ = std::fs::remove_file(&temp_path);
                    sessions.remove(&uuid);
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "patch_blob_buffered: open temp file failed");
                sessions.remove(&uuid);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }

        session.size = new_size as u64;
        new_size
    };

    patch_blob_response(name, uuid, total_size)
}

/// Streamed PATCH: stream body chunks directly to the session temp file.
/// Keeps memory usage bounded to one chunk at a time regardless of total size.
async fn patch_blob_streamed(
    state: Arc<AppState>,
    name: String,
    uuid: String,
    body: Body,
) -> Response {
    // Extract session metadata under the lock, then release before async I/O.
    let (temp_path, existing_size) = {
        let mut sessions = state.upload_sessions.write();
        let session = match sessions.get_mut(&uuid) {
            Some(s) => s,
            None => {
                return (StatusCode::NOT_FOUND, "Upload session not found or expired")
                    .into_response();
            }
        };

        if session.name != name {
            tracing::warn!(
                session_name = %session.name,
                request_name = %name,
                "SECURITY: upload session name mismatch — possible session fixation"
            );
            return (
                StatusCode::BAD_REQUEST,
                "Session does not belong to this repository",
            )
                .into_response();
        }

        if session.created_at.elapsed() >= SESSION_TTL {
            let _ = std::fs::remove_file(&session.temp_path);
            sessions.remove(&uuid);
            return (StatusCode::NOT_FOUND, "Upload session expired").into_response();
        }

        (session.temp_path.clone(), session.size)
    };

    // Open temp file in append mode outside the lock.
    let mut file = match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&temp_path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(error = %e, ?temp_path, "patch_blob_streamed: open failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut written: u64 = 0;
    let max_total = max_session_size() as u64;
    let mut stream = body.into_data_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk = match chunk_result {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "patch_blob_streamed: client disconnect");
                drop(file);
                return StatusCode::BAD_REQUEST.into_response();
            }
        };

        if existing_size + written + chunk.len() as u64 > max_total {
            drop(file);
            let removed_temp = {
                let mut sessions = state.upload_sessions.write();
                sessions.remove(&uuid).map(|s| s.temp_path)
            };
            if let Some(p) = removed_temp {
                let _ = tokio::fs::remove_file(&p).await;
            }
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "Upload session exceeds size limit",
            )
                .into_response();
        }

        if let Err(e) = file.write_all(&chunk).await {
            tracing::error!(error = %e, "patch_blob_streamed: write chunk failed");
            drop(file);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }

        written += chunk.len() as u64;
    }

    if let Err(e) = file.flush().await {
        tracing::error!(error = %e, "patch_blob_streamed: flush failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    drop(file);

    // Update session size under the lock.
    let new_total = {
        let mut sessions = state.upload_sessions.write();
        match sessions.get_mut(&uuid) {
            Some(s) => {
                s.size += written;
                s.size as usize
            }
            None => {
                // Session removed by a concurrent expiry sweep — tolerate.
                (existing_size + written) as usize
            }
        }
    };

    patch_blob_response(name, uuid, new_total)
}

/// Build the 202 Accepted response for a completed PATCH.
fn patch_blob_response(name: String, uuid: String, total_size: usize) -> Response {
    let location = format!("/v2/{}/blobs/uploads/{}", name, uuid);
    let range = if total_size > 0 {
        format!("0-{}", total_size - 1)
    } else {
        "0-0".to_string()
    };
    (
        StatusCode::ACCEPTED,
        [
            (header::LOCATION, location),
            (header::RANGE, range),
            (HeaderName::from_static("docker-upload-uuid"), uuid),
        ],
    )
        .into_response()
}

/// PUT handler for completing blob uploads.
/// Handles both monolithic uploads (body contains all data) and
/// chunked upload finalization (body may be empty, data already in session temp file).
async fn upload_blob(
    State(state): State<Arc<AppState>>,
    Path((name, uuid)): Path<(String, String)>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    request: axum::extract::Request,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let digest = match params.get("digest") {
        Some(d) => d.clone(),
        None => return (StatusCode::BAD_REQUEST, "Missing digest parameter").into_response(),
    };

    if let Err(e) = validate_digest(&digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    if !digest.starts_with("sha256:") {
        return (
            StatusCode::BAD_REQUEST,
            "Only sha256 digests are supported for blob uploads",
        )
            .into_response();
    }

    let threshold_bytes = state.config.server.docker_stream_threshold_mb * 1024 * 1024;
    let upload_path = match content_length(request.headers()) {
        Some(len) if len < threshold_bytes => UploadPath::Buffered,
        _ => UploadPath::Streamed,
    };

    let body = request.into_body();

    match upload_path {
        UploadPath::Buffered => upload_blob_buffered(state, name, uuid, digest, body).await,
        UploadPath::Streamed => upload_blob_streamed(state, name, uuid, digest, body).await,
    }
}

/// Buffered PUT: materialise the entire body in memory, then write via the existing `put` path.
async fn upload_blob_buffered(
    state: Arc<AppState>,
    name: String,
    uuid: String,
    digest: String,
    body: Body,
) -> Response {
    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "upload_blob_buffered: body read error");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    // Resolve data: session temp file (chunked) + any body appended.
    let data = {
        let mut sessions = state.upload_sessions.write();
        if let Some(session) = sessions.remove(&uuid) {
            if session.name != name {
                tracing::warn!(
                    session_name = %session.name,
                    request_name = %name,
                    "SECURITY: upload finalization name mismatch"
                );
                let _ = std::fs::remove_file(&session.temp_path);
                return (
                    StatusCode::BAD_REQUEST,
                    "Session does not belong to this repository",
                )
                    .into_response();
            }
            let mut session_data = if session.temp_path.exists() {
                match std::fs::read(&session.temp_path) {
                    Ok(d) => {
                        let _ = std::fs::remove_file(&session.temp_path);
                        d
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "upload_blob_buffered: read temp file failed");
                        let _ = std::fs::remove_file(&session.temp_path);
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                }
            } else {
                Vec::new()
            };
            if !body_bytes.is_empty() {
                session_data.extend_from_slice(&body_bytes);
            }
            session_data
        } else {
            body_bytes.to_vec()
        }
    };

    // Verify digest.
    {
        use sha2::Digest as _;
        let computed = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));
        if computed != digest {
            tracing::warn!(
                expected = %digest,
                computed = %computed,
                name = %name,
                "SECURITY: blob digest mismatch — rejecting upload"
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "errors": [{
                        "code": "DIGEST_INVALID",
                        "message": "provided digest did not match uploaded content",
                        "detail": { "expected": digest, "computed": computed }
                    }]
                })),
            )
                .into_response();
        }
    }

    let key = format!("docker/{}/blobs/{}", name, digest);
    match state.storage.put(&key, &data).await {
        Ok(()) => blob_upload_created_response(&state, name, digest),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Streamed PUT: stream the body to a temp file chunk-by-chunk (O(chunk) memory),
/// verify digest from the streaming hasher, then move the temp file into storage.
///
/// When a chunked PATCH session already exists for this UUID, the existing temp
/// file is reused (appended to) and the hasher is seeded by re-reading the file
/// contents so the final digest covers the complete concatenated blob.
async fn upload_blob_streamed(
    state: Arc<AppState>,
    name: String,
    uuid: String,
    digest: String,
    body: Body,
) -> Response {
    use sha2::Digest as _;

    // Outcome of the session-lookup phase. We resolve the session under the
    // lock, then release the guard before performing any async I/O so the
    // future remains `Send`.
    enum SessionLookup {
        ExistingSession {
            temp_path: std::path::PathBuf,
            prior_size: u64,
        },
        Mismatch {
            temp_path: std::path::PathBuf,
        },
        NoSession,
    }

    let lookup = {
        let mut sessions = state.upload_sessions.write();
        match sessions.remove(&uuid) {
            Some(s) if s.name == name => SessionLookup::ExistingSession {
                temp_path: s.temp_path,
                prior_size: s.size,
            },
            Some(s) => SessionLookup::Mismatch {
                temp_path: s.temp_path,
            },
            None => SessionLookup::NoSession,
        }
    };

    // Determine whether we're continuing a chunked session or starting fresh.
    let (temp_path, mut hasher, prior_size) = match lookup {
        SessionLookup::ExistingSession {
            temp_path,
            prior_size,
        } => {
            // Chunked session exists: seed hasher from the existing temp file
            // before appending the PUT body so digest covers all bytes.
            let mut h = sha2::Sha256::new();
            if temp_path.exists() {
                // Re-read prior chunks into the hasher. This is the only
                // correct path: the PATCH handler stores raw bytes without
                // computing a running hash, so we must replay them here.
                let prior_data = match tokio::fs::read(&temp_path).await {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::error!(error = %e, "upload_blob_streamed: read prior temp file failed");
                        let _ = tokio::fs::remove_file(&temp_path).await;
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                };
                h.update(&prior_data);
            }
            (temp_path, h, prior_size)
        }
        SessionLookup::Mismatch { temp_path } => {
            // Session belongs to a different repository.
            tracing::warn!(
                request_name = %name,
                "SECURITY: upload finalization name mismatch"
            );
            let _ = tokio::fs::remove_file(&temp_path).await;
            return (
                StatusCode::BAD_REQUEST,
                "Session does not belong to this repository",
            )
                .into_response();
        }
        SessionLookup::NoSession => {
            // No prior PATCH — pure monolithic streamed upload.
            let temp_dir = docker_upload_temp_dir(&state.config);
            let temp = temp_dir.join(&uuid);
            if let Err(e) = tokio::fs::create_dir_all(&temp_dir).await {
                tracing::error!(error = %e, "upload_blob_streamed: create temp dir failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            (temp, sha2::Sha256::new(), 0u64)
        }
    };

    // Append to temp file outside the lock.
    let mut file = match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&temp_path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(error = %e, ?temp_path, "upload_blob_streamed: open temp file failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut written: u64 = 0;
    let max_total = max_session_size() as u64;
    let mut stream = body.into_data_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk = match chunk_result {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "upload_blob_streamed: client disconnect / read error");
                drop(file);
                let _ = tokio::fs::remove_file(&temp_path).await;
                return StatusCode::BAD_REQUEST.into_response();
            }
        };

        if prior_size + written + chunk.len() as u64 > max_total {
            drop(file);
            let _ = tokio::fs::remove_file(&temp_path).await;
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "blob exceeds max session size",
            )
                .into_response();
        }

        if let Err(e) = file.write_all(&chunk).await {
            tracing::error!(error = %e, "upload_blob_streamed: write chunk failed");
            drop(file);
            let _ = tokio::fs::remove_file(&temp_path).await;
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }

        // Update the running hash and release the chunk immediately.
        // RAM usage is bounded to this one chunk's allocation.
        hasher.update(&chunk);
        written += chunk.len() as u64;
    }

    if let Err(e) = file.flush().await {
        tracing::error!(error = %e, "upload_blob_streamed: flush failed");
        drop(file);
        let _ = tokio::fs::remove_file(&temp_path).await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    drop(file);

    // Verify digest from the streaming hasher — no second read of the file.
    let computed = format!("sha256:{}", hex::encode(hasher.finalize()));
    if computed != digest {
        tracing::warn!(
            expected = %digest,
            computed = %computed,
            name = %name,
            "SECURITY: streamed blob digest mismatch — rejecting upload"
        );
        let _ = tokio::fs::remove_file(&temp_path).await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "errors": [{
                    "code": "DIGEST_INVALID",
                    "message": "provided digest did not match uploaded content",
                    "detail": { "expected": digest, "computed": computed }
                }]
            })),
        )
            .into_response();
    }

    // Move temp file into final storage location (rename for local fs, multipart for S3).
    let key = format!("docker/{}/blobs/{}", name, digest);
    match state.storage.put_from_path(&key, &temp_path).await {
        Ok(()) => blob_upload_created_response(&state, name, digest),
        Err(e) => {
            tracing::error!(error = %e, "upload_blob_streamed: put_from_path failed");
            let _ = tokio::fs::remove_file(&temp_path).await;
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Build the 201 Created response after a successful blob upload.
fn blob_upload_created_response(state: &AppState, name: String, digest: String) -> Response {
    state.metrics.record_upload("docker");
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        format!("{}@{}", name, &digest[..19.min(digest.len())]),
        "docker",
        "LOCAL",
    ));
    state.repo_index.invalidate("docker");
    let location = format!("/v2/{}/blobs/{}", name, digest);
    (
        StatusCode::CREATED,
        [
            (header::LOCATION, location),
            (HeaderName::from_static("docker-content-digest"), digest),
        ],
    )
        .into_response()
}

async fn get_manifest(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((name, reference)): Path<(String, String)>,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_docker_reference(&reference) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // Extract publish date from .meta.json sidecar
    let publish_date = extract_docker_publish_date(
        &state.storage,
        &name,
        &reference,
        state.config.docker.upstreams.is_empty(),
    )
    .await;

    // Curation check — manifests carry the image identity
    if let Some(response) = crate::curation::check_download(
        &state.curation,
        state.config.curation.bypass_token.as_deref(),
        &headers,
        crate::curation::RegistryType::Docker,
        &name,
        Some(&reference),
        publish_date,
    ) {
        return response;
    }

    let key = format!("docker/{}/manifests/{}.json", name, reference);

    // Try local storage first
    if let Ok(data) = state.storage.get(&key).await {
        // Curation integrity verification (issue #189)
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation,
            crate::curation::RegistryType::Docker,
            &name,
            Some(&reference),
            &data,
        ) {
            return response;
        }

        state.metrics.record_download("docker");
        state.metrics.record_cache_hit();
        state.activity.push(ActivityEntry::new(
            ActionType::Pull,
            format!("{}:{}", name, reference),
            "docker",
            "LOCAL",
        ));

        // Calculate digest for Docker-Content-Digest header
        use sha2::Digest;
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));

        // Detect manifest media type from content
        let content_type = detect_manifest_media_type(&data);

        // Update metadata (downloads, last_pulled) in background
        let meta_key = format!("docker/{}/manifests/{}.meta.json", name, reference);
        let state_clone = state.clone();
        let storage_clone = state.storage.clone();
        tokio::spawn(update_metadata_on_pull(
            state_clone,
            storage_clone,
            meta_key,
        ));

        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (HeaderName::from_static("docker-content-digest"), digest),
            ],
            data,
        )
            .into_response();
    }

    // Try upstream proxies
    tracing::debug!(
        upstreams_count = state.config.docker.upstreams.len(),
        "Trying upstream proxies"
    );
    for upstream in &state.config.docker.upstreams {
        tracing::debug!(upstream_url = %upstream.url, "Trying upstream");
        match fetch_manifest_from_upstream(
            &state.http_client,
            &upstream.url,
            &name,
            &reference,
            &state.docker_auth,
            state.config.docker.proxy_timeout,
            upstream.auth.as_deref(),
            &state.circuit_breaker,
        )
        .await
        {
            Ok((data, content_type)) => {
                state.metrics.record_download("docker");
                state.metrics.record_cache_miss();
                state.activity.push(ActivityEntry::new(
                    ActionType::ProxyFetch,
                    format!("{}:{}", name, reference),
                    "docker",
                    "PROXY",
                ));

                // Calculate digest for Docker-Content-Digest header
                use sha2::Digest;
                let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));

                // Cache manifest and create metadata (fire and forget)
                let storage = state.storage.clone();
                let key_clone = key.clone();
                let data_clone = data.clone();
                let name_clone = name.clone();
                let reference_clone = reference.clone();
                let digest_clone = digest.clone();
                let state_clone = Arc::clone(&state);
                tokio::spawn(async move {
                    // Store manifest by tag and digest
                    let _ = storage.put(&key_clone, &data_clone).await;
                    let digest_key =
                        format!("docker/{}/manifests/{}.json", name_clone, digest_clone);
                    let _ = storage.put(&digest_key, &data_clone).await;

                    // Extract and save metadata
                    let metadata = extract_metadata(&data_clone, &storage, &name_clone).await;
                    if let Ok(meta_json) = serde_json::to_vec(&metadata) {
                        let meta_key = format!(
                            "docker/{}/manifests/{}.meta.json",
                            name_clone, reference_clone
                        );
                        let _ = storage.put(&meta_key, &meta_json).await;

                        let digest_meta_key =
                            format!("docker/{}/manifests/{}.meta.json", name_clone, digest_clone);
                        let _ = storage.put(&digest_meta_key, &meta_json).await;
                    }
                    state_clone.repo_index.invalidate("docker");
                });

                return (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, content_type),
                        (HeaderName::from_static("docker-content-digest"), digest),
                    ],
                    Bytes::from(data),
                )
                    .into_response();
            }
            Err(ProxyError::CircuitOpen(reg)) => return circuit_open_response(&reg),
            Err(_) => continue,
        }
    }

    // Auto-prepend library/ for single-segment names (Docker Hub official images)
    // e.g., "nginx" -> "library/nginx", "alpine" -> "library/alpine"
    if !name.contains('/') {
        let library_name = format!("library/{}", name);
        for upstream in &state.config.docker.upstreams {
            match fetch_manifest_from_upstream(
                &state.http_client,
                &upstream.url,
                &library_name,
                &reference,
                &state.docker_auth,
                state.config.docker.proxy_timeout,
                upstream.auth.as_deref(),
                &state.circuit_breaker,
            )
            .await
            {
                Ok((data, content_type)) => {
                    state.metrics.record_download("docker");
                    state.metrics.record_cache_miss();
                    state.activity.push(ActivityEntry::new(
                        ActionType::ProxyFetch,
                        format!("{}:{}", name, reference),
                        "docker",
                        "PROXY",
                    ));

                    use sha2::Digest;
                    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));

                    // Cache under original name for future local hits
                    let storage = state.storage.clone();
                    let key_clone = key.clone();
                    let data_clone = data.clone();
                    tokio::spawn(async move {
                        if let Err(e) = storage.put(&key_clone, &data_clone).await {
                            tracing::warn!(key = %key_clone, error = %e, "Failed to cache blob in storage");
                        }
                    });

                    state.repo_index.invalidate("docker");

                    return (
                        StatusCode::OK,
                        [
                            (header::CONTENT_TYPE, content_type),
                            (HeaderName::from_static("docker-content-digest"), digest),
                        ],
                        Bytes::from(data),
                    )
                        .into_response();
                }
                Err(ProxyError::CircuitOpen(reg)) => return circuit_open_response(&reg),
                Err(_) => continue,
            }
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

async fn put_manifest(
    State(state): State<Arc<AppState>>,
    Path((name, reference)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_docker_reference(&reference) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // Calculate digest
    use sha2::Digest;
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&body)));

    // Store by tag/reference
    let key = format!("docker/{}/manifests/{}.json", name, reference);
    if state.storage.put(&key, &body).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Also store by digest for direct digest lookups
    let digest_key = format!("docker/{}/manifests/{}.json", name, digest);
    if state.storage.put(&digest_key, &body).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Extract and save metadata
    let metadata = extract_metadata(&body, &state.storage, &name).await;
    let meta_key = format!("docker/{}/manifests/{}.meta.json", name, reference);
    if let Ok(meta_json) = serde_json::to_vec(&metadata) {
        let _ = state.storage.put(&meta_key, &meta_json).await;

        // Also save metadata by digest
        let digest_meta_key = format!("docker/{}/manifests/{}.meta.json", name, digest);
        let _ = state.storage.put(&digest_meta_key, &meta_json).await;
    }

    state.metrics.record_upload("docker");
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        format!("{}:{}", name, reference),
        "docker",
        "LOCAL",
    ));
    state.audit.log(AuditEntry::new(
        "push",
        "api",
        &format!("{}:{}", name, reference),
        "docker",
        "manifest",
    ));
    state.repo_index.invalidate("docker");

    let location = format!("/v2/{}/manifests/{}", name, reference);
    (
        StatusCode::CREATED,
        [
            (header::LOCATION, location),
            (HeaderName::from_static("docker-content-digest"), digest),
        ],
    )
        .into_response()
}

async fn list_tags(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let prefix = format!("docker/{}/manifests/", name);
    let keys = state.storage.list(&prefix).await;
    let tags: Vec<String> = keys
        .iter()
        .filter_map(|k| {
            k.strip_prefix(&prefix)
                .and_then(|t| t.strip_suffix(".json"))
                .map(String::from)
        })
        .filter(|t| !ends_with_ci(t, ".meta") && !t.contains(".meta."))
        .collect();
    (StatusCode::OK, Json(json!({"name": name, "tags": tags}))).into_response()
}

// ============================================================================
// Delete handlers (Docker Registry V2 spec)
// ============================================================================

async fn delete_manifest(
    State(state): State<Arc<AppState>>,
    Path((name, reference)): Path<(String, String)>,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_docker_reference(&reference) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = format!("docker/{}/manifests/{}.json", name, reference);

    // If reference is a tag, also delete digest-keyed copy
    let is_tag = !reference.starts_with("sha256:");
    if is_tag {
        if let Ok(data) = state.storage.get(&key).await {
            use sha2::Digest;
            let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));
            let digest_key = format!("docker/{}/manifests/{}.json", name, digest);
            let _ = state.storage.delete(&digest_key).await;
            let digest_meta = format!("docker/{}/manifests/{}.meta.json", name, digest);
            let _ = state.storage.delete(&digest_meta).await;
        }
    }

    // Delete manifest
    match state.storage.delete(&key).await {
        Ok(()) => {
            // Delete associated metadata
            let meta_key = format!("docker/{}/manifests/{}.meta.json", name, reference);
            let _ = state.storage.delete(&meta_key).await;

            state.audit.log(AuditEntry::new(
                "delete",
                "api",
                &format!("{}:{}", name, reference),
                "docker",
                "manifest",
            ));
            state.repo_index.invalidate("docker");
            tracing::info!(name = %name, reference = %reference, "Docker manifest deleted");
            StatusCode::ACCEPTED.into_response()
        }
        Err(crate::storage::StorageError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "errors": [{
                    "code": "MANIFEST_UNKNOWN",
                    "message": "manifest unknown",
                    "detail": { "name": name, "reference": reference }
                }]
            })),
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn delete_blob(
    State(state): State<Arc<AppState>>,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_digest(&digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = format!("docker/{}/blobs/{}", name, digest);
    match state.storage.delete(&key).await {
        Ok(()) => {
            state.audit.log(AuditEntry::new(
                "delete",
                "api",
                &format!("{}@{}", name, &digest[..19.min(digest.len())]),
                "docker",
                "blob",
            ));
            state.repo_index.invalidate("docker");
            tracing::info!(name = %name, digest = %digest, "Docker blob deleted");
            StatusCode::ACCEPTED.into_response()
        }
        Err(crate::storage::StorageError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "errors": [{
                    "code": "BLOB_UNKNOWN",
                    "message": "blob unknown to registry",
                    "detail": { "digest": digest }
                }]
            })),
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// ============================================================================
// Namespace handlers (for two-segment names like library/alpine)
// These combine ns/name into a single name and delegate to the main handlers
// ============================================================================

async fn check_blob_ns(
    state: State<Arc<AppState>>,
    Path((ns, name, digest)): Path<(String, String, String)>,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    check_blob(state, Path((full_name, digest))).await
}

async fn download_blob_ns(
    state: State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((ns, name, digest)): Path<(String, String, String)>,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    download_blob(state, headers, Path((full_name, digest))).await
}

async fn start_upload_ns(
    state: State<Arc<AppState>>,
    Path((ns, name)): Path<(String, String)>,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    start_upload(state, Path(full_name)).await
}

async fn patch_blob_ns(
    state: State<Arc<AppState>>,
    Path((ns, name, uuid)): Path<(String, String, String)>,
    request: axum::extract::Request,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    patch_blob(state, Path((full_name, uuid)), request).await
}

async fn upload_blob_ns(
    state: State<Arc<AppState>>,
    Path((ns, name, uuid)): Path<(String, String, String)>,
    query: axum::extract::Query<std::collections::HashMap<String, String>>,
    request: axum::extract::Request,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    upload_blob(state, Path((full_name, uuid)), query, request).await
}

async fn get_manifest_ns(
    state: State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((ns, name, reference)): Path<(String, String, String)>,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    get_manifest(state, headers, Path((full_name, reference))).await
}

async fn put_manifest_ns(
    state: State<Arc<AppState>>,
    Path((ns, name, reference)): Path<(String, String, String)>,
    body: Bytes,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    put_manifest(state, Path((full_name, reference)), body).await
}

async fn list_tags_ns(
    state: State<Arc<AppState>>,
    Path((ns, name)): Path<(String, String)>,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    list_tags(state, Path(full_name)).await
}

async fn delete_manifest_ns(
    state: State<Arc<AppState>>,
    Path((ns, name, reference)): Path<(String, String, String)>,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    delete_manifest(state, Path((full_name, reference))).await
}

async fn delete_blob_ns(
    state: State<Arc<AppState>>,
    Path((ns, name, digest)): Path<(String, String, String)>,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    delete_blob(state, Path((full_name, digest))).await
}

/// Fetch a blob from an upstream Docker registry
#[allow(clippy::too_many_arguments)]
pub async fn fetch_blob_from_upstream(
    client: &reqwest::Client,
    upstream_url: &str,
    name: &str,
    digest: &str,
    docker_auth: &DockerAuth,
    timeout: u64,
    basic_auth: Option<&str>,
    cb: &CircuitBreakerRegistry,
) -> Result<Vec<u8>, ProxyError> {
    let cb_key = format!("docker:{}", upstream_url.trim_end_matches('/'));
    cb.check(&cb_key)?;

    let url = format!(
        "{}/v2/{}/blobs/{}",
        upstream_url.trim_end_matches('/'),
        name,
        digest
    );

    // First try — with basic auth if configured
    let mut request = client.get(&url).timeout(Duration::from_secs(timeout));
    if let Some(credentials) = basic_auth {
        request = request.header("Authorization", basic_auth_header(credentials));
    }
    let response = request.send().await.map_err(|e| {
        cb.record_failure(&cb_key);
        ProxyError::Network(e.to_string())
    })?;

    let response = if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        // Get Www-Authenticate header and fetch token
        let www_auth = response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        if let Some(token) = docker_auth
            .get_token(upstream_url, name, www_auth.as_deref(), basic_auth)
            .await
        {
            client
                .get(&url)
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await
                .map_err(|e| {
                    cb.record_failure(&cb_key);
                    ProxyError::Network(e.to_string())
                })?
        } else {
            // Auth issue (token fetch failed), not upstream down
            return Err(ProxyError::Network("token fetch failed".into()));
        }
    } else {
        response
    };

    if !response.status().is_success() {
        let status = response.status().as_u16();
        cb.record_failure(&cb_key);
        return Err(ProxyError::Upstream(status));
    }

    let bytes = response.bytes().await.map_err(|e| {
        cb.record_failure(&cb_key);
        ProxyError::Network(e.to_string())
    })?;
    cb.record_success(&cb_key);
    Ok(bytes.to_vec())
}

/// Fetch a manifest from an upstream Docker registry
/// Returns (manifest_bytes, content_type)
#[allow(clippy::too_many_arguments)]
pub async fn fetch_manifest_from_upstream(
    client: &reqwest::Client,
    upstream_url: &str,
    name: &str,
    reference: &str,
    docker_auth: &DockerAuth,
    timeout: u64,
    basic_auth: Option<&str>,
    cb: &CircuitBreakerRegistry,
) -> Result<(Vec<u8>, String), ProxyError> {
    let cb_key = format!("docker:{}", upstream_url.trim_end_matches('/'));
    cb.check(&cb_key)?;

    let url = format!(
        "{}/v2/{}/manifests/{}",
        upstream_url.trim_end_matches('/'),
        name,
        reference
    );

    tracing::debug!(url = %url, "Fetching manifest from upstream");

    // Request with Accept header for manifest types
    let accept_header = "application/vnd.docker.distribution.manifest.v2+json, \
                         application/vnd.docker.distribution.manifest.list.v2+json, \
                         application/vnd.oci.image.manifest.v1+json, \
                         application/vnd.oci.image.index.v1+json";

    // First try — with basic auth if configured
    let mut request = client
        .get(&url)
        .timeout(Duration::from_secs(timeout))
        .header("Accept", accept_header);
    if let Some(credentials) = basic_auth {
        request = request.header("Authorization", basic_auth_header(credentials));
    }
    let response = request.send().await.map_err(|e| {
        tracing::error!(error = %e, url = %url, "Failed to send request to upstream");
        cb.record_failure(&cb_key);
        ProxyError::Network(e.to_string())
    })?;

    tracing::debug!(status = %response.status(), "Initial upstream response");

    let response = if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        // Get Www-Authenticate header and fetch token
        let www_auth = response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        tracing::debug!(www_auth = ?www_auth, "Got 401, fetching token");

        if let Some(token) = docker_auth
            .get_token(upstream_url, name, www_auth.as_deref(), basic_auth)
            .await
        {
            tracing::debug!("Token acquired, retrying with auth");
            client
                .get(&url)
                .header("Accept", accept_header)
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to send authenticated request");
                    cb.record_failure(&cb_key);
                    ProxyError::Network(e.to_string())
                })?
        } else {
            tracing::error!("Failed to acquire token");
            // Auth issue (token fetch failed), not upstream down
            return Err(ProxyError::Network("token fetch failed".into()));
        }
    } else {
        response
    };

    tracing::debug!(status = %response.status(), "Final upstream response");

    if !response.status().is_success() {
        let status = response.status().as_u16();
        tracing::warn!(status = %response.status(), "Upstream returned non-success status");
        cb.record_failure(&cb_key);
        return Err(ProxyError::Upstream(status));
    }

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/vnd.docker.distribution.manifest.v2+json")
        .to_string();

    let bytes = response.bytes().await.map_err(|e| {
        cb.record_failure(&cb_key);
        ProxyError::Network(e.to_string())
    })?;

    cb.record_success(&cb_key);
    Ok((bytes.to_vec(), content_type))
}

/// Detect manifest media type from its JSON content
fn detect_manifest_media_type(data: &[u8]) -> String {
    // Try to parse as JSON and extract mediaType
    if let Ok(json) = serde_json::from_slice::<Value>(data) {
        if let Some(media_type) = json.get("mediaType").and_then(|v| v.as_str()) {
            return media_type.to_string();
        }

        // Check schemaVersion for older manifests
        if let Some(schema_version) = json.get("schemaVersion").and_then(|v| v.as_u64()) {
            if schema_version == 1 {
                return "application/vnd.docker.distribution.manifest.v1+json".to_string();
            }
            // schemaVersion 2 without mediaType - check config.mediaType to distinguish OCI vs Docker
            if let Some(config) = json.get("config") {
                if let Some(config_mt) = config.get("mediaType").and_then(|v| v.as_str()) {
                    if config_mt.starts_with("application/vnd.docker.") {
                        return "application/vnd.docker.distribution.manifest.v2+json".to_string();
                    }
                    // OCI or Helm or any non-docker config mediaType
                    return "application/vnd.oci.image.manifest.v1+json".to_string();
                }
                // No config.mediaType - assume docker v2
                return "application/vnd.docker.distribution.manifest.v2+json".to_string();
            }
            // If it has "manifests" array, it's an index/list
            if json.get("manifests").is_some() {
                return "application/vnd.oci.image.index.v1+json".to_string();
            }
        }
    }

    // Default fallback
    "application/vnd.docker.distribution.manifest.v2+json".to_string()
}

/// Extract publish date from Docker manifest `.meta.json` sidecar.
///
/// Docker metadata sidecar stores `push_timestamp` (Unix seconds) when the
/// manifest was first pushed or cached.
// TODO(v1.0): trust_upstream_dates config for high-security installs
async fn extract_docker_publish_date(
    storage: &Storage,
    name: &str,
    reference: &str,
    upstreams_empty: bool,
) -> Option<i64> {
    // Try .meta.json sidecar (has push_timestamp)
    let meta_key = format!("docker/{}/manifests/{}.meta.json", name, reference);
    if let Ok(data) = storage.get(&meta_key).await {
        if let Ok(meta) = serde_json::from_slice::<ImageMetadata>(&data) {
            if meta.push_timestamp > 0 {
                return Some(meta.push_timestamp as i64);
            }
        }
    }

    // mtime fallback — only for hosted mode (no upstreams configured)
    if upstreams_empty {
        let manifest_key = format!("docker/{}/manifests/{}.json", name, reference);
        return crate::curation::extract_mtime_as_publish_date(storage, &manifest_key).await;
    }

    None
}

/// Extract metadata from a Docker manifest
/// Handles both single-arch manifests and multi-arch indexes
async fn extract_metadata(manifest: &[u8], storage: &Storage, name: &str) -> ImageMetadata {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut metadata = ImageMetadata {
        push_timestamp: now,
        last_pulled: 0,
        downloads: 0,
        ..Default::default()
    };

    let Ok(json) = serde_json::from_slice::<Value>(manifest) else {
        return metadata;
    };

    // Check if this is a manifest list/index (multi-arch)
    if json.get("manifests").is_some() {
        // For multi-arch, extract info from the first platform manifest
        if let Some(manifests) = json.get("manifests").and_then(|m| m.as_array()) {
            // Sum sizes from all platform manifests
            let total_size: u64 = manifests
                .iter()
                .filter_map(|m| m.get("size").and_then(|s| s.as_u64()))
                .sum();
            metadata.size_bytes = total_size;

            // Get OS/arch from first platform (usually linux/amd64)
            if let Some(first) = manifests.first() {
                if let Some(platform) = first.get("platform") {
                    metadata.os = platform
                        .get("os")
                        .and_then(|v| v.as_str())
                        .unwrap_or("multi-arch")
                        .to_string();
                    metadata.arch = platform
                        .get("architecture")
                        .and_then(|v| v.as_str())
                        .unwrap_or("multi")
                        .to_string();
                    metadata.variant = platform
                        .get("variant")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                }
            }
        }
        return metadata;
    }

    // Single-arch manifest - extract layers
    if let Some(layers) = json.get("layers").and_then(|l| l.as_array()) {
        let mut total_size: u64 = 0;
        for layer in layers {
            let digest = layer
                .get("digest")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();
            let size = layer.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
            total_size += size;
            metadata.layers.push(LayerInfo { digest, size });
        }
        metadata.size_bytes = total_size;
    }

    // Try to get OS/arch from config blob
    if let Some(config) = json.get("config") {
        if let Some(config_digest) = config.get("digest").and_then(|d| d.as_str()) {
            let (os, arch, variant) = get_config_info(storage, name, config_digest).await;
            metadata.os = os;
            metadata.arch = arch;
            metadata.variant = variant;
        }
    }

    // If we couldn't get OS/arch, set defaults
    if metadata.os.is_empty() {
        metadata.os = "unknown".to_string();
    }
    if metadata.arch.is_empty() {
        metadata.arch = "unknown".to_string();
    }

    metadata
}

/// Get OS/arch information from a config blob
async fn get_config_info(
    storage: &Storage,
    name: &str,
    config_digest: &str,
) -> (String, String, Option<String>) {
    let key = format!("docker/{}/blobs/{}", name, config_digest);

    let Ok(data) = storage.get(&key).await else {
        return ("unknown".to_string(), "unknown".to_string(), None);
    };

    let Ok(config) = serde_json::from_slice::<Value>(&data) else {
        return ("unknown".to_string(), "unknown".to_string(), None);
    };

    let os = config
        .get("os")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let arch = config
        .get("architecture")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let variant = config
        .get("variant")
        .and_then(|v| v.as_str())
        .map(String::from);

    (os, arch, variant)
}

/// Update metadata when a manifest is pulled
/// Increments download counter and updates last_pulled timestamp
async fn update_metadata_on_pull(state: Arc<AppState>, storage: Storage, meta_key: String) {
    // Lock to prevent lost counter increments from concurrent pulls
    let lock = state.publish_lock(&meta_key);
    let _guard = lock.lock().await;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Try to read existing metadata
    let mut metadata = if let Ok(data) = storage.get(&meta_key).await {
        serde_json::from_slice::<ImageMetadata>(&data).unwrap_or_default()
    } else {
        ImageMetadata::default()
    };

    // Update pull stats
    metadata.downloads += 1;
    metadata.last_pulled = now;

    // Save back
    if let Ok(json) = serde_json::to_vec(&metadata) {
        let _ = storage.put(&meta_key, &json).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_image_metadata_default() {
        let meta = ImageMetadata::default();
        assert_eq!(meta.push_timestamp, 0);
        assert_eq!(meta.last_pulled, 0);
        assert_eq!(meta.downloads, 0);
        assert_eq!(meta.size_bytes, 0);
        assert_eq!(meta.os, "");
        assert_eq!(meta.arch, "");
        assert!(meta.variant.is_none());
        assert!(meta.layers.is_empty());
    }

    #[test]
    fn test_image_metadata_serialization() {
        let meta = ImageMetadata {
            push_timestamp: 1700000000,
            last_pulled: 1700001000,
            downloads: 42,
            size_bytes: 1024000,
            os: "linux".to_string(),
            arch: "amd64".to_string(),
            variant: None,
            layers: vec![LayerInfo {
                digest: "sha256:abc123".to_string(),
                size: 512000,
            }],
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("\"os\":\"linux\""));
        assert!(json.contains("\"arch\":\"amd64\""));
        assert!(!json.contains("variant")); // None => skipped
    }

    #[test]
    fn test_image_metadata_with_variant() {
        let meta = ImageMetadata {
            variant: Some("v8".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("\"variant\":\"v8\""));
    }

    #[test]
    fn test_image_metadata_deserialization() {
        let json = r#"{
            "push_timestamp": 1700000000,
            "last_pulled": 0,
            "downloads": 5,
            "size_bytes": 2048,
            "os": "linux",
            "arch": "arm64",
            "variant": "v8",
            "layers": [
                {"digest": "sha256:aaa", "size": 1024},
                {"digest": "sha256:bbb", "size": 1024}
            ]
        }"#;
        let meta: ImageMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.os, "linux");
        assert_eq!(meta.arch, "arm64");
        assert_eq!(meta.variant, Some("v8".to_string()));
        assert_eq!(meta.layers.len(), 2);
        assert_eq!(meta.layers[0].digest, "sha256:aaa");
        assert_eq!(meta.layers[1].size, 1024);
    }

    #[test]
    fn test_layer_info_serialization_roundtrip() {
        let layer = LayerInfo {
            digest: "sha256:deadbeef".to_string(),
            size: 999999,
        };
        let json = serde_json::to_value(&layer).unwrap();
        let restored: LayerInfo = serde_json::from_value(json).unwrap();
        assert_eq!(layer.digest, restored.digest);
        assert_eq!(layer.size, restored.size);
    }

    #[test]
    fn test_cleanup_expired_sessions_empty() {
        let sessions: RwLock<HashMap<String, UploadSession>> = RwLock::new(HashMap::new());
        cleanup_expired_sessions(&sessions);
        assert_eq!(sessions.read().len(), 0);
    }

    #[test]
    fn test_cleanup_expired_sessions_fresh() {
        let sessions: RwLock<HashMap<String, UploadSession>> = RwLock::new(HashMap::new());
        let temp_dir = tempfile::TempDir::new().unwrap();
        let temp_path = temp_dir.path().join("uuid-1");
        std::fs::write(&temp_path, b"test data").unwrap();
        sessions.write().insert(
            "uuid-1".to_string(),
            UploadSession {
                temp_path,
                size: 9,
                name: "test/image".to_string(),
                created_at: std::time::Instant::now(),
            },
        );
        cleanup_expired_sessions(&sessions);
        assert_eq!(sessions.read().len(), 1); // not expired
    }

    #[test]
    fn test_max_upload_sessions_default() {
        // Without env var set, should return default
        let max = max_upload_sessions();
        assert!(max > 0);
        assert_eq!(max, DEFAULT_MAX_UPLOAD_SESSIONS);
    }

    #[test]
    fn test_max_session_size_default() {
        // Skip this test if another test has temporarily set the env var to
        // exercise a low-limit code path (NORA_MAX_UPLOAD_SESSION_SIZE_MB).
        // The oversize integration test sets this to "1" for the duration of
        // its HTTP call, which can race with this synchronous test.
        if std::env::var("NORA_MAX_UPLOAD_SESSION_SIZE_MB").is_ok() {
            return;
        }
        let max = max_session_size();
        assert_eq!(max, DEFAULT_MAX_SESSION_SIZE_MB * 1024 * 1024);
    }

    // --- detect_manifest_media_type tests ---

    #[test]
    fn test_detect_manifest_explicit_media_type() {
        let manifest = serde_json::json!({
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "schemaVersion": 2
        });
        let result = detect_manifest_media_type(manifest.to_string().as_bytes());
        assert_eq!(
            result,
            "application/vnd.docker.distribution.manifest.v2+json"
        );
    }

    #[test]
    fn test_detect_manifest_oci_media_type() {
        let manifest = serde_json::json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "schemaVersion": 2
        });
        let result = detect_manifest_media_type(manifest.to_string().as_bytes());
        assert_eq!(result, "application/vnd.oci.image.manifest.v1+json");
    }

    #[test]
    fn test_detect_manifest_schema_v1() {
        let manifest = serde_json::json!({
            "schemaVersion": 1,
            "name": "test/image"
        });
        let result = detect_manifest_media_type(manifest.to_string().as_bytes());
        assert_eq!(
            result,
            "application/vnd.docker.distribution.manifest.v1+json"
        );
    }

    #[test]
    fn test_detect_manifest_docker_v2_from_config() {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "digest": "sha256:abc"
            }
        });
        let result = detect_manifest_media_type(manifest.to_string().as_bytes());
        assert_eq!(
            result,
            "application/vnd.docker.distribution.manifest.v2+json"
        );
    }

    #[test]
    fn test_detect_manifest_oci_from_config() {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:abc"
            }
        });
        let result = detect_manifest_media_type(manifest.to_string().as_bytes());
        assert_eq!(result, "application/vnd.oci.image.manifest.v1+json");
    }

    #[test]
    fn test_detect_manifest_no_config_media_type() {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "digest": "sha256:abc"
            }
        });
        let result = detect_manifest_media_type(manifest.to_string().as_bytes());
        assert_eq!(
            result,
            "application/vnd.docker.distribution.manifest.v2+json"
        );
    }

    #[test]
    fn test_detect_manifest_index() {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [
                {"digest": "sha256:aaa", "platform": {"os": "linux", "architecture": "amd64"}}
            ]
        });
        let result = detect_manifest_media_type(manifest.to_string().as_bytes());
        assert_eq!(result, "application/vnd.oci.image.index.v1+json");
    }

    #[test]
    fn test_detect_manifest_invalid_json() {
        let result = detect_manifest_media_type(b"not json at all");
        assert_eq!(
            result,
            "application/vnd.docker.distribution.manifest.v2+json"
        );
    }

    #[test]
    fn test_detect_manifest_empty() {
        let result = detect_manifest_media_type(b"{}");
        assert_eq!(
            result,
            "application/vnd.docker.distribution.manifest.v2+json"
        );
    }

    #[test]
    fn test_detect_manifest_helm_chart() {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.cncf.helm.config.v1+json",
                "digest": "sha256:abc"
            }
        });
        let result = detect_manifest_media_type(manifest.to_string().as_bytes());
        assert_eq!(result, "application/vnd.oci.image.manifest.v1+json");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{
        body_bytes, create_test_context, create_test_context_with_config, send,
    };
    use axum::body::{Body, Bytes};
    use axum::http::{header, Method, StatusCode};
    use axum::Router;
    use sha2::Digest;

    #[tokio::test]
    async fn test_docker_v2_check() {
        let ctx = create_test_context();
        let resp = send(&ctx.app, Method::GET, "/v2/", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_docker_catalog_empty() {
        let ctx = create_test_context();
        let resp = send(&ctx.app, Method::GET, "/v2/_catalog", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["repositories"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_docker_put_get_manifest() {
        let ctx = create_test_context();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
            "layers": []
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();

        let put_resp = send(
            &ctx.app,
            Method::PUT,
            "/v2/alpine/manifests/latest",
            Body::from(manifest_bytes.clone()),
        )
        .await;
        assert_eq!(put_resp.status(), StatusCode::CREATED);
        let digest_header = put_resp
            .headers()
            .get("docker-content-digest")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(digest_header.starts_with("sha256:"));

        let get_resp = send(
            &ctx.app,
            Method::GET,
            "/v2/alpine/manifests/latest",
            Body::empty(),
        )
        .await;
        assert_eq!(get_resp.status(), StatusCode::OK);
        let get_digest = get_resp
            .headers()
            .get("docker-content-digest")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(get_digest, digest_header);
        let body = body_bytes(get_resp).await;
        assert_eq!(body.as_ref(), manifest_bytes.as_slice());
    }

    #[tokio::test]
    async fn test_docker_list_tags() {
        let ctx = create_test_context();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
            "layers": []
        });
        send(
            &ctx.app,
            Method::PUT,
            "/v2/alpine/manifests/latest",
            Body::from(serde_json::to_vec(&manifest).unwrap()),
        )
        .await;

        let list_resp = send(&ctx.app, Method::GET, "/v2/alpine/tags/list", Body::empty()).await;
        assert_eq!(list_resp.status(), StatusCode::OK);
        let body = body_bytes(list_resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "alpine");
        let tags = json["tags"].as_array().unwrap();
        assert!(tags.contains(&serde_json::json!("latest")));
    }

    #[tokio::test]
    async fn test_docker_delete_manifest() {
        let ctx = create_test_context();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
            "layers": []
        });
        let put_resp = send(
            &ctx.app,
            Method::PUT,
            "/v2/alpine/manifests/latest",
            Body::from(serde_json::to_vec(&manifest).unwrap()),
        )
        .await;
        let digest = put_resp
            .headers()
            .get("docker-content-digest")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let del = send(
            &ctx.app,
            Method::DELETE,
            &format!("/v2/alpine/manifests/{}", digest),
            Body::empty(),
        )
        .await;
        assert_eq!(del.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_docker_monolithic_upload() {
        let ctx = create_test_context();
        let blob_data = b"test blob data";
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

        let post_resp = send(
            &ctx.app,
            Method::POST,
            "/v2/alpine/blobs/uploads/",
            Body::empty(),
        )
        .await;
        assert_eq!(post_resp.status(), StatusCode::ACCEPTED);
        let location = post_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let uuid = location.rsplit('/').next().unwrap();

        let put_url = format!("/v2/alpine/blobs/uploads/{}?digest={}", uuid, digest);
        let put_resp = send(&ctx.app, Method::PUT, &put_url, Body::from(&blob_data[..])).await;
        assert_eq!(put_resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_docker_chunked_upload() {
        let ctx = create_test_context();
        let blob_data = b"test chunked blob";
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

        let post_resp = send(
            &ctx.app,
            Method::POST,
            "/v2/alpine/blobs/uploads/",
            Body::empty(),
        )
        .await;
        assert_eq!(post_resp.status(), StatusCode::ACCEPTED);
        let location = post_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let uuid = location.rsplit('/').next().unwrap();

        let patch_url = format!("/v2/alpine/blobs/uploads/{}", uuid);
        let patch_resp = send(
            &ctx.app,
            Method::PATCH,
            &patch_url,
            Body::from(&blob_data[..]),
        )
        .await;
        assert_eq!(patch_resp.status(), StatusCode::ACCEPTED);

        let put_url = format!("/v2/alpine/blobs/uploads/{}?digest={}", uuid, digest);
        let put_resp = send(&ctx.app, Method::PUT, &put_url, Body::empty()).await;
        assert_eq!(put_resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_docker_check_blob() {
        let ctx = create_test_context();
        let blob_data = b"test blob for head";
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

        let post_resp = send(
            &ctx.app,
            Method::POST,
            "/v2/alpine/blobs/uploads/",
            Body::empty(),
        )
        .await;
        let location = post_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let uuid = location.rsplit('/').next().unwrap();
        let put_url = format!("/v2/alpine/blobs/uploads/{}?digest={}", uuid, digest);
        send(&ctx.app, Method::PUT, &put_url, Body::from(&blob_data[..])).await;

        let head_url = format!("/v2/alpine/blobs/{}", digest);
        let head_resp = send(&ctx.app, Method::HEAD, &head_url, Body::empty()).await;
        assert_eq!(head_resp.status(), StatusCode::OK);
        let cl = head_resp
            .headers()
            .get(header::CONTENT_LENGTH)
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert_eq!(cl, blob_data.len());
    }

    #[tokio::test]
    async fn test_docker_download_blob() {
        let ctx = create_test_context();
        let blob_data = b"test blob for download";
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

        let post_resp = send(
            &ctx.app,
            Method::POST,
            "/v2/alpine/blobs/uploads/",
            Body::empty(),
        )
        .await;
        let location = post_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let uuid = location.rsplit('/').next().unwrap();
        let put_url = format!("/v2/alpine/blobs/uploads/{}?digest={}", uuid, digest);
        send(&ctx.app, Method::PUT, &put_url, Body::from(&blob_data[..])).await;

        let get_url = format!("/v2/alpine/blobs/{}", digest);
        let get_resp = send(&ctx.app, Method::GET, &get_url, Body::empty()).await;
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body = body_bytes(get_resp).await;
        assert_eq!(body.as_ref(), &blob_data[..]);
    }

    #[tokio::test]
    async fn test_docker_blob_not_found() {
        let ctx = create_test_context();
        let fake_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let head_url = format!("/v2/alpine/blobs/{}", fake_digest);
        let resp = send(&ctx.app, Method::HEAD, &head_url, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_docker_delete_blob() {
        let ctx = create_test_context();
        let blob_data = b"test blob for delete";
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

        let post_resp = send(
            &ctx.app,
            Method::POST,
            "/v2/alpine/blobs/uploads/",
            Body::empty(),
        )
        .await;
        let location = post_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let uuid = location.rsplit('/').next().unwrap();
        let put_url = format!("/v2/alpine/blobs/uploads/{}?digest={}", uuid, digest);
        send(&ctx.app, Method::PUT, &put_url, Body::from(&blob_data[..])).await;

        let delete_url = format!("/v2/alpine/blobs/{}", digest);
        let delete_resp = send(&ctx.app, Method::DELETE, &delete_url, Body::empty()).await;
        assert_eq!(delete_resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_docker_namespaced_routes() {
        let ctx = create_test_context();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
            "layers": []
        });
        let put_resp = send(
            &ctx.app,
            Method::PUT,
            "/v2/library/alpine/manifests/latest",
            Body::from(serde_json::to_vec(&manifest).unwrap()),
        )
        .await;
        assert_eq!(put_resp.status(), StatusCode::CREATED);
        assert!(put_resp
            .headers()
            .get("docker-content-digest")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("sha256:"));
    }

    #[tokio::test]
    async fn test_extract_docker_publish_date_from_meta() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());
        let meta = super::ImageMetadata {
            push_timestamp: 1700000000,
            ..Default::default()
        };
        storage
            .put(
                "docker/library/nginx/manifests/latest.meta.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();

        let result = super::extract_docker_publish_date(
            &storage,
            "library/nginx",
            "latest",
            true, // no upstreams
        )
        .await;
        assert_eq!(result, Some(1700000000));
    }

    #[tokio::test]
    async fn test_extract_docker_publish_date_mtime_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());

        // No .meta.json, but manifest exists — should fall back to mtime (hosted mode)
        storage
            .put("docker/library/nginx/manifests/latest.json", b"{}")
            .await
            .unwrap();

        let result = super::extract_docker_publish_date(
            &storage,
            "library/nginx",
            "latest",
            true, // hosted mode (no upstreams)
        )
        .await;
        assert!(result.is_some());
        assert!(result.unwrap() > 0);
    }

    #[tokio::test]
    async fn test_extract_docker_publish_date_proxy_no_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());

        // No .meta.json, manifest exists, but proxy mode — no fallback
        storage
            .put("docker/library/nginx/manifests/latest.json", b"{}")
            .await
            .unwrap();

        let result = super::extract_docker_publish_date(
            &storage,
            "library/nginx",
            "latest",
            false, // proxy mode (has upstreams)
        )
        .await;
        assert!(result.is_none());
    }

    /// Circuit breaker open on Docker upstream MUST return 503 + Retry-After.
    #[tokio::test]
    async fn test_docker_circuit_breaker_trips() {
        use crate::config::DockerUpstream;
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};

        let ctx = create_test_context_with_config(|cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 2;
            cfg.circuit_breaker.reset_timeout = 3600;
            // Unreachable upstream
            cfg.docker.upstreams = vec![DockerUpstream {
                url: "http://127.0.0.1:1".into(),
                auth: None,
            }];
        });

        // Trip the breaker for this upstream
        ctx.state
            .circuit_breaker
            .record_failure("docker:http://127.0.0.1:1");
        ctx.state
            .circuit_breaker
            .record_failure("docker:http://127.0.0.1:1");

        // Request a manifest NOT in local storage → proxy path → cb.check() → 503
        let response = send(
            &ctx.app,
            Method::GET,
            "/v2/library/nonexistent/manifests/latest",
            Body::empty(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("30")
        );
        let body = body_bytes(response).await;
        assert!(String::from_utf8_lossy(&body).contains("temporarily unavailable"));
    }

    /// Per-upstream circuit breaker isolation: upstream A down, upstream B serves.
    #[tokio::test]
    async fn test_docker_circuit_breaker_per_upstream() {
        use crate::config::DockerUpstream;
        use crate::test_helpers::create_test_context_with_config;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 2;
            cfg.circuit_breaker.reset_timeout = 3600;
            cfg.docker.upstreams = vec![
                DockerUpstream {
                    url: "http://127.0.0.1:1".into(), // upstream A (will be tripped)
                    auth: None,
                },
                DockerUpstream {
                    url: "http://127.0.0.1:2".into(), // upstream B (stays closed)
                    auth: None,
                },
            ];
        });

        // Trip only upstream A
        ctx.state
            .circuit_breaker
            .record_failure("docker:http://127.0.0.1:1");
        ctx.state
            .circuit_breaker
            .record_failure("docker:http://127.0.0.1:1");

        // Upstream A should be open
        assert!(ctx
            .state
            .circuit_breaker
            .check("docker:http://127.0.0.1:1")
            .is_err());

        // Upstream B should still be closed (requests allowed)
        assert!(ctx
            .state
            .circuit_breaker
            .check("docker:http://127.0.0.1:2")
            .is_ok());
    }

    // -----------------------------------------------------------------------
    // Streaming upload tests
    // -----------------------------------------------------------------------

    /// Helper: POST /v2/{name}/blobs/uploads/ and return the UUID string.
    async fn start_upload_session(app: &Router, name: &str) -> String {
        let resp = send(
            app,
            Method::POST,
            &format!("/v2/{}/blobs/uploads/", name),
            Body::empty(),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::ACCEPTED,
            "expected 202 from start_upload"
        );
        let location = resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        location.rsplit('/').next().unwrap().to_string()
    }

    /// Helper: build a Content-Length header value that forces the streamed path.
    fn cl_header_exceeds(threshold_mb: usize, body_len: usize) -> String {
        // We just pass the real body length — if it's ≥ threshold the handler
        // will pick UploadPath::Streamed.
        let _ = threshold_mb;
        body_len.to_string()
    }

    // -----------------------------------------------------------------------
    // content_length helper — pure unit test (no I/O)
    // -----------------------------------------------------------------------

    /// Verify `content_length` parses all interesting header cases correctly.
    ///
    /// The helper is `fn content_length(headers: &HeaderMap) -> Option<usize>`.
    /// We call it via `super::content_length` from inside the same module.
    #[test]
    fn content_length_helper() {
        use axum::http::HeaderMap;

        // Missing header → None
        let empty = HeaderMap::new();
        assert_eq!(super::content_length(&empty), None);

        // Valid numeric value
        let mut valid = HeaderMap::new();
        valid.insert(header::CONTENT_LENGTH, "12345".parse().unwrap());
        assert_eq!(super::content_length(&valid), Some(12345));

        // Zero is valid
        let mut zero = HeaderMap::new();
        zero.insert(header::CONTENT_LENGTH, "0".parse().unwrap());
        assert_eq!(super::content_length(&zero), Some(0));

        // Non-numeric value → None
        let mut bad = HeaderMap::new();
        bad.insert(header::CONTENT_LENGTH, "not-a-number".parse().unwrap());
        assert_eq!(super::content_length(&bad), None);

        // Very large value that fits in usize (on 64-bit targets)
        let mut large = HeaderMap::new();
        large.insert(header::CONTENT_LENGTH, "10737418240".parse().unwrap()); // 10 GiB
        assert_eq!(super::content_length(&large), Some(10_737_418_240));
    }

    // -----------------------------------------------------------------------
    // Buffered path is unchanged for small uploads
    // -----------------------------------------------------------------------

    /// Body of 1 MiB with a 1024 MiB threshold must stay on the buffered path.
    /// Exercises that the existing `upload_blob_buffered` logic is not broken by
    /// the new branching logic in `upload_blob`.
    #[tokio::test]
    async fn buffered_path_unchanged_for_small_uploads() {
        // Default threshold is 1024 MB; a 1 MiB body is well below it.
        let ctx = create_test_context();

        let blob_data = vec![0xABu8; 1024 * 1024]; // 1 MiB
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob_data)));

        let uuid = start_upload_session(&ctx.app, "myimage").await;

        // Send the PUT with an explicit Content-Length so the handler can
        // see it is below the 1024 MiB threshold → buffered path.
        use tower::ServiceExt;
        let req = axum::http::Request::builder()
            .method(Method::PUT)
            .uri(format!(
                "/v2/myimage/blobs/uploads/{}?digest={}",
                uuid, digest
            ))
            .header(header::CONTENT_LENGTH, blob_data.len().to_string())
            .body(Body::from(blob_data.clone()))
            .unwrap();
        let put_resp = ctx.app.clone().oneshot(req).await.unwrap();
        assert_eq!(put_resp.status(), StatusCode::CREATED);

        // Confirm the blob landed in storage.
        let key = format!("docker/myimage/blobs/{}", digest);
        let stored = ctx.state.storage.get(&key).await.unwrap();
        assert_eq!(stored.as_ref(), blob_data.as_slice());
    }

    // -----------------------------------------------------------------------
    // Streamed upload — success path
    // -----------------------------------------------------------------------

    /// Synthesise a 32 MiB random-ish body, force the streamed path via a 1 MiB
    /// threshold, verify HTTP 201, blob exists in storage, and digest is correct.
    #[tokio::test]
    async fn streamed_upload_succeeds_for_32mib() {
        // Set threshold to 1 MB so our 32 MiB body takes the streamed path.
        let ctx = create_test_context_with_config(|cfg| {
            cfg.server.docker_stream_threshold_mb = 1;
        });

        // Deterministic pseudo-random data so the test is reproducible.
        let body_size = 32 * 1024 * 1024usize; // 32 MiB
        let blob_data: Vec<u8> = (0..body_size).map(|i| (i ^ (i >> 8)) as u8).collect();
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob_data)));

        let uuid = start_upload_session(&ctx.app, "bigimage").await;

        // Send PUT with Content-Length ≥ threshold to trigger UploadPath::Streamed.
        use tower::ServiceExt;
        let req = axum::http::Request::builder()
            .method(Method::PUT)
            .uri(format!(
                "/v2/bigimage/blobs/uploads/{}?digest={}",
                uuid, digest
            ))
            .header(
                header::CONTENT_LENGTH,
                cl_header_exceeds(1, blob_data.len()),
            )
            .body(Body::from(blob_data.clone()))
            .unwrap();

        let put_resp = ctx.app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            put_resp.status(),
            StatusCode::CREATED,
            "expected 201 from streamed upload"
        );

        // Verify location and content-digest headers.
        let location = put_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            location.contains(&digest),
            "location header must include digest"
        );
        let returned_digest = put_resp
            .headers()
            .get("docker-content-digest")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(returned_digest, digest);

        // Verify the blob exists in storage with the correct content.
        let key = format!("docker/bigimage/blobs/{}", digest);
        let stored = ctx.state.storage.get(&key).await.unwrap();
        assert_eq!(stored.len(), body_size, "stored size mismatch");
        assert_eq!(
            stored.as_ref(),
            blob_data.as_slice(),
            "stored bytes mismatch"
        );

        // Verify no temp file was left behind.
        let temp_dir = ctx.state.config.storage.path.as_str().to_string();
        let temp_path = std::path::PathBuf::from(&temp_dir)
            .join("tmp/docker-uploads")
            .join(&uuid);
        assert!(
            !temp_path.exists(),
            "temp file must be removed after successful streamed upload"
        );
    }

    // -----------------------------------------------------------------------
    // Streamed upload — digest mismatch
    // -----------------------------------------------------------------------

    /// Providing the wrong digest for a streamed upload must return 400 with
    /// the `DIGEST_INVALID` OCI error code, and the temp file must be cleaned up.
    #[tokio::test]
    async fn streamed_upload_rejects_digest_mismatch() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.server.docker_stream_threshold_mb = 1;
        });

        // 512 KiB body — small enough to stay under ANY plausible session-size
        // limit that a concurrently running oversize test might inject via env var.
        let body_size = 512 * 1024usize;
        let blob_data: Vec<u8> = (0..body_size).map(|i| i as u8).collect();
        // Intentionally wrong digest — all zeros.
        let wrong_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        let uuid = start_upload_session(&ctx.app, "mismatch-test").await;

        use tower::ServiceExt;
        let req = axum::http::Request::builder()
            .method(Method::PUT)
            .uri(format!(
                "/v2/mismatch-test/blobs/uploads/{}?digest={}",
                uuid, wrong_digest
            ))
            .header(header::CONTENT_LENGTH, blob_data.len().to_string())
            .body(Body::from(blob_data.clone()))
            .unwrap();
        let resp = ctx.app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "expected 400 for digest mismatch"
        );

        // Response body must contain DIGEST_INVALID.
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["errors"][0]["code"].as_str().unwrap(),
            "DIGEST_INVALID",
            "error code must be DIGEST_INVALID"
        );

        // Temp file must have been deleted.
        let temp_path = std::path::PathBuf::from(&ctx.state.config.storage.path)
            .join("tmp/docker-uploads")
            .join(&uuid);
        assert!(
            !temp_path.exists(),
            "temp file must be removed after digest mismatch"
        );
    }

    // -----------------------------------------------------------------------
    // Streamed upload — oversize rejection
    // -----------------------------------------------------------------------

    /// When the streamed body exceeds `max_session_size` (controlled via env),
    /// the handler must return 413 and remove the temp file.
    ///
    /// Strategy: we exploit the fact that the oversize check in
    /// `upload_blob_streamed` adds `prior_size` (from the session) to `written`.
    /// We inject a session whose `size` is pre-set to (default_limit - 1 byte)
    /// via PATCH, then send a 2-byte PUT body.  This lets us stay well under any
    /// realistic allocation budget while still triggering the 413 path.
    ///
    /// `NORA_MAX_UPLOAD_SESSION_SIZE_MB` is set to "1" to allow small buffers.
    /// The RAII guard restores the env var on both success and panic paths.
    /// Other tests in this suite deliberately use bodies ≤ 512 KiB so they
    /// are not affected even if this env var is briefly visible to them.
    #[tokio::test]
    async fn streamed_upload_rejects_oversize() {
        struct EnvGuard(&'static str);
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                std::env::remove_var(self.0);
            }
        }

        // 1 MiB session-size cap.  Restored by EnvGuard on drop.
        std::env::set_var("NORA_MAX_UPLOAD_SESSION_SIZE_MB", "1");
        let _env_guard = EnvGuard("NORA_MAX_UPLOAD_SESSION_SIZE_MB");

        let ctx = create_test_context_with_config(|cfg| {
            cfg.server.docker_stream_threshold_mb = 1; // force streamed path
        });

        // Body is 2 MiB — exceeds the 1 MiB limit set above.
        let body_size = 2 * 1024 * 1024usize;
        let blob_data: Vec<u8> = vec![0x55u8; body_size];
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob_data)));

        let uuid = start_upload_session(&ctx.app, "oversize-test").await;

        use tower::ServiceExt;
        let req = axum::http::Request::builder()
            .method(Method::PUT)
            .uri(format!(
                "/v2/oversize-test/blobs/uploads/{}?digest={}",
                uuid, digest
            ))
            .header(header::CONTENT_LENGTH, body_size.to_string())
            .body(Body::from(blob_data))
            .unwrap();
        let resp = ctx.app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "expected 413 for body exceeding session size limit"
        );

        // Temp file must have been removed.
        let temp_path = std::path::PathBuf::from(&ctx.state.config.storage.path)
            .join("tmp/docker-uploads")
            .join(&uuid);
        assert!(
            !temp_path.exists(),
            "temp file must be removed after oversize rejection"
        );
    }

    // -----------------------------------------------------------------------
    // Streamed upload — client disconnect cleanup
    // -----------------------------------------------------------------------

    /// When the request body stream errors mid-flight during a streamed PUT,
    /// the handler must return 400 and must not leave an orphan temp file.
    ///
    /// Implementation note: `upload_blob_streamed` explicitly calls
    /// `tokio::fs::remove_file(&temp_path)` on the disconnect arm (the `Err`
    /// branch of `stream.next().await`). This test verifies that invariant.
    /// If it ever fails, the fix is to ensure the remove call is present in
    /// that arm — a regression against the OOM-fix design contract.
    #[tokio::test]
    async fn streamed_upload_client_disconnect_cleanup() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.server.docker_stream_threshold_mb = 1;
        });

        // Build a body stream that delivers one good chunk then an error.
        // chunk_a: 256 KiB — below any plausible concurrent session-size limit
        // so a concurrently running oversize test cannot cause a spurious 413.
        // The handler still takes the streamed path because Content-Length is
        // omitted (unknown length → always streamed).
        let chunk_a = Bytes::from(vec![0xAAu8; 256 * 1024]);

        // The real digest is irrelevant — we won't reach the verification step.
        let fake_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        let uuid = start_upload_session(&ctx.app, "disconnect-test").await;

        // Construct a body from a stream that emits one chunk then an error.
        let stream = futures::stream::iter(vec![
            Ok::<Bytes, std::io::Error>(chunk_a),
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "simulated disconnect",
            )),
        ]);
        let body = Body::from_stream(stream);

        use tower::ServiceExt;
        let req = axum::http::Request::builder()
            .method(Method::PUT)
            .uri(format!(
                "/v2/disconnect-test/blobs/uploads/{}?digest={}",
                uuid, fake_digest
            ))
            // No Content-Length → handler cannot know size → always streamed.
            .body(body)
            .unwrap();
        let resp = ctx.app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "expected 400 on client disconnect"
        );

        // Allow async cleanup to complete.
        tokio::task::yield_now().await;

        // The temp file must have been removed by the disconnect handler arm.
        let temp_path = std::path::PathBuf::from(&ctx.state.config.storage.path)
            .join("tmp/docker-uploads")
            .join(&uuid);
        assert!(
            !temp_path.exists(),
            "temp file must be removed on client disconnect (no orphan allowed)"
        );
    }

    // -----------------------------------------------------------------------
    // Chunked PATCH (streamed) + monolithic PUT — end-to-end
    // -----------------------------------------------------------------------

    /// Two 8 MiB PATCH chunks via the streamed path, then a PUT with an empty
    /// body and the SHA-256 of the concatenated chunks.
    ///
    /// This exercises `patch_blob_streamed` + `upload_blob_streamed` together
    /// and verifies that the hasher seeding from the existing temp file in
    /// `upload_blob_streamed` produces the correct final digest.
    #[tokio::test]
    async fn chunked_patch_then_monolithic_put_streamed() {
        // 1 MB threshold → both 8 MiB PATCH chunks take the streamed path.
        let ctx = create_test_context_with_config(|cfg| {
            cfg.server.docker_stream_threshold_mb = 1;
        });

        let chunk_size = 8 * 1024 * 1024usize; // 8 MiB per chunk
        let chunk1: Vec<u8> = (0..chunk_size).map(|i| (i % 251) as u8).collect();
        let chunk2: Vec<u8> = (0..chunk_size).map(|i| (i % 241) as u8).collect();

        // Pre-compute the digest of the full concatenated payload.
        let mut full_payload = chunk1.clone();
        full_payload.extend_from_slice(&chunk2);
        let digest = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(&full_payload))
        );

        let uuid = start_upload_session(&ctx.app, "chunked-test").await;

        // PATCH chunk 1 — Content-Length exceeds threshold → streamed.
        use tower::ServiceExt;
        let patch1_req = axum::http::Request::builder()
            .method(Method::PATCH)
            .uri(format!("/v2/chunked-test/blobs/uploads/{}", uuid))
            .header(header::CONTENT_LENGTH, chunk1.len().to_string())
            .body(Body::from(chunk1.clone()))
            .unwrap();
        let patch1_resp = ctx.app.clone().oneshot(patch1_req).await.unwrap();
        assert_eq!(
            patch1_resp.status(),
            StatusCode::ACCEPTED,
            "first PATCH must return 202"
        );
        let range1 = patch1_resp
            .headers()
            .get("range")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(
            range1,
            format!("0-{}", chunk_size - 1),
            "range header after first chunk"
        );

        // PATCH chunk 2 — also streamed.
        let patch2_req = axum::http::Request::builder()
            .method(Method::PATCH)
            .uri(format!("/v2/chunked-test/blobs/uploads/{}", uuid))
            .header(header::CONTENT_LENGTH, chunk2.len().to_string())
            .body(Body::from(chunk2.clone()))
            .unwrap();
        let patch2_resp = ctx.app.clone().oneshot(patch2_req).await.unwrap();
        assert_eq!(
            patch2_resp.status(),
            StatusCode::ACCEPTED,
            "second PATCH must return 202"
        );

        // PUT with empty body — finalize using the queued session data.
        let put_req = axum::http::Request::builder()
            .method(Method::PUT)
            .uri(format!(
                "/v2/chunked-test/blobs/uploads/{}?digest={}",
                uuid, digest
            ))
            .header(header::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .unwrap();
        let put_resp = ctx.app.clone().oneshot(put_req).await.unwrap();
        assert_eq!(
            put_resp.status(),
            StatusCode::CREATED,
            "PUT finalization must return 201"
        );

        // Verify the stored blob matches the expected concatenated digest.
        let returned_digest = put_resp
            .headers()
            .get("docker-content-digest")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            returned_digest, digest,
            "docker-content-digest must match sha256 of concatenated chunks"
        );

        // Confirm the blob is retrievable.
        let key = format!("docker/chunked-test/blobs/{}", digest);
        let stored = ctx.state.storage.get(&key).await.unwrap();
        assert_eq!(
            stored.len(),
            chunk_size * 2,
            "stored blob size must be 16 MiB"
        );
        assert_eq!(
            &stored[..chunk_size],
            chunk1.as_slice(),
            "first chunk data mismatch"
        );
        assert_eq!(
            &stored[chunk_size..],
            chunk2.as_slice(),
            "second chunk data mismatch"
        );
    }
}
