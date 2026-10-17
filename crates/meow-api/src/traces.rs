//! Diagnostic flow-trace endpoints.
//!
//! Recording is a runtime toggle rather than configuration: a client starts a
//! session, reproduces a problem, stops it, then reads the captured flows.
//! Only one session records at a time, which is what the single user-facing
//! on/off control maps to.
//!
//! ```text
//! POST   /traces/sessions            start recording      → { session }
//! POST   /traces/sessions/{id}/stop  stop and flush       → { session }
//! DELETE /traces/sessions/{id}       delete a recording   → 204
//! GET    /traces/sessions            list, newest first   → { sessions }
//! GET    /traces/sessions/{id}/flows one session's flows  → { session, flows }
//! ```
//!
//! Field names are serde's default snake_case, matching what the clients of
//! this endpoint decode. Note this differs from `/connections`, which is
//! camelCase for mihomo dashboard compatibility.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use meow_tunnel::trace::{TraceFlow, TraceSession, TraceStore};
use serde::{Deserialize, Serialize};
use std::io;
use std::sync::Arc;

use crate::routes::AppState;

/// Default page size, matching the other paginated endpoints.
const DEFAULT_LIMIT: usize = 50;
/// Upper bound so one request cannot pull an entire capped session into memory.
const MAX_LIMIT: usize = 1000;

#[derive(Debug, Deserialize)]
pub(crate) struct PageParams {
    limit: Option<usize>,
    offset: Option<usize>,
}

impl PageParams {
    fn limit(&self) -> usize {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }

    fn offset(&self) -> usize {
        self.offset.unwrap_or(0)
    }
}

#[derive(Serialize)]
struct SessionsResponse {
    sessions: Vec<TraceSession>,
}

#[derive(Serialize)]
struct SessionResponse {
    session: TraceSession,
}

#[derive(Serialize)]
struct FlowsResponse {
    session: TraceSession,
    flows: Vec<TraceFlow>,
}

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/traces/sessions", get(list_sessions).post(start_session))
        .route("/traces/sessions/{id}/stop", post(stop_session))
        .route("/traces/sessions/{id}", delete(delete_session))
        .route("/traces/sessions/{id}/flows", get(get_flows))
}

/// Trace storage is only present when the embedder installed one.
///
/// The error is boxed because `Response` is large and this sits in a `Result`
/// on every handler's entry path (`clippy::result_large_err`).
fn store(state: &AppState) -> Result<Arc<TraceStore>, Box<Response>> {
    state.tunnel.trace_store().ok_or_else(|| {
        Box::new(msg_err(
            StatusCode::NOT_IMPLEMENTED,
            "flow tracing is not enabled on this runtime",
        ))
    })
}

fn msg_err(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "message": message }))).into_response()
}

/// Map storage failures onto the status codes the endpoints document.
fn io_err(error: &io::Error) -> Response {
    let status = match error.kind() {
        io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
        // Already recording, or deleting the session that is still live.
        io::ErrorKind::AlreadyExists | io::ErrorKind::ResourceBusy => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    msg_err(status, &error.to_string())
}

/// Run a blocking store operation off the async runtime.
///
/// Every one of these touches the filesystem — reading a session file scans it
/// line by line — so none of them may run on a reactor thread.
async fn blocking<T, F>(work: F) -> Response
where
    T: Serialize + Send + 'static,
    F: FnOnce() -> io::Result<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(error)) => io_err(&error),
        Err(error) => msg_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("trace task failed: {error}"),
        ),
    }
}

async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PageParams>,
) -> Response {
    let store = match store(&state) {
        Ok(store) => store,
        Err(response) => return *response,
    };
    let (limit, offset) = (params.limit(), params.offset());
    blocking(move || {
        Ok(SessionsResponse {
            sessions: store.list_sessions(limit, offset)?,
        })
    })
    .await
}

#[derive(Default, Deserialize)]
struct RecordingOptions {
    #[serde(default)]
    capture_http: bool,
}

async fn start_session(
    State(state): State<Arc<AppState>>,
    options: Option<Json<RecordingOptions>>,
) -> Response {
    let store = match store(&state) {
        Ok(store) => store,
        Err(response) => return *response,
    };
    let options = options.map(|Json(value)| value).unwrap_or_default();
    blocking(move || {
        Ok(SessionResponse {
            session: store.start_session_with_http(options.capture_http)?,
        })
    })
    .await
}

async fn stop_session(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let store = match store(&state) {
        Ok(store) => store,
        Err(response) => return *response,
    };
    blocking(move || {
        Ok(SessionResponse {
            session: store.stop_session(&id)?,
        })
    })
    .await
}

async fn delete_session(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let store = match store(&state) {
        Ok(store) => store,
        Err(response) => return *response,
    };
    match tokio::task::spawn_blocking(move || store.delete_session(&id)).await {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => msg_err(StatusCode::NOT_FOUND, "no such trace session"),
        Ok(Err(error)) => io_err(&error),
        Err(error) => msg_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("trace task failed: {error}"),
        ),
    }
}

async fn get_flows(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<PageParams>,
) -> Response {
    let store = match store(&state) {
        Ok(store) => store,
        Err(response) => return *response,
    };
    let (limit, offset) = (params.limit(), params.offset());
    blocking(move || {
        let (session, flows) = store.read_flows(&id, limit, offset)?;
        Ok(FlowsResponse { session, flows })
    })
    .await
}
