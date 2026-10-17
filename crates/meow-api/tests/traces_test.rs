//! End-to-end coverage for the `/traces/...` diagnostic endpoints.
#![cfg(feature = "trace")]

use axum::http::{Request, StatusCode};
use dashmap::DashMap;
use http_body_util::BodyExt;
use meow_api::routes::{create_router, AppState};
use meow_common::DnsMode;
use meow_config::raw::RawConfig;
use meow_dns::Resolver;
use meow_trie::DomainTrie;
use meow_tunnel::trace::{FlowGuard, TraceConfig, TraceStore};
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use tower::ServiceExt;

/// Builds a state whose tunnel has a trace store rooted in a temp dir.
/// Pass `false` to model a runtime built without tracing installed.
fn test_state(with_trace: bool) -> Arc<AppState> {
    let resolver = Arc::new(Resolver::new(
        vec!["8.8.8.8:53".parse().unwrap()],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        false,
    ));
    let tunnel = Tunnel::new(resolver);

    let dir = tempfile::tempdir().unwrap();
    if with_trace {
        let store = TraceStore::new(TraceConfig::new(dir.path().join("traces"))).unwrap();
        tunnel.set_trace_store(Some(Arc::new(store)));
    }
    let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
    std::mem::forget(dir);

    Arc::new(AppState {
        tunnel,
        secret: None,
        config_path: Some(config_path),
        raw_config: Arc::new(RwLock::new(RawConfig::default())),
        log_tx: broadcast::channel(16).0,
        proxy_providers: Arc::new(DashMap::new()),
        rule_providers: Arc::new(RwLock::new(HashMap::new())),
        listeners: vec![],
        external_ui: None,
        provider_dialer_registry: Default::default(),
        rule_provider_refresh: Default::default(),
        proxy_provider_refresh: Default::default(),
        traffic_feed: Default::default(),
        dns_server: Default::default(),
    })
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn call(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
) -> (StatusCode, axum::response::Response) {
    let resp = create_router(Arc::clone(state))
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    (resp.status(), resp)
}

#[tokio::test]
async fn start_list_stop_round_trip() {
    let state = test_state(true);

    let (status, resp) = call(&state, "POST", "/traces/sessions").await;
    assert_eq!(status, StatusCode::OK);
    let started = body_json(resp).await;
    let id = started["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        started["session"]["status"], "recording",
        "a fresh session reports as recording"
    );
    assert!(
        started["session"]["started_at_ms"].is_i64(),
        "snake_case keys are what the Swift client decodes"
    );

    let (status, resp) = call(&state, "GET", "/traces/sessions").await;
    assert_eq!(status, StatusCode::OK);
    let listed = body_json(resp).await;
    let sessions = listed["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["session_id"], id.as_str());

    let (status, resp) = call(&state, "POST", &format!("/traces/sessions/{id}/stop")).await;
    assert_eq!(status, StatusCode::OK);
    let stopped = body_json(resp).await;
    assert_eq!(stopped["session"]["status"], "completed");
    assert!(stopped["session"]["ended_at_ms"].is_i64());
}

#[tokio::test]
async fn second_start_conflicts_while_recording() {
    let state = test_state(true);
    let (status, _) = call(&state, "POST", "/traces/sessions").await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = call(&state, "POST", "/traces/sessions").await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "only one session records at a time"
    );
}

#[tokio::test]
async fn flows_endpoint_returns_session_and_empty_flows() {
    let state = test_state(true);
    let (_, resp) = call(&state, "POST", "/traces/sessions").await;
    let id = body_json(resp).await["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    call(&state, "POST", &format!("/traces/sessions/{id}/stop")).await;

    let (status, resp) = call(&state, "GET", &format!("/traces/sessions/{id}/flows")).await;
    assert_eq!(status, StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["session"]["session_id"], id.as_str());
    assert!(body["flows"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn unknown_session_is_not_found() {
    let state = test_state(true);
    let (status, _) = call(&state, "GET", "/traces/sessions/nope/flows").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = call(&state, "POST", "/traces/sessions/nope/stop").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = call(&state, "DELETE", "/traces/sessions/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn active_session_cannot_be_deleted() {
    let state = test_state(true);
    let (_, resp) = call(&state, "POST", "/traces/sessions").await;
    let id = body_json(resp).await["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, _) = call(&state, "DELETE", &format!("/traces/sessions/{id}")).await;
    assert_eq!(status, StatusCode::CONFLICT);

    call(&state, "POST", &format!("/traces/sessions/{id}/stop")).await;
    let (status, _) = call(&state, "DELETE", &format!("/traces/sessions/{id}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, resp) = call(&state, "GET", "/traces/sessions").await;
    assert!(body_json(resp).await["sessions"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn endpoints_report_not_implemented_without_a_store() {
    let state = test_state(false);
    let (status, _) = call(&state, "GET", "/traces/sessions").await;
    assert_eq!(
        status,
        StatusCode::NOT_IMPLEMENTED,
        "a runtime without tracing installed says so rather than 500ing"
    );
}

#[tokio::test]
async fn explicit_request_sampling_option_is_honored_and_exported() {
    let state = test_state(true);
    let response = create_router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/traces/sessions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"capture_http":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let id = body_json(response).await["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let flow = FlowGuard::begin(state.tunnel.inner().trace_recorder());
    flow.capture_request(b"GET /app HTTP/1.1\r\nAuthorization: Bearer secret\r\n\r\n");
    drop(flow);
    let (status, response) = call(&state, "POST", &format!("/traces/sessions/{id}/stop")).await;
    assert_eq!(status, StatusCode::OK);
    let session = body_json(response).await;
    assert_eq!(session["session"]["recorded_flows"], 1);
    let (_, response) = call(&state, "GET", &format!("/traces/sessions/{id}/flows")).await;
    let body = body_json(response).await;
    let text = body["flows"][0]["http_request_sample"]["text"]
        .as_str()
        .unwrap();
    assert!(text.contains("GET /app"));
    assert!(!text.contains("secret"));
}
