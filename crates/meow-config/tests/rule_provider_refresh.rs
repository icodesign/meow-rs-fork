//! Rule-provider cache sidecars, refresh status and size limits (Potatso
//! additions on top of the cache-first load of #750).

use std::io::{Read, Write};
use std::sync::Arc;

use meow_common::{Metadata, Rule, RuleMatchHelper};

#[tokio::test]
async fn refresh_updates_live_handle_and_keeps_last_good_candidate() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for body in [
            "payload:\n  - 'old.example'\n",
            "payload:\n  - 'new.example'\n",
            "payload: not-a-sequence\n",
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            assert!(stream.read(&mut request).unwrap() > 0);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        }
    });

    let directory = tempfile::tempdir().unwrap();
    let cache_path = directory.path().join("rule-providers/live.yaml");
    let config_path = directory.path().join("config.yaml");
    std::fs::write(
        &config_path,
        format!(
            r#"
mode: rule
rule-providers:
  live:
    type: http
    behavior: domain
    format: yaml
    url: http://{addr}/rules.yaml
    path: rule-providers/live.yaml
    interval: 60
rules:
  - RULE-SET,live,DIRECT
  - MATCH,REJECT
"#
        ),
    )
    .unwrap();

    let config = meow_config::load_config(config_path.to_str().unwrap())
        .await
        .unwrap();
    let provider = Arc::clone(config.rule_providers.get("live").unwrap());
    let stable_rule: &dyn Rule = config.rules[0].as_ref();
    let metadata = |host: &str| Metadata {
        host: host.into(),
        ..Default::default()
    };
    let helper = RuleMatchHelper;

    assert!(stable_rule.match_metadata(&metadata("old.example"), &helper));
    assert!(!stable_rule.match_metadata(&metadata("new.example"), &helper));

    provider.refresh().await.unwrap();
    assert_eq!(provider.status().state, "ready");
    assert_eq!(provider.status().rule_count, 1);
    let (total, preview) = provider.preview_entries(0, 20).unwrap().unwrap();
    assert_eq!(total, 1);
    assert_eq!(preview, ["new.example"]);
    assert!(!stable_rule.match_metadata(&metadata("old.example"), &helper));
    assert!(stable_rule.match_metadata(&metadata("new.example"), &helper));
    assert_eq!(
        std::fs::read_to_string(&cache_path).unwrap(),
        "payload:\n  - 'new.example'\n"
    );

    provider
        .refresh()
        .await
        .expect_err("invalid candidate must not replace last-good rules");
    server.join().unwrap();
    assert!(stable_rule.match_metadata(&metadata("new.example"), &helper));
    assert_eq!(
        std::fs::read_to_string(cache_path).unwrap(),
        "payload:\n  - 'new.example'\n"
    );
    let status = provider.status();
    assert_eq!(status.state, "failed");
    assert!(status.using_last_good);
    assert!(status.last_error.is_some());
    assert!(directory
        .path()
        .join("rule-providers/live.yaml.status.json")
        .is_file());
}

#[tokio::test]
async fn cache_keeps_timestamp_binds_source_and_checks_payload_integrity() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for entry in ["first.test", "second.test", "third.test"] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            assert!(stream.read(&mut request).unwrap() > 0);
            let body = format!("payload:\n  - '{entry}'\n");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        }
    });
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.yaml");
    let write_config = |source: &str| {
        std::fs::write(&config_path, format!("mode: rule\nrule-providers:\n  live:\n    type: http\n    behavior: domain\n    format: yaml\n    url: http://{addr}/{source}\n    path: rule-providers/live.yaml\n    interval: 60\nrules:\n  - RULE-SET,live,DIRECT\n  - MATCH,REJECT\n")).unwrap();
    };
    write_config("first");
    let first = meow_config::load_config(config_path.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        first.rule_providers["live"]
            .preview_entries(0, 10)
            .unwrap()
            .unwrap()
            .1,
        ["first.test"]
    );
    let metadata_path = directory.path().join("rule-providers/live.yaml.meta.json");
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
    metadata["updated_at"] = 1234.into();
    metadata["last_attempt_at"] = 0.into();
    std::fs::write(&metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();
    let reloaded = meow_config::load_config(config_path.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        reloaded.rule_providers["live"].updated_at_secs(),
        1234,
        "cache reads must not renew freshness"
    );
    assert_eq!(
        reloaded.rule_providers["live"].status().next_update_at,
        Some(1294)
    );
    write_config("second");
    let changed = meow_config::load_config(config_path.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        changed.rule_providers["live"]
            .preview_entries(0, 10)
            .unwrap()
            .unwrap()
            .1,
        ["second.test"]
    );
    std::fs::write(
        directory.path().join("rule-providers/live.yaml"),
        "payload:\n  - 'tampered.test'\n",
    )
    .unwrap();
    let repaired = meow_config::load_config(config_path.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        repaired.rule_providers["live"]
            .preview_entries(0, 10)
            .unwrap()
            .unwrap()
            .1,
        ["third.test"]
    );
    server.join().unwrap();
}

#[tokio::test]
async fn expired_cached_provider_refreshes_immediately_after_reconnect() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for entry in ["old.test", "fresh.test"] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            assert!(stream.read(&mut request).unwrap() > 0);
            let body = format!("payload:\n  - '{entry}'\n");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        }
    });
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.yaml");
    std::fs::write(&config_path, format!("rule-providers:\n  live:\n    type: http\n    behavior: domain\n    url: http://{addr}/rules\n    path: rule-providers/live.yaml\n    interval: 86400\nrules:\n  - RULE-SET,live,DIRECT\n")).unwrap();
    let initial = meow_config::load_config(config_path.to_str().unwrap())
        .await
        .unwrap();
    drop(initial);
    let path = directory.path().join("rule-providers/live.yaml.meta.json");
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    metadata["updated_at"] = 1.into();
    metadata["last_attempt_at"] = 0.into();
    std::fs::write(&path, serde_json::to_vec(&metadata).unwrap()).unwrap();
    let reloaded = meow_config::load_config(config_path.to_str().unwrap())
        .await
        .unwrap();
    let provider = &reloaded.rule_providers["live"];
    let registry = Arc::new(parking_lot::RwLock::new(reloaded.rule_providers.clone()));
    let supervisor = meow_config::rule_provider_refresh::RefreshSupervisor::default();
    supervisor.reconcile(&registry);
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while provider.updated_at_secs() == 1 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("expired cache should not wait another complete interval");
    assert_eq!(
        provider.preview_entries(0, 10).unwrap().unwrap().1,
        ["fresh.test"]
    );
    server.join().unwrap();
}

#[tokio::test]
async fn provider_size_limit_rejects_oversized_initial_payload() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1024];
        assert!(stream.read(&mut request).unwrap() > 0);
        let body = "payload:\n  - 'oversized.test'\n";
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
    });
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.yaml");
    std::fs::write(&path, format!("rule-providers:\n  live:\n    type: http\n    behavior: domain\n    url: http://{addr}/rules\n    path: rule-providers/live.yaml\n    size-limit: 8\nrules:\n  - MATCH,DIRECT\n")).unwrap();
    let loaded = meow_config::load_config(path.to_str().unwrap())
        .await
        .unwrap();
    // 0.22.0 retains failed providers empty so later manual/interval refresh
    // can heal acquisition failures. Oversized bytes must remain uninstalled.
    let provider = &loaded.rule_providers["live"];
    assert_eq!(provider.rule_count(), 0);
    assert_eq!(provider.status().state, "failed");
    assert!(provider.status().last_error.is_some());
    assert!(!directory.path().join("rule-providers/live.yaml").exists());
    server.join().unwrap();
}

#[tokio::test]
async fn offline_download_publishes_cache_and_keeps_last_good_on_failure() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for body in ["payload:\n  - example.com\n", "payload: invalid\n"] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            assert!(stream.read(&mut request).unwrap() > 0);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        }
    });
    let directory = tempfile::tempdir().unwrap();
    let cfg: meow_config::raw::RawRuleProvider = serde_yaml::from_str(&format!(
        "type: http\nbehavior: domain\nformat: yaml\nurl: http://{addr}/rules\npath: rule-providers/direct.yaml\ninterval: 86400\n"
    ))
    .unwrap();
    let download = || {
        meow_config::rule_provider::download_http_provider(
            "direct".to_string(),
            cfg.clone(),
            directory.path().to_path_buf(),
            meow_config::GeoDataConfig::default(),
        )
    };
    download().await.unwrap();
    let cache = directory.path().join("rule-providers/direct.yaml");
    let original = std::fs::read(&cache).unwrap();
    let read_status = || -> serde_json::Value {
        serde_json::from_slice(
            &std::fs::read(
                directory
                    .path()
                    .join("rule-providers/direct.yaml.status.json"),
            )
            .unwrap(),
        )
        .unwrap()
    };
    assert_eq!(read_status()["state"], "ready");
    assert_eq!(read_status()["ruleCount"], 1);
    assert!(directory
        .path()
        .join("rule-providers/direct.yaml.meta.json")
        .is_file());

    download()
        .await
        .expect_err("an unparseable payload must not be published");
    server.join().unwrap();
    assert_eq!(std::fs::read(&cache).unwrap(), original);
    let status = read_status();
    assert_eq!(status["state"], "failed");
    assert_eq!(status["usingLastGood"], true);
    assert_eq!(status["ruleCount"], 1);
    assert!(status["lastError"].is_string());
}
