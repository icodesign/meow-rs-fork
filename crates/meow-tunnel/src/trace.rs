//! On-disk flow tracing for connection diagnostics.
//!
//! Tracing is an **opt-in recording session**, not a always-on collector: the
//! user flips it on, reproduces a problem, flips it off. That framing is what
//! keeps the cost defensible — when no session is active the only work on the
//! connection path is one relaxed [`AtomicBool`] load (see
//! [`TraceStore::recorder`]).
//!
//! # Storage layout
//!
//! Everything lives under one directory as newline-delimited JSON:
//!
//! ```text
//! <dir>/sessions.jsonl     append-only session event log (start / stop)
//! <dir>/<session_id>.jsonl one line per completed flow
//! ```
//!
//! `sessions.jsonl` is an *event log folded on read* rather than a mutable
//! index. That is deliberate: the embedding process can be killed at any
//! moment (an iOS network extension is reclaimed without warning), and a
//! session whose start event has no matching stop event is simply reported as
//! [`STATUS_INTERRUPTED`]. There is no index to repair and no torn write to
//! recover from.
//!
//! # Write path
//!
//! Flows are handed to a dedicated writer thread over a **bounded** channel and
//! never written from the connection task. Two reasons, both load-bearing:
//!
//! 1. A synchronous `write(2)` on the connection path would block a relay task.
//! 2. It would contaminate the very measurement being taken — the recorder's
//!    own I/O jitter would show up inside the stage timings it records.
//!
//! When the queue is full the flow is dropped and counted
//! ([`TraceRecorder::dropped`]); recording never applies backpressure to
//! traffic.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use meow_common::Metadata;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

#[path = "trace_http.rs"]
mod http;
pub use http::HttpRequestSample;

/// A session that is currently accepting flows.
pub const STATUS_RECORDING: &str = "recording";
/// A session the caller stopped explicitly.
pub const STATUS_COMPLETED: &str = "completed";
/// A session whose process died before it could be stopped.
pub const STATUS_INTERRUPTED: &str = "interrupted";
/// A session stopped by one of the [`TraceConfig`] caps.
pub const STATUS_TRUNCATED: &str = "truncated";

/// Flow reached the relay stage and closed normally.
pub const FLOW_STATUS_OK: &str = "ok";
/// Flow failed before or during relay; see `error_message`.
pub const FLOW_STATUS_FAILED: &str = "failed";
/// The connection task was dropped mid-flight (embedder cancellation, tunnel
/// shutdown, panic-unwind). Recorded from `Drop`, so these flows are captured
/// rather than silently lost — they are usually the interesting ones.
pub const FLOW_STATUS_ABORTED: &str = "aborted";

/// A connection still open when the recording ended.
pub const FLOW_STATUS_IN_PROGRESS: &str = "in_progress";

// Bound live diagnostic state independently of the on-disk session cap.
const MAX_LIVE_FLOWS: usize = 256;
type LiveFlows = Arc<Mutex<HashMap<String, Weak<FlowGuardInner>>>>;

const SESSIONS_FILE: &str = "sessions.jsonl";
const FLOW_FILE_SUFFIX: &str = ".jsonl";

/// How long the writer parks before waking to flush and re-check the caps.
/// Also bounds how stale an in-flight session file can be when read
/// concurrently.
const FLUSH_INTERVAL: Duration = Duration::from_millis(250);

/// One timed step inside a flow (`rule_match`, `dns_resolve`, `dial`, …).
///
/// Offsets are relative to the flow's own start so a reader can lay the stages
/// out on a timeline without knowing the wall-clock epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceFlowStage {
    pub name: String,
    pub started_offset_ms: u64,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// One connection's full lifecycle, written as a single JSONL line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceFlow {
    pub session_id: String,
    pub flow_id: String,
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
    pub network: String,
    pub inbound_tag: String,
    pub source_addr: String,
    pub destination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound_tag: Option<String>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub total_duration_ms: u64,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    pub stages: Vec<TraceFlowStage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_request_sample: Option<HttpRequestSample>,
}

/// A recording session's metadata, folded from the session event log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceSession {
    pub session_id: String,
    pub started_at_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at_ms: Option<i64>,
    pub status: String,
    #[serde(default)]
    pub capture_http: bool,
    #[serde(default)]
    pub recorded_flows: u64,
    #[serde(default)]
    pub dropped_flows: u64,
}

/// A line in `sessions.jsonl`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum SessionEvent {
    Start {
        session_id: String,
        started_at_ms: i64,
        #[serde(default)]
        capture_http: bool,
    },
    Stop {
        session_id: String,
        ended_at_ms: i64,
        status: String,
        #[serde(default)]
        recorded_flows: u64,
        #[serde(default)]
        dropped_flows: u64,
    },
}

/// Limits that keep a forgotten recording from filling the container.
///
/// All four exist because "user turns tracing on and walks away" is the
/// expected failure mode, not an edge case.
#[derive(Debug, Clone)]
pub struct TraceConfig {
    /// Directory holding `sessions.jsonl` and the per-session flow files.
    pub dir: PathBuf,
    /// Stop the session after this many flows.
    pub max_flows_per_session: usize,
    /// Stop the session once its flow file reaches this size.
    pub max_session_bytes: u64,
    /// Keep at most this many sessions on disk; oldest are pruned on start.
    pub max_sessions: usize,
    /// Stop the session after this much wall-clock time, even when idle.
    pub max_duration: Duration,
    /// Bounded hand-off queue depth between connection tasks and the writer.
    pub queue_capacity: usize,
}

impl TraceConfig {
    /// Defaults sized for interactive diagnosis: a few minutes of browsing
    /// fits comfortably, an overnight accident cannot.
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            max_flows_per_session: 20_000,
            max_session_bytes: 16 * 1024 * 1024,
            max_sessions: 10,
            max_duration: Duration::from_secs(30 * 60),
            queue_capacity: 1024,
        }
    }
}

/// Boxed so the enum stays small (`large_enum_variant`): `TraceFlow` is a
/// multi-`String` struct and the channel holds `queue_capacity` slots.
enum WriterMsg {
    Flow(Box<TraceFlow>),
    Stop,
}

/// Handle to the active session, cloned into the connection path.
///
/// Recording is fire-and-forget: [`Self::record`] never blocks, never fails
/// loudly, and never touches the filesystem.
pub struct TraceRecorder {
    session_id: String,
    started_at_ms: i64,
    tx: SyncSender<WriterMsg>,
    active: Arc<AtomicBool>,
    recorded: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    writer: Mutex<Option<JoinHandle<()>>>,
    live_flows: LiveFlows,
    capture_http: bool,
}

impl TraceRecorder {
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn started_at_ms(&self) -> i64 {
        self.started_at_ms
    }

    /// Whether the writer is still accepting flows. Goes false on explicit
    /// stop and when a [`TraceConfig`] cap trips.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Flows successfully handed to the writer.
    #[must_use]
    pub fn recorded(&self) -> u64 {
        self.recorded.load(Ordering::Relaxed)
    }

    /// Flows discarded because the queue was full. A non-zero value means the
    /// trace has holes — surface it rather than presenting a partial capture
    /// as complete.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Hand one completed flow to the writer thread.
    ///
    /// Called from connection tasks: bounded, non-blocking, allocation-free
    /// beyond the `Box` that moves the flow into the queue.
    pub fn record(&self, flow: TraceFlow) {
        if !self.active.load(Ordering::Relaxed) {
            return;
        }
        match self.tx.try_send(WriterMsg::Flow(Box::new(flow))) {
            Ok(()) => {
                self.recorded.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.active.store(false, Ordering::Relaxed);
            }
        }
    }

    /// Signal the writer to finalize and wait for it to land on disk.
    fn shutdown(&self) {
        // The writer freezes the live-flow registry before its final flush.
        // Doing that here would race a completing flow and lose its record.
        // A disconnected writer has already finalized; nothing to wait for.
        let _ = self.tx.send(WriterMsg::Stop);
        if let Some(handle) = self.writer.lock().take() {
            if handle.join().is_err() {
                warn!("trace writer thread panicked");
            }
        }
    }
}

/// Owns the trace directory and the at-most-one active session.
pub struct TraceStore {
    config: TraceConfig,
    /// Fast path for the connection hot path: checked before the mutex so an
    /// idle runtime pays one relaxed load per connection.
    enabled: AtomicBool,
    active: Mutex<Option<Arc<TraceRecorder>>>,
}

impl TraceStore {
    /// Create the store, ensuring the trace directory exists.
    ///
    /// # Errors
    /// Returns an error if the trace directory cannot be created.
    pub fn new(config: TraceConfig) -> io::Result<Self> {
        fs::create_dir_all(&config.dir)?;
        Ok(Self {
            config,
            enabled: AtomicBool::new(false),
            active: Mutex::new(None),
        })
    }

    #[must_use]
    pub fn config(&self) -> &TraceConfig {
        &self.config
    }

    /// The active recorder, or `None` when nothing is being recorded.
    ///
    /// This is the connection path's entry point — the [`AtomicBool`] check
    /// short-circuits before any locking when tracing is off.
    #[must_use]
    pub fn recorder(&self) -> Option<Arc<TraceRecorder>> {
        if !self.enabled.load(Ordering::Relaxed) {
            return None;
        }
        let mut guard = self.active.lock();
        let live = guard.as_ref().filter(|r| r.is_active()).map(Arc::clone);
        if live.is_none() {
            // Either nothing is recording, or a cap tripped and the writer
            // finalized itself — drop the dead handle so no caller sees it.
            *guard = None;
            self.enabled.store(false, Ordering::Relaxed);
        }
        live
    }

    #[must_use]
    pub fn is_recording(&self) -> bool {
        self.recorder().is_some()
    }

    /// Begin a recording session.
    ///
    /// Only one session may be active at a time, matching the single on/off
    /// control this is built for.
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::AlreadyExists`] when a session is already
    /// recording, or any I/O error from creating the session files.
    pub fn start_session(&self) -> io::Result<TraceSession> {
        self.start_session_with_http(false)
    }

    /// Start a recording, optionally sampling plaintext HTTP request bytes.
    pub fn start_session_with_http(&self, capture_http: bool) -> io::Result<TraceSession> {
        let mut guard = self.active.lock();
        if guard.as_ref().is_some_and(|r| r.is_active()) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a trace session is already recording",
            ));
        }
        *guard = None;

        // Prune before allocating a new slot so `max_sessions` counts the
        // session about to be created.
        if let Err(error) = self.prune_locked(self.config.max_sessions.saturating_sub(1)) {
            warn!("trace: pruning old sessions failed: {error}");
        }

        let session_id = uuid::Uuid::new_v4().to_string();
        let started_at_ms = now_ms();
        let flow_path = self.flow_path(&session_id);

        // Create the flow file up front so a session that records nothing is
        // still readable (empty) rather than a missing-file error.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&flow_path)?;

        append_session_event(
            &self.sessions_path(),
            &SessionEvent::Start {
                session_id: session_id.clone(),
                started_at_ms,
                capture_http,
            },
        )?;

        let (tx, rx) = sync_channel(self.config.queue_capacity);
        let active = Arc::new(AtomicBool::new(true));
        let recorded = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));

        let live_flows = Arc::new(Mutex::new(HashMap::new()));
        let writer = WriterContext {
            file: BufWriter::new(file),
            rx,
            sessions_path: self.sessions_path(),
            session_id: session_id.clone(),
            active: Arc::clone(&active),
            max_flows: self.config.max_flows_per_session,
            max_bytes: self.config.max_session_bytes,
            max_duration: self.config.max_duration,
            live_flows: Arc::clone(&live_flows),
            dropped: Arc::clone(&dropped),
        };
        let handle = std::thread::Builder::new()
            .name("meow-trace-writer".into())
            .spawn(move || writer.run())?;

        *guard = Some(Arc::new(TraceRecorder {
            session_id: session_id.clone(),
            started_at_ms,
            tx,
            active,
            recorded,
            dropped,
            writer: Mutex::new(Some(handle)),
            live_flows,
            capture_http,
        }));
        self.enabled.store(true, Ordering::Relaxed);

        debug!("trace: started session {session_id}");
        Ok(TraceSession {
            session_id,
            started_at_ms,
            ended_at_ms: None,
            status: STATUS_RECORDING.to_string(),
            capture_http,
            recorded_flows: 0,
            dropped_flows: 0,
        })
    }

    /// Stop the active session and wait for its file to be finalized.
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::NotFound`] when `session_id` is not the active
    /// session, or any I/O error from reading back the finalized session.
    pub fn stop_session(&self, session_id: &str) -> io::Result<TraceSession> {
        let recorder = {
            let mut guard = self.active.lock();
            match guard.as_ref() {
                Some(recorder) if recorder.session_id() == session_id => guard.take(),
                _ => None,
            }
        };
        let Some(recorder) = recorder else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no such recording session",
            ));
        };

        self.enabled.store(false, Ordering::Relaxed);
        recorder.shutdown();

        debug!(
            "trace: stopped session {session_id} ({} recorded, {} dropped)",
            recorder.recorded(),
            recorder.dropped()
        );
        self.session(session_id)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "session vanished after stop"))
    }

    /// Delete a session's flow file and its entries in the event log.
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::ResourceBusy`] for the session currently
    /// recording, or any I/O error from rewriting the event log.
    pub fn delete_session(&self, session_id: &str) -> io::Result<bool> {
        let guard = self.active.lock();
        if guard
            .as_ref()
            .is_some_and(|r| r.session_id() == session_id && r.is_active())
        {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                "stop the session before deleting it",
            ));
        }
        drop(guard);

        let sessions = self.read_sessions()?;
        if !sessions.iter().any(|s| s.session_id == session_id) {
            return Ok(false);
        }
        let retained = sessions
            .into_iter()
            .filter(|s| s.session_id != session_id)
            .collect::<Vec<_>>();
        self.rewrite_sessions(&retained)?;
        remove_file_if_present(&self.flow_path(session_id))?;
        Ok(true)
    }

    /// Sessions newest first, paginated.
    ///
    /// # Errors
    /// Returns any I/O error from reading the event log.
    pub fn list_sessions(&self, limit: usize, offset: usize) -> io::Result<Vec<TraceSession>> {
        let sessions = self.read_sessions()?;
        Ok(sessions.into_iter().skip(offset).take(limit).collect())
    }

    /// One session's metadata, or `None` when it is unknown.
    ///
    /// # Errors
    /// Returns any I/O error from reading the event log.
    pub fn session(&self, session_id: &str) -> io::Result<Option<TraceSession>> {
        Ok(self
            .read_sessions()?
            .into_iter()
            .find(|s| s.session_id == session_id))
    }

    /// A session's flows in recorded order, paginated.
    ///
    /// Pagination scans from the start of the file. That is acceptable here:
    /// sessions are capped at [`TraceConfig::max_flows_per_session`] and this
    /// is a diagnostic read, not a serving path.
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::NotFound`] for an unknown session, or any I/O
    /// error from reading its flow file.
    pub fn read_flows(
        &self,
        session_id: &str,
        limit: usize,
        offset: usize,
    ) -> io::Result<(TraceSession, Vec<TraceFlow>)> {
        let Some(session) = self.session(session_id)? else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no such trace session",
            ));
        };

        let path = self.flow_path(session_id);
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok((session, Vec::new()));
            }
            Err(error) => return Err(error),
        };

        let mut flows = Vec::new();
        let mut seen = 0usize;
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            // A crash can leave a half-written final line. Skipping it beats
            // failing the whole read — the rest of the capture is still good.
            let Ok(flow) = serde_json::from_str::<TraceFlow>(&line) else {
                debug!("trace: skipping unparsable flow line in session {session_id}");
                continue;
            };
            if seen < offset {
                seen += 1;
                continue;
            }
            flows.push(flow);
            if flows.len() >= limit {
                break;
            }
        }
        Ok((session, flows))
    }

    fn sessions_path(&self) -> PathBuf {
        self.config.dir.join(SESSIONS_FILE)
    }

    fn flow_path(&self, session_id: &str) -> PathBuf {
        self.config
            .dir
            .join(format!("{session_id}{FLOW_FILE_SUFFIX}"))
    }

    /// Fold the event log into sessions, newest first.
    fn read_sessions(&self) -> io::Result<Vec<TraceSession>> {
        let live = self
            .active
            .lock()
            .as_ref()
            .filter(|r| r.is_active())
            .map(|r| r.session_id().to_string());
        self.read_sessions_with_live(live.as_deref())
    }

    /// The lock-free core of [`Self::read_sessions`].
    ///
    /// Split out because `start_session` folds the log while already holding
    /// the active-session lock, and `parking_lot::Mutex` is not reentrant —
    /// re-locking here would deadlock the caller.
    ///
    /// A start without a stop means the process died mid-recording unless it
    /// is `live`, so it is reported as [`STATUS_INTERRUPTED`].
    fn read_sessions_with_live(&self, live: Option<&str>) -> io::Result<Vec<TraceSession>> {
        let path = self.sessions_path();
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };

        let mut sessions: Vec<TraceSession> = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let Ok(event) = serde_json::from_str::<SessionEvent>(&line) else {
                debug!("trace: skipping unparsable session event");
                continue;
            };
            match event {
                SessionEvent::Start {
                    session_id,
                    started_at_ms,
                    capture_http,
                } => sessions.push(TraceSession {
                    session_id,
                    started_at_ms,
                    ended_at_ms: None,
                    status: STATUS_RECORDING.to_string(),
                    capture_http,
                    recorded_flows: 0,
                    dropped_flows: 0,
                }),
                SessionEvent::Stop {
                    session_id,
                    ended_at_ms,
                    status,
                    recorded_flows,
                    dropped_flows,
                } => {
                    if let Some(session) = sessions
                        .iter_mut()
                        .rev()
                        .find(|s| s.session_id == session_id)
                    {
                        session.ended_at_ms = Some(ended_at_ms);
                        session.status = status;
                        session.recorded_flows = recorded_flows;
                        session.dropped_flows = dropped_flows;
                    }
                }
            }
        }

        for session in &mut sessions {
            if session.status == STATUS_RECORDING && live != Some(session.session_id.as_str()) {
                session.status = STATUS_INTERRUPTED.to_string();
            }
        }
        sessions.sort_by_key(|session| std::cmp::Reverse(session.started_at_ms));
        Ok(sessions)
    }

    /// Keep the `keep` newest sessions, deleting the rest.
    ///
    /// Caller holds the active-session lock and has already cleared it, so no
    /// session is live from this fold's point of view.
    fn prune_locked(&self, keep: usize) -> io::Result<()> {
        let sessions = self.read_sessions_with_live(None)?;
        if sessions.len() <= keep {
            return Ok(());
        }
        let (retained, pruned) = sessions.split_at(keep);
        for session in pruned {
            remove_file_if_present(&self.flow_path(&session.session_id))?;
        }
        self.rewrite_sessions(retained)
    }

    /// Rebuild the event log from a session list.
    ///
    /// Written to a temp file and renamed so a crash mid-prune leaves the old
    /// log intact rather than a truncated one.
    fn rewrite_sessions(&self, sessions: &[TraceSession]) -> io::Result<()> {
        let path = self.sessions_path();
        let temp = path.with_extension("jsonl.tmp");
        {
            let mut writer = BufWriter::new(File::create(&temp)?);
            // Oldest first, so a re-read folds them back in the original order.
            for session in sessions.iter().rev() {
                write_event(
                    &mut writer,
                    &SessionEvent::Start {
                        session_id: session.session_id.clone(),
                        started_at_ms: session.started_at_ms,
                        capture_http: session.capture_http,
                    },
                )?;
                if let Some(ended_at_ms) = session.ended_at_ms {
                    write_event(
                        &mut writer,
                        &SessionEvent::Stop {
                            session_id: session.session_id.clone(),
                            ended_at_ms,
                            status: session.status.clone(),
                            recorded_flows: session.recorded_flows,
                            dropped_flows: session.dropped_flows,
                        },
                    )?;
                }
            }
            writer.flush()?;
        }
        fs::rename(&temp, &path)
    }
}

impl Drop for TraceStore {
    fn drop(&mut self) {
        if let Some(recorder) = self.active.lock().take() {
            recorder.shutdown();
        }
    }
}

/// Collects one connection's timeline while it runs, emitting a [`TraceFlow`]
/// on drop.
///
/// Emitting from `Drop` rather than at the end of `handle_tcp` is deliberate
/// and mirrors [`crate::ConnectionGuard`]: a connection task can be cancelled
/// mid-`.await` (embedder cancellation, tunnel shutdown, unwind), and those
/// flows are exactly the ones worth seeing. `Drop` runs on every exit path.
///
/// Cost when no session is recording: `inner` is `None`, every method is a
/// single branch, and [`Self::now`] does not even read the clock.
pub struct FlowGuard {
    inner: Option<Arc<FlowGuardInner>>,
}

struct FlowGuardInner {
    flow_id: String,
    recorder: Arc<TraceRecorder>,
    started_at_ms: i64,
    start: Instant,
    state: Mutex<FlowState>,
}

#[derive(Default)]
struct FlowState {
    stages: Vec<TraceFlowStage>,
    pending_stages: Vec<(String, Instant)>,
    request: http::HttpSampleBuffer,
    upload_bytes: u64,
    download_bytes: u64,
    network: String,
    inbound_tag: String,
    source_addr: String,
    destination: String,
    resolved_ip: Option<String>,
    outbound_tag: Option<String>,
    /// Shared with the statistics table, so an aborted flow still reports the
    /// bytes it moved before it died.
    counters: Option<Arc<crate::statistics::ConnCounters>>,
    status: Option<&'static str>,
    error: Option<String>,
    emitted: bool,
}

impl FlowGuard {
    fn active_inner(&self) -> Option<&FlowGuardInner> {
        self.inner
            .as_deref()
            .filter(|inner| inner.recorder.is_active())
    }

    /// A guard that records nothing. Used by the untraced call paths so they
    /// share one code path with the traced ones.
    #[must_use]
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    /// Start collecting, if `recorder` is `Some` (i.e. a session is live).
    #[must_use]
    pub fn begin(recorder: Option<Arc<TraceRecorder>>) -> Self {
        let Some(recorder) = recorder else {
            return Self::disabled();
        };
        let mut live = recorder.live_flows.lock();
        if !recorder.is_active() || live.len() >= MAX_LIVE_FLOWS {
            recorder.dropped.fetch_add(1, Ordering::Relaxed);
            return Self::disabled();
        }
        let inner = Arc::new(FlowGuardInner {
            flow_id: uuid::Uuid::new_v4().to_string(),
            recorder: Arc::clone(&recorder),
            started_at_ms: now_ms(),
            start: Instant::now(),
            state: Mutex::new(FlowState::default()),
        });
        live.insert(inner.flow_id.clone(), Arc::downgrade(&inner));
        Self { inner: Some(inner) }
    }

    #[must_use]
    pub fn is_recording(&self) -> bool {
        self.active_inner().is_some()
    }

    /// Timestamp for the start of a stage.
    ///
    /// Returns `None` — and skips the clock read entirely — when this guard is
    /// not recording, so untraced connections pay nothing for the call sites.
    #[must_use]
    #[inline]
    pub fn now(&self) -> Option<Instant> {
        self.active_inner().map(|_| Instant::now())
    }

    /// Close a stage opened at `started`.
    ///
    /// `detail` is a closure so its (allocating) body never runs when tracing
    /// is off.
    pub fn stage<F>(&self, name: &str, started: Option<Instant>, detail: F)
    where
        F: FnOnce() -> Option<String>,
    {
        let (Some(inner), Some(started)) = (self.active_inner(), started) else {
            return;
        };
        let stage = TraceFlowStage {
            name: name.to_string(),
            started_offset_ms: millis(started.saturating_duration_since(inner.start)),
            duration_ms: millis(started.elapsed()),
            detail: detail(),
        };
        let mut state = inner.state.lock();
        state.pending_stages.retain(|(pending, _)| pending != name);
        state.stages.push(stage);
    }

    /// Begin a stage that may still be pending when the user stops recording.
    pub fn start_stage(&self, name: &str) {
        if let Some(inner) = self.active_inner() {
            inner
                .state
                .lock()
                .pending_stages
                .push((name.to_string(), Instant::now()));
        }
    }

    /// Observe the beginning of an inbound TCP stream, only when opted in.
    pub fn capture_request(&self, bytes: &[u8]) {
        if let Some(inner) = self.active_inner() {
            if inner.recorder.capture_http {
                inner.state.lock().request.observe(bytes);
            }
        }
    }

    /// Byte counters for UDP/DNS, which do not use the TCP statistics table.
    pub fn add_traffic(&self, upload: usize, download: usize) {
        if let Some(inner) = self.active_inner() {
            let mut state = inner.state.lock();
            state.upload_bytes = state.upload_bytes.saturating_add(upload as u64);
            state.download_bytes = state.download_bytes.saturating_add(download as u64);
        }
    }

    /// Snapshot the addressing fields. Called once the metadata is enriched so
    /// a later abort still has something to report.
    pub fn observe(&self, metadata: &Metadata) {
        let Some(inner) = self.active_inner() else {
            return;
        };
        let mut state = inner.state.lock();
        state.network = metadata.network.to_string();
        state.inbound_tag = metadata.in_name.to_string();
        state.source_addr = metadata.source_address().to_string();
        state.destination = metadata.remote_address().to_string();
        state.resolved_ip = metadata.dst_ip.map(|ip| ip.to_string());
    }

    /// Record the resolved address separately from [`Self::observe`], for the
    /// DNS stage which resolves before the rest of the metadata settles.
    pub fn set_resolved_ip(&self, ip: &std::net::IpAddr) {
        if let Some(inner) = self.active_inner() {
            inner.state.lock().resolved_ip = Some(ip.to_string());
        }
    }

    pub fn set_outbound(&self, name: &str) {
        if let Some(inner) = self.active_inner() {
            inner.state.lock().outbound_tag = Some(name.to_string());
        }
    }

    /// Share the live byte counters so `Drop` can report traffic for flows
    /// that never reach an explicit completion.
    pub fn attach_counters(&self, counters: &Arc<crate::statistics::ConnCounters>) {
        if let Some(inner) = self.active_inner() {
            inner.state.lock().counters = Some(Arc::clone(counters));
        }
    }

    /// Mark the flow as having completed its relay normally.
    pub fn succeed(&self) {
        if let Some(inner) = self.active_inner() {
            inner.state.lock().status = Some(FLOW_STATUS_OK);
        }
    }

    /// Mark the flow as failed, capturing `error` as the reason.
    pub fn fail(&self, error: &dyn std::fmt::Display) {
        if let Some(inner) = self.active_inner() {
            let mut state = inner.state.lock();
            state.status = Some(FLOW_STATUS_FAILED);
            state.error = Some(error.to_string());
        }
    }
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        let Some(inner) = &self.inner else {
            return;
        };
        // Serialize completion with the writer's final live-flow snapshot.
        let mut live = inner.recorder.live_flows.lock();
        live.remove(&inner.flow_id);
        if let Some(flow) = inner.take_flow(FLOW_STATUS_ABORTED) {
            inner.recorder.record(flow);
        }
    }
}

impl FlowGuardInner {
    fn take_flow(&self, unfinished_status: &str) -> Option<TraceFlow> {
        let mut state = self.state.lock();
        if state.emitted {
            return None;
        }
        state.emitted = true;
        let (upload_bytes, download_bytes) = state.counters.as_ref().map_or(
            (state.upload_bytes, state.download_bytes),
            |counters| {
                (
                    u64::try_from(counters.upload_bytes()).unwrap_or(0),
                    u64::try_from(counters.download_bytes()).unwrap_or(0),
                )
            },
        );
        let pending = std::mem::take(&mut state.pending_stages);
        for (name, started) in pending {
            state.stages.push(TraceFlowStage {
                name,
                started_offset_ms: millis(started.saturating_duration_since(self.start)),
                duration_ms: millis(started.elapsed()),
                detail: Some("Still pending when recording ended".into()),
            });
        }
        Some(TraceFlow {
            session_id: self.recorder.session_id().to_string(),
            flow_id: self.flow_id.clone(),
            started_at_ms: self.started_at_ms,
            ended_at_ms: now_ms(),
            network: std::mem::take(&mut state.network),
            inbound_tag: std::mem::take(&mut state.inbound_tag),
            source_addr: std::mem::take(&mut state.source_addr),
            destination: std::mem::take(&mut state.destination),
            resolved_ip: state.resolved_ip.take(),
            outbound_tag: state.outbound_tag.take(),
            upload_bytes,
            download_bytes,
            total_duration_ms: millis(self.start.elapsed()),
            status: state.status.unwrap_or(unfinished_status).to_string(),
            error_message: state.error.take(),
            stages: std::mem::take(&mut state.stages),
            http_request_sample: state.request.finish(),
        })
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Everything the writer thread owns, moved across the spawn boundary.
struct WriterContext {
    file: BufWriter<File>,
    rx: Receiver<WriterMsg>,
    sessions_path: PathBuf,
    session_id: String,
    active: Arc<AtomicBool>,
    max_flows: usize,
    max_bytes: u64,
    max_duration: Duration,
    live_flows: LiveFlows,
    dropped: Arc<AtomicU64>,
}

impl WriterContext {
    fn run(mut self) {
        let started = Instant::now();
        let mut flows = 0usize;
        let mut bytes = 0u64;
        let mut dirty = false;

        let mut status = loop {
            if started.elapsed() >= self.max_duration {
                break STATUS_TRUNCATED;
            }
            match self.rx.recv_timeout(FLUSH_INTERVAL) {
                Ok(WriterMsg::Flow(flow)) => {
                    match serde_json::to_string(&flow) {
                        Ok(line) => {
                            if bytes + line.len() as u64 + 1 > self.max_bytes {
                                self.dropped.fetch_add(1, Ordering::Relaxed);
                                break STATUS_TRUNCATED;
                            }
                            if let Err(error) = writeln!(self.file, "{line}") {
                                self.dropped.fetch_add(1, Ordering::Relaxed);
                                warn!("trace: write failed, ending session: {error}");
                                break STATUS_TRUNCATED;
                            }
                            // +1 for the newline; close enough for a cap.
                            bytes += line.len() as u64 + 1;
                            flows += 1;
                            dirty = true;
                        }
                        Err(error) => {
                            self.dropped.fetch_add(1, Ordering::Relaxed);
                            warn!("trace: dropping unserializable flow: {error}");
                        }
                    }
                    if flows >= self.max_flows || bytes >= self.max_bytes {
                        break STATUS_TRUNCATED;
                    }
                }
                Ok(WriterMsg::Stop) => break STATUS_COMPLETED,
                Err(RecvTimeoutError::Timeout) => {
                    if dirty {
                        if let Err(error) = self.file.flush() {
                            warn!("trace: flush failed: {error}");
                            break STATUS_TRUNCATED;
                        }
                        dirty = false;
                    }
                }
                // Every sender is gone without an explicit stop — the runtime
                // went away underneath us.
                Err(RecvTimeoutError::Disconnected) => break STATUS_INTERRUPTED,
            }
        };

        // Stop accepting flows before the final flush so nothing races in
        // after the stop event is durable.
        let mut live = self.live_flows.lock();
        self.active.store(false, Ordering::Relaxed);
        let pending: Vec<_> = live
            .values()
            .filter_map(Weak::upgrade)
            .filter_map(|inner| inner.take_flow(FLOW_STATUS_IN_PROGRESS))
            .collect();
        live.clear();
        drop(live);
        // No registry lock is held across serialization or filesystem I/O.
        // A connection finishing during stop can release its guard immediately.
        let completed = self.rx.try_iter().filter_map(|message| match message {
            WriterMsg::Flow(flow) => Some(*flow),
            WriterMsg::Stop => None,
        });
        // A guard can complete after Stop is enqueued but before the registry
        // freezes. Its flow is behind Stop in the queue and must still be kept.
        for flow in pending.into_iter().chain(completed) {
            if flows >= self.max_flows || bytes >= self.max_bytes {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                status = STATUS_TRUNCATED;
                continue;
            }
            if let Ok(line) = serde_json::to_string(&flow) {
                if bytes + line.len() as u64 + 1 > self.max_bytes
                    || writeln!(self.file, "{line}").is_err()
                {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    status = STATUS_TRUNCATED;
                    continue;
                }
                bytes += line.len() as u64 + 1;
                flows += 1;
            }
        }
        if let Err(error) = self.file.flush() {
            status = STATUS_TRUNCATED;
            warn!("trace: final flush failed: {error}");
        }
        if let Err(error) = append_session_event(
            &self.sessions_path,
            &SessionEvent::Stop {
                session_id: self.session_id.clone(),
                ended_at_ms: now_ms(),
                status: status.to_string(),
                recorded_flows: flows as u64,
                dropped_flows: self.dropped.load(Ordering::Relaxed),
            },
        ) {
            warn!("trace: recording stop event failed: {error}");
        }
        debug!(
            "trace: writer for {} finished with {flows} flows ({status})",
            self.session_id
        );
    }
}

fn write_event(writer: &mut impl Write, event: &SessionEvent) -> io::Result<()> {
    let line = serde_json::to_string(event).map_err(io::Error::other)?;
    writeln!(writer, "{line}")
}

fn append_session_event(path: &Path, event: &SessionEvent) -> io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    write_event(&mut file, event)?;
    file.flush()
}

fn remove_file_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "meow-trace-{label}-{}",
                uuid::Uuid::new_v4().simple()
            ));
            fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn store(dir: &TempDir) -> TraceStore {
        TraceStore::new(TraceConfig::new(dir.0.clone())).expect("create store")
    }

    fn flow(session_id: &str, destination: &str) -> TraceFlow {
        TraceFlow {
            session_id: session_id.to_string(),
            flow_id: uuid::Uuid::new_v4().to_string(),
            started_at_ms: 1_700_000_000_000,
            ended_at_ms: 1_700_000_000_120,
            network: "tcp".to_string(),
            inbound_tag: "tun".to_string(),
            source_addr: "10.0.0.2:51000".to_string(),
            destination: destination.to_string(),
            resolved_ip: Some("93.184.216.34".to_string()),
            outbound_tag: Some("PROXY".to_string()),
            upload_bytes: 512,
            download_bytes: 4096,
            total_duration_ms: 120,
            status: FLOW_STATUS_OK.to_string(),
            error_message: None,
            http_request_sample: None,
            stages: vec![TraceFlowStage {
                name: "dial".to_string(),
                started_offset_ms: 5,
                duration_ms: 60,
                detail: Some("PROXY".to_string()),
            }],
        }
    }

    #[test]
    fn recorder_is_none_until_a_session_starts() {
        let dir = TempDir::new("idle");
        let store = store(&dir);
        assert!(
            store.recorder().is_none(),
            "idle store hands out no recorder"
        );
        assert!(!store.is_recording());
    }

    #[test]
    fn flows_round_trip_through_the_writer() {
        let dir = TempDir::new("roundtrip");
        let store = store(&dir);
        let session = store.start_session().expect("start");

        let recorder = store.recorder().expect("recorder while recording");
        let written = flow(&session.session_id, "example.com:443");
        recorder.record(written.clone());

        let stopped = store.stop_session(&session.session_id).expect("stop");
        assert_eq!(stopped.status, STATUS_COMPLETED);
        assert!(stopped.ended_at_ms.is_some());

        let (_, flows) = store
            .read_flows(&session.session_id, 50, 0)
            .expect("read flows");
        assert_eq!(flows, vec![written], "flow survives the JSONL round trip");
    }

    #[test]
    fn only_one_session_records_at_a_time() {
        let dir = TempDir::new("single");
        let store = store(&dir);
        let session = store.start_session().expect("start");

        let error = store.start_session().expect_err("second start rejected");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);

        store.stop_session(&session.session_id).expect("stop");
        store.start_session().expect("start after stop");
    }

    #[test]
    fn flow_cap_truncates_the_session() {
        let dir = TempDir::new("cap");
        let mut config = TraceConfig::new(dir.0.clone());
        config.max_flows_per_session = 3;
        let store = TraceStore::new(config).expect("create store");
        let session = store.start_session().expect("start");
        let recorder = store.recorder().expect("recorder");

        for index in 0..10 {
            recorder.record(flow(&session.session_id, &format!("host{index}:443")));
        }

        // The writer self-finalizes once the cap trips; wait for it to settle.
        let deadline = Instant::now() + Duration::from_secs(5);
        while recorder.is_active() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!recorder.is_active(), "cap stops the writer");
        assert!(
            store.recorder().is_none(),
            "store drops the finalized recorder"
        );

        let listed = store.list_sessions(10, 0).expect("list");
        assert_eq!(listed[0].status, STATUS_TRUNCATED);

        let (_, flows) = store
            .read_flows(&session.session_id, 100, 0)
            .expect("read flows");
        assert_eq!(flows.len(), 3, "no flows past the cap are written");
    }

    #[test]
    fn interrupted_sessions_are_reported_without_a_stop_event() {
        let dir = TempDir::new("interrupted");
        // Simulate a process that died mid-recording: a start event with no
        // matching stop, and no live recorder to claim it.
        append_session_event(
            &dir.0.join(SESSIONS_FILE),
            &SessionEvent::Start {
                session_id: "ghost".to_string(),
                started_at_ms: 1_700_000_000_000,
                capture_http: false,
            },
        )
        .expect("write start event");

        let store = store(&dir);
        let sessions = store.list_sessions(10, 0).expect("list");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].status, STATUS_INTERRUPTED);
    }

    #[test]
    fn live_session_is_not_marked_interrupted() {
        let dir = TempDir::new("live");
        let store = store(&dir);
        let session = store.start_session().expect("start");

        let sessions = store.list_sessions(10, 0).expect("list");
        assert_eq!(sessions[0].status, STATUS_RECORDING);

        store.stop_session(&session.session_id).expect("stop");
    }

    #[test]
    fn pruning_keeps_the_newest_sessions() {
        let dir = TempDir::new("prune");
        let mut config = TraceConfig::new(dir.0.clone());
        config.max_sessions = 2;
        let store = TraceStore::new(config).expect("create store");

        let mut ids = Vec::new();
        for _ in 0..4 {
            let session = store.start_session().expect("start");
            store.stop_session(&session.session_id).expect("stop");
            ids.push(session.session_id);
            // started_at_ms has millisecond resolution and ordering drives the
            // prune decision.
            std::thread::sleep(Duration::from_millis(2));
        }

        let sessions = store.list_sessions(10, 0).expect("list");
        assert_eq!(sessions.len(), 2, "older sessions are pruned");
        assert_eq!(sessions[0].session_id, ids[3]);
        assert_eq!(sessions[1].session_id, ids[2]);
        assert!(
            !dir.0.join(format!("{}{FLOW_FILE_SUFFIX}", ids[0])).exists(),
            "pruned flow file is deleted"
        );
    }

    #[test]
    fn delete_removes_the_session_and_its_flows() {
        let dir = TempDir::new("delete");
        let store = store(&dir);
        let session = store.start_session().expect("start");
        store
            .recorder()
            .expect("recorder")
            .record(flow(&session.session_id, "example.com:443"));
        store.stop_session(&session.session_id).expect("stop");

        assert!(store.delete_session(&session.session_id).expect("delete"));
        assert!(store.list_sessions(10, 0).expect("list").is_empty());
        assert!(!dir
            .0
            .join(format!("{}{FLOW_FILE_SUFFIX}", session.session_id))
            .exists());
        assert!(
            !store
                .delete_session(&session.session_id)
                .expect("re-delete"),
            "deleting a missing session reports false, not an error"
        );
    }

    #[test]
    fn active_session_cannot_be_deleted() {
        let dir = TempDir::new("delete-active");
        let store = store(&dir);
        let session = store.start_session().expect("start");

        let error = store
            .delete_session(&session.session_id)
            .expect_err("active session is protected");
        assert_eq!(error.kind(), io::ErrorKind::ResourceBusy);

        store.stop_session(&session.session_id).expect("stop");
    }

    #[test]
    fn flow_pagination_walks_the_file() {
        let dir = TempDir::new("paginate");
        let store = store(&dir);
        let session = store.start_session().expect("start");
        let recorder = store.recorder().expect("recorder");
        for index in 0..10 {
            recorder.record(flow(&session.session_id, &format!("host{index}:443")));
        }
        store.stop_session(&session.session_id).expect("stop");

        let (_, page) = store
            .read_flows(&session.session_id, 3, 4)
            .expect("read page");
        assert_eq!(page.len(), 3);
        assert_eq!(page[0].destination, "host4:443");
        assert_eq!(page[2].destination, "host6:443");
    }

    #[test]
    fn truncated_trailing_line_does_not_fail_the_read() {
        let dir = TempDir::new("torn");
        let store = store(&dir);
        let session = store.start_session().expect("start");
        store
            .recorder()
            .expect("recorder")
            .record(flow(&session.session_id, "example.com:443"));
        store.stop_session(&session.session_id).expect("stop");

        // Append a half-written line, as a crash mid-write would leave.
        let mut file = OpenOptions::new()
            .append(true)
            .open(
                dir.0
                    .join(format!("{}{FLOW_FILE_SUFFIX}", session.session_id)),
            )
            .expect("open flow file");
        file.write_all(b"{\"session_id\":\"tor").expect("write");
        drop(file);

        let (_, flows) = store
            .read_flows(&session.session_id, 50, 0)
            .expect("read survives the torn line");
        assert_eq!(flows.len(), 1);
    }

    #[test]
    fn dropped_flows_are_counted_not_blocked() {
        let dir = TempDir::new("backpressure");
        let mut config = TraceConfig::new(dir.0.clone());
        config.queue_capacity = 1;
        let store = TraceStore::new(config).expect("create store");
        let session = store.start_session().expect("start");
        let recorder = store.recorder().expect("recorder");

        for index in 0..5_000 {
            recorder.record(flow(&session.session_id, &format!("host{index}:443")));
        }
        store.stop_session(&session.session_id).expect("stop");

        assert_eq!(
            recorder.recorded() + recorder.dropped(),
            5_000,
            "every flow is either queued or counted as dropped"
        );
    }

    /// Read back the flows a closure records, stopping the session first so
    /// the writer has flushed.
    fn recorded_flows(store: &TraceStore, session_id: &str) -> Vec<TraceFlow> {
        store.stop_session(session_id).expect("stop");
        store.read_flows(session_id, 100, 0).expect("read").1
    }

    fn traced_metadata() -> Metadata {
        Metadata {
            network: meow_common::Network::Tcp,
            host: "example.com".into(),
            dst_port: 443,
            in_name: "tun".into(),
            ..Default::default()
        }
    }

    #[test]
    fn disabled_guard_records_nothing() {
        let guard = FlowGuard::disabled();
        assert!(!guard.is_recording());
        assert!(
            guard.now().is_none(),
            "an inert guard must not even read the clock"
        );
        // Exercising the full surface must not panic or allocate a flow.
        guard.stage("dial", guard.now(), || panic!("detail must not be built"));
        guard.observe(&traced_metadata());
        guard.set_outbound("PROXY");
        guard.succeed();
    }

    #[test]
    fn guard_emits_a_flow_with_its_stages_on_drop() {
        let dir = TempDir::new("guard-stages");
        let store = store(&dir);
        let session = store.start_session().expect("start");

        {
            let guard = FlowGuard::begin(store.recorder());
            assert!(guard.is_recording());
            let started = guard.now();
            guard.stage("rule_match", started, || Some("DOMAIN(example.com)".into()));
            guard.stage("dial", guard.now(), || Some("PROXY".into()));
            guard.observe(&traced_metadata());
            guard.set_outbound("PROXY");
            guard.succeed();
        }

        let flows = recorded_flows(&store, &session.session_id);
        assert_eq!(flows.len(), 1, "dropping the guard emits exactly one flow");
        let flow = &flows[0];
        assert_eq!(flow.status, FLOW_STATUS_OK);
        assert_eq!(flow.destination, "example.com:443");
        assert_eq!(flow.inbound_tag, "tun");
        assert_eq!(flow.outbound_tag.as_deref(), Some("PROXY"));
        assert_eq!(
            flow.stages
                .iter()
                .map(|stage| stage.name.as_str())
                .collect::<Vec<_>>(),
            vec!["rule_match", "dial"],
            "stages keep the order they were closed in"
        );
        assert_eq!(
            flow.stages[0].detail.as_deref(),
            Some("DOMAIN(example.com)")
        );
    }

    #[test]
    fn abandoned_flow_is_recorded_as_aborted_with_its_bytes() {
        let dir = TempDir::new("guard-abort");
        let store = store(&dir);
        let session = store.start_session().expect("start");

        {
            // No succeed()/fail() — models a task cancelled mid-relay.
            let guard = FlowGuard::begin(store.recorder());
            guard.observe(&traced_metadata());
            let counters = Arc::new(crate::statistics::ConnCounters::default());
            counters.upload.store(1234, Ordering::Relaxed);
            counters.download.store(5678, Ordering::Relaxed);
            guard.attach_counters(&counters);
        }

        let flows = recorded_flows(&store, &session.session_id);
        assert_eq!(flows.len(), 1);
        assert_eq!(
            flows[0].status, FLOW_STATUS_ABORTED,
            "a flow that never completed is still captured"
        );
        assert_eq!(flows[0].upload_bytes, 1234);
        assert_eq!(flows[0].download_bytes, 5678);
    }

    #[test]
    fn failed_flow_carries_its_error() {
        let dir = TempDir::new("guard-fail");
        let store = store(&dir);
        let session = store.start_session().expect("start");

        {
            let guard = FlowGuard::begin(store.recorder());
            guard.observe(&traced_metadata());
            guard.fail(&"connection refused");
        }

        let flows = recorded_flows(&store, &session.session_id);
        assert_eq!(flows[0].status, FLOW_STATUS_FAILED);
        assert_eq!(
            flows[0].error_message.as_deref(),
            Some("connection refused")
        );
    }

    #[test]
    fn guard_is_inert_when_no_session_is_recording() {
        let dir = TempDir::new("guard-idle");
        let store = store(&dir);
        let guard = FlowGuard::begin(store.recorder());
        assert!(
            !guard.is_recording(),
            "no session means the connection path stays on the cheap path"
        );
    }

    #[test]
    fn recording_stops_when_the_store_is_dropped() {
        let dir = TempDir::new("drop");
        let session_id = {
            let store = store(&dir);
            let session = store.start_session().expect("start");
            store
                .recorder()
                .expect("recorder")
                .record(flow(&session.session_id, "example.com:443"));
            session.session_id
        };

        let store = store(&dir);
        let sessions = store.list_sessions(10, 0).expect("list");
        assert_eq!(sessions[0].session_id, session_id);
        assert_ne!(
            sessions[0].status, STATUS_RECORDING,
            "dropping the store finalizes the session"
        );
    }
    #[test]
    fn stopping_records_a_pending_flow_without_closing_the_connection() {
        let dir = TempDir::new("pending");
        let store = store(&dir);
        let session = store.start_session().expect("start");
        let guard = FlowGuard::begin(store.recorder());
        guard.observe(&traced_metadata());
        guard.start_stage("dial");
        guard.add_traffic(45, 0);
        store.stop_session(&session.session_id).expect("stop");
        assert!(!guard.is_recording());
        assert!(guard.now().is_none());
        guard.stage("after-stop", guard.now(), || {
            panic!("stopped recording must not build details")
        });
        guard.add_traffic(999, 999);
        let (_, flows) = store.read_flows(&session.session_id, 10, 0).expect("read");
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].status, FLOW_STATUS_IN_PROGRESS);
        assert_eq!(flows[0].upload_bytes, 45);
        assert_eq!(flows[0].stages[0].name, "dial");
        drop(guard);
        assert_eq!(
            store
                .read_flows(&session.session_id, 10, 0)
                .expect("read")
                .1
                .len(),
            1
        );
    }

    #[test]
    fn request_contents_require_explicit_opt_in() {
        let dir = TempDir::new("request-opt-in");
        let store = store(&dir);
        for enabled in [false, true] {
            let session = store.start_session_with_http(enabled).expect("start");
            let guard = FlowGuard::begin(store.recorder());
            guard.observe(&traced_metadata());
            guard.capture_request(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
            guard.succeed();
            drop(guard);
            store.stop_session(&session.session_id).expect("stop");
            let (_, flows) = store.read_flows(&session.session_id, 10, 0).expect("read");
            assert_eq!(flows[0].http_request_sample.is_some(), enabled);
            assert_eq!(
                store.list_sessions(10, 0).expect("sessions")[0].capture_http,
                enabled
            );
        }
    }

    #[test]
    fn stop_and_concurrent_completion_preserve_each_flow_once() {
        for _ in 0..10 {
            let dir = TempDir::new("stop-race");
            let store = store(&dir);
            let session = store.start_session().expect("start");
            let barrier = Arc::new(std::sync::Barrier::new(21));
            let threads: Vec<_> = (0..20)
                .map(|_| {
                    let guard = FlowGuard::begin(store.recorder());
                    guard.observe(&traced_metadata());
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        guard.succeed();
                        drop(guard);
                    })
                })
                .collect();
            barrier.wait();
            store.stop_session(&session.session_id).expect("stop");
            for thread in threads {
                thread.join().expect("join");
            }
            let (session, flows) = store.read_flows(&session.session_id, 100, 0).expect("read");
            assert_eq!(flows.len(), 20);
            assert_eq!(
                flows
                    .iter()
                    .map(|flow| &flow.flow_id)
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                20
            );
            assert_eq!(session.dropped_flows, 0);
        }
    }

    #[test]
    fn live_state_cap_is_reported_without_retaining_unbounded_connections() {
        let dir = TempDir::new("live-cap");
        let store = store(&dir);
        let session = store.start_session().expect("start");
        let guards: Vec<_> = (0..=MAX_LIVE_FLOWS)
            .map(|_| FlowGuard::begin(store.recorder()))
            .collect();
        assert!(!guards.last().expect("last guard").is_recording());
        store.stop_session(&session.session_id).expect("stop");
        let (session, flows) = store
            .read_flows(&session.session_id, 1000, 0)
            .expect("read");
        assert_eq!(flows.len(), MAX_LIVE_FLOWS);
        assert_eq!(session.recorded_flows, MAX_LIVE_FLOWS as u64);
        assert_eq!(session.dropped_flows, 1);
        drop(guards);
    }
}
