//! Session pool for connection reuse with configurable cleanup

use crate::session::{Session, Stream};
use meow_common::atomic::{AtomicU, Uint};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, interval};
use tracing::{field, info_span};

/// Configuration for session pool
#[derive(Debug, Clone)]
pub struct SessionPoolConfig {
    /// Interval for checking idle sessions (default: 30s)
    pub check_interval: Duration,

    /// Idle timeout for sessions (default: 60s)
    pub idle_timeout: Duration,

    /// Minimum number of idle sessions to keep (default: 1)
    pub min_idle_sessions: usize,
}

impl Default for SessionPoolConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(60),
            min_idle_sessions: 1,
        }
    }
}

/// Pooled session with metadata
struct PooledSession {
    session: Arc<Session>,
    // None while exclusively checked out; Some marks the actual idle start.
    idle_since: Arc<std::sync::Mutex<Option<Instant>>>,
    /// Pool generation the session was dialled under (see
    /// [`SessionPool::reset`]).
    generation: Uint,
}

/// Exclusive use of a registered session. Dropping a cancelled dial returns it;
/// a successful dial transfers that responsibility to the stream's close hook.
/// The pool retains all sessions, including checked-out ones, for reset/reaping.
pub struct SessionLease {
    pub session: Arc<Session>,
    idle_since: Option<Arc<std::sync::Mutex<Option<Instant>>>>,
}

impl SessionLease {
    pub(crate) fn attach_to_stream(mut self, stream: &Stream) {
        let idle_since = self.idle_since.take().expect("lease owns its idle state");
        // Capture only the idle state: retaining the session/pool here would
        // create an Arc cycle through Session -> Stream -> close hook.
        stream.set_close_hook(Box::new(move || {
            *idle_since.lock().unwrap() = Some(Instant::now());
        }));
    }
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        if let Some(idle_since) = self.idle_since.take() {
            *idle_since.lock().unwrap() = Some(Instant::now());
        }
    }
}

/// Owns all sessions and checks out idle ones for sequential reuse.
pub struct SessionPool {
    // All sessions registered by sequence, including exclusive active leases.
    sessions: Arc<RwLock<BTreeMap<u64, PooledSession>>>,

    // Sequence counter (monotonically increasing)
    next_seq: Arc<AtomicU>,

    // Configuration
    config: SessionPoolConfig,

    // Cleanup task handle
    cleanup_task: Arc<Mutex<Option<JoinHandle<()>>>>,

    // Bumped by `reset`; sessions from an older generation are never handed
    // out again. Compared for equality only, so the MIPS32 wrap is harmless.
    generation: Arc<AtomicU>,
}

impl Default for SessionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionPool {
    /// Create a new session pool with default configuration
    pub fn new() -> Self {
        Self::with_config(SessionPoolConfig::default())
    }

    /// Create a new session pool with custom configuration
    pub fn with_config(config: SessionPoolConfig) -> Self {
        let pool = Self {
            sessions: Arc::new(RwLock::new(BTreeMap::new())),
            next_seq: Arc::new(AtomicU::new(1)),
            config,
            cleanup_task: Arc::new(Mutex::new(None)),
            generation: Arc::new(AtomicU::new(0)),
        };

        // Start automatic cleanup task
        pool.start_cleanup_task();

        pool
    }

    /// Get the next sequence number
    pub fn next_seq(&self) -> u64 {
        // `AtomicU` is 32-bit on targets without 64-bit atomics (MIPS32); the
        // public sequence stays u64 and simply wraps sooner there.
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; widens u32 on targets without 64-bit atomics"
        )]
        self.next_seq.fetch_add(1, Ordering::Relaxed).into()
    }

    /// Current pool generation. Capture it before dialling a session and hand
    /// it to [`add_idle_session_from`](Self::add_idle_session_from) so a
    /// session whose dial straddles a [`reset`](Self::reset) is never pooled.
    pub fn generation(&self) -> Uint {
        self.generation.load(Ordering::SeqCst)
    }

    /// Close every pooled session — streams still on them fail with
    /// `SessionClosed` — so the next stream dials a fresh connection. Called
    /// when the host's outbound-interface binding changes (meow-rs issue
    /// #695): a session's socket dialled before the binding stays unbound.
    ///
    /// Non-blocking: stale sessions stop being handed out at once, and the
    /// close itself (async) runs on a spawned task. Pooled sessions keep
    /// themselves alive through their own tasks, so dropping them from the
    /// map without `close` would leak their sockets.
    pub fn reset(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::warn!("[SessionPool] reset without a tokio runtime; sessions stay pooled");
            return;
        };
        let sessions_registry = Arc::clone(&self.sessions);
        let generation = Arc::clone(&self.generation);
        runtime.spawn(async move {
            let stale: Vec<PooledSession> = {
                let mut sessions = sessions_registry.write().await;
                let current = generation.load(Ordering::SeqCst);
                let seqs: Vec<u64> = sessions
                    .iter()
                    .filter(|(_, pooled)| pooled.generation != current)
                    .map(|(seq, _)| *seq)
                    .collect();
                seqs.iter().filter_map(|seq| sessions.remove(seq)).collect()
            };
            tracing::debug!("[SessionPool] Reset: closing {} sessions", stale.len());
            for pooled in stale {
                if let Err(e) = pooled.session.close().await {
                    tracing::debug!("[SessionPool] Failed to close reset session: {}", e);
                }
            }
        });
    }

    /// Exclusively check out the newest idle session. Active sessions stay
    /// registered for reset/cleanup but are never shared by concurrent dials.
    /// AnyTLS reuses sessions sequentially; it has no per-stream flow control.
    pub async fn get_idle_session(&self) -> Option<SessionLease> {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, pooled| !pooled.session.is_closed());
        let generation = self.generation();
        for pooled in sessions.values().rev() {
            if pooled.generation != generation {
                continue;
            }
            let mut idle = pooled.idle_since.lock().unwrap();
            if idle.take().is_some() {
                return Some(SessionLease {
                    session: Arc::clone(&pooled.session),
                    idle_since: Some(Arc::clone(&pooled.idle_since)),
                });
            }
        }
        None
    }

    /// Register a newly dialled session already checked out, atomically with
    /// respect to reset. It must not become visible as idle before its stream.
    pub(crate) async fn add_leased_session_from(
        &self,
        session: Arc<Session>,
        generation: Uint,
    ) -> Option<SessionLease> {
        let idle_since = Arc::new(std::sync::Mutex::new(None));
        let mut sessions = self.sessions.write().await;
        if generation != self.generation() || session.is_closed() {
            return None;
        }
        sessions.insert(
            session.seq(),
            PooledSession {
                session: Arc::clone(&session),
                idle_since: Arc::clone(&idle_since),
                generation,
            },
        );
        Some(SessionLease {
            session,
            idle_since: Some(idle_since),
        })
    }

    /// Add a session to the idle pool
    pub async fn add_idle_session(&self, session: Arc<Session>) {
        self.add_idle_session_from(session, self.generation()).await;
    }

    /// Add a session dialled under `generation` to the idle pool. Returns
    /// `false` (and does not pool it) if a [`reset`](Self::reset) has run
    /// since — the caller must close it.
    pub async fn add_idle_session_from(&self, session: Arc<Session>, generation: Uint) -> bool {
        if session.is_closed() {
            tracing::debug!("[SessionPool] Session already closed, skipping add to pool");
            return true;
        }
        let seq = session.seq();

        let pooled = PooledSession {
            session,
            idle_since: Arc::new(std::sync::Mutex::new(Some(Instant::now()))),
            generation,
        };

        let mut sessions = self.sessions.write().await;
        // Checked under the map lock the reset's drain takes, after the
        // bump: a stale session can never slip in behind the drain.
        if generation != self.generation() {
            return false;
        }
        sessions.insert(seq, pooled);

        tracing::debug!(
            "[SessionPool] ➕ Added session to pool (seq={}, total_idle={})",
            seq,
            sessions.len()
        );
        true
    }

    /// Get current number of idle sessions
    pub async fn idle_count(&self) -> usize {
        self.sessions
            .read()
            .await
            .values()
            .filter(|pooled| {
                !pooled.session.is_closed() && pooled.idle_since.lock().unwrap().is_some()
            })
            .count()
    }

    /// Clean up expired idle sessions
    pub async fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut sessions = self.sessions.write().await;

        if sessions.is_empty() {
            return;
        }

        let initial_count = sessions.len();
        let cleanup_span = info_span!(
            "anytls.session_pool.cleanup",
            idle_initial = initial_count as u64,
            removed = field::Empty,
            remaining = field::Empty
        );
        // Record-only span — an Entered guard held across the awaits below
        // would leak this span onto unrelated tasks on this worker thread.
        let mut to_remove = Vec::new();
        let mut active_count = 0;

        // Iterate from oldest to newest (ascending seq order)
        for (seq, pooled) in sessions.iter() {
            if pooled.session.is_closed() {
                to_remove.push(*seq);
                continue;
            }

            let Some(idle_since) = *pooled.idle_since.lock().unwrap() else {
                continue;
            };
            let idle_duration = now.saturating_duration_since(idle_since);

            // Keep sessions that haven't expired
            if idle_duration < self.config.idle_timeout {
                active_count += 1;
                continue;
            }

            // Keep at least min_idle_sessions
            if active_count < self.config.min_idle_sessions {
                active_count += 1;
                tracing::trace!(
                    "[SessionPool] Keeping expired session (seq={}) to maintain min_idle={}",
                    seq,
                    self.config.min_idle_sessions
                );
                continue;
            }

            // Mark for removal
            tracing::debug!(
                "[SessionPool] 🗑️ Marking session for cleanup (seq={}, idle_for={:.1}s)",
                seq,
                idle_duration.as_secs_f64()
            );
            to_remove.push(*seq);
        }

        // Remove expired sessions
        for seq in &to_remove {
            if let Some(pooled) = sessions.remove(seq) {
                // Close the session
                if let Err(e) = pooled.session.close().await {
                    tracing::warn!("[SessionPool] Failed to close session {}: {}", seq, e);
                }
            }
        }

        let removed = to_remove.len();
        if removed > 0 {
            tracing::debug!(
                "[SessionPool] Cleaned up {} expired sessions ({} -> {} idle)",
                removed,
                initial_count,
                sessions.len()
            );
        }
        cleanup_span.record("removed", removed as u64);
        cleanup_span.record("remaining", sessions.len() as u64);
    }

    /// Start automatic cleanup task
    fn start_cleanup_task(&self) {
        let sessions_registry = Arc::clone(&self.sessions);
        let check_interval = self.config.check_interval;
        let idle_timeout = self.config.idle_timeout;
        let min_idle = self.config.min_idle_sessions;
        let cleanup_task_handle = Arc::clone(&self.cleanup_task);

        let handle = tokio::spawn(async move {
            let mut interval_timer = interval(check_interval);

            tracing::debug!(
                "[SessionPool] Cleanup task started (interval={:?}, timeout={:?}, min_idle={})",
                check_interval,
                idle_timeout,
                min_idle
            );

            loop {
                interval_timer.tick().await;

                // Perform cleanup
                let now = Instant::now();
                let mut sessions = sessions_registry.write().await;

                if sessions.is_empty() {
                    continue;
                }

                let mut to_remove = Vec::new();
                let mut active_count = 0;

                for (seq, pooled) in sessions.iter() {
                    if pooled.session.is_closed() {
                        to_remove.push(*seq);
                        continue;
                    }

                    let Some(idle_since) = *pooled.idle_since.lock().unwrap() else {
                        continue;
                    };
                    let idle_duration = now.saturating_duration_since(idle_since);

                    if idle_duration < idle_timeout {
                        active_count += 1;
                        continue;
                    }

                    if active_count < min_idle {
                        active_count += 1;
                        continue;
                    }

                    to_remove.push(*seq);
                }

                if !to_remove.is_empty() {
                    for seq in &to_remove {
                        if let Some(pooled) = sessions.remove(seq)
                            && let Err(e) = pooled.session.close().await
                        {
                            tracing::warn!("[SessionPool] Failed to close session {}: {}", seq, e);
                        }
                    }

                    tracing::debug!(
                        "[SessionPool] Auto-cleanup: removed {} expired sessions",
                        to_remove.len()
                    );
                }
            }
        });

        // Store the handle
        if let Ok(mut task) = cleanup_task_handle.try_lock() {
            *task = Some(handle);
        };
    }

    /// Stop cleanup task (called on drop)
    pub async fn stop_cleanup_task(&self) {
        let mut task_guard = self.cleanup_task.lock().await;
        if let Some(handle) = task_guard.take() {
            handle.abort();
            tracing::debug!("[SessionPool] Cleanup task stopped");
        }
    }
}

impl Drop for SessionPool {
    fn drop(&mut self) {
        // Attempt to stop cleanup task
        // Note: This is best-effort since Drop is sync
        if let Ok(mut task) = self.cleanup_task.try_lock()
            && let Some(handle) = task.take()
        {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SessionPoolConfig::default();
        assert_eq!(config.check_interval, Duration::from_secs(30));
        assert_eq!(config.idle_timeout, Duration::from_secs(60));
        assert_eq!(config.min_idle_sessions, 1);
    }

    #[test]
    fn test_custom_config() {
        let config = SessionPoolConfig {
            check_interval: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            min_idle_sessions: 5,
        };

        assert_eq!(config.check_interval, Duration::from_secs(10));
        assert_eq!(config.idle_timeout, Duration::from_secs(30));
        assert_eq!(config.min_idle_sessions, 5);
    }

    #[tokio::test]
    async fn test_session_pool_creation() {
        let pool = SessionPool::new();
        assert_eq!(pool.idle_count().await, 0);
    }

    #[tokio::test]
    async fn test_next_seq() {
        let pool = SessionPool::new();
        let seq1 = pool.next_seq();
        let seq2 = pool.next_seq();
        let seq3 = pool.next_seq();

        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_eq!(seq3, 3);
    }

    #[tokio::test]
    async fn test_get_idle_session_empty() {
        let pool = SessionPool::new();
        let session = pool.get_idle_session().await;
        assert!(session.is_none());
    }

    fn test_session(seq: u64) -> Arc<Session> {
        let session = Arc::new(Session::new_client(
            tokio::io::empty(),
            tokio::io::sink(),
            crate::padding::PaddingFactory::default().into_shared(),
            None,
        ));
        session.set_seq(seq);
        session
    }

    #[tokio::test]
    async fn checked_out_session_is_unavailable_to_concurrent_dials() {
        let pool = SessionPool::new();
        pool.add_idle_session(test_session(1)).await;
        let first = pool.get_idle_session().await.unwrap();
        assert!(
            pool.get_idle_session().await.is_none(),
            "an active session is not idle"
        );
        drop(first);
        assert!(
            pool.get_idle_session().await.is_some(),
            "a released session is reusable"
        );
    }

    fn test_stream() -> Stream {
        let (writer, _rx) = crate::session::writer::StreamWriter::channel();
        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
        Stream::new(1, crate::session::StreamReader::new(1, rx), writer).0
    }

    #[tokio::test]
    async fn stream_close_returns_lease_once_even_when_close_precedes_attachment() {
        for peer_closed in [false, true] {
            let pool = SessionPool::new();
            let session = test_session(1);
            let lease = pool
                .add_leased_session_from(session, pool.generation())
                .await
                .unwrap();
            assert!(pool.get_idle_session().await.is_none());
            let stream = test_stream();
            if peer_closed {
                stream.close_with_error(crate::util::AnyTlsError::StreamClosed);
            }
            lease.attach_to_stream(&stream);
            if !peer_closed {
                assert!(pool.get_idle_session().await.is_none());
                stream.close();
            }
            let next = pool.get_idle_session().await.unwrap();
            // Old-stream teardown must not return a session checked out anew.
            stream.close();
            assert!(pool.get_idle_session().await.is_none());
            drop(next);
            assert_eq!(pool.idle_count().await, 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cleanup_counts_only_idle_sessions_and_starts_timeout_on_return() {
        let pool = SessionPool::with_config(SessionPoolConfig {
            check_interval: Duration::from_secs(3600),
            idle_timeout: Duration::from_secs(60),
            min_idle_sessions: 0,
        });
        pool.stop_cleanup_task().await;
        let session = test_session(1);
        let lease = pool
            .add_leased_session_from(Arc::clone(&session), pool.generation())
            .await
            .unwrap();
        tokio::time::advance(Duration::from_secs(120)).await;
        pool.cleanup_expired().await;
        assert!(!session.is_closed(), "an active lease is not reaped");
        drop(lease);
        pool.cleanup_expired().await;
        assert!(!session.is_closed(), "idle timeout starts on return");
        tokio::time::advance(Duration::from_secs(61)).await;
        pool.cleanup_expired().await;
        assert!(session.is_closed(), "returned sessions remain managed");
    }

    /// meow-rs issue #695: a reset stops handing out pooled sessions at once,
    /// closes them (they keep themselves alive otherwise), refuses a session
    /// dialled across it, and pools post-reset sessions normally.
    #[tokio::test]
    async fn reset_closes_pooled_sessions_and_refuses_straddling_ones() {
        let pool = SessionPool::new();
        let pooled = test_session(1);
        pool.add_idle_session(Arc::clone(&pooled)).await;
        let checked_out = pool.get_idle_session().await.unwrap();
        let dialled_at = pool.generation();

        pool.reset();
        assert!(
            pool.get_idle_session().await.is_none(),
            "a pre-reset session is never handed out again"
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while !pooled.is_closed() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the reset closes the pooled session");
        assert_eq!(pool.idle_count().await, 0);
        drop(checked_out);
        assert!(
            pool.get_idle_session().await.is_none(),
            "reset also owns active leases"
        );

        let straddling = test_session(2);
        assert!(
            !pool
                .add_idle_session_from(Arc::clone(&straddling), dialled_at)
                .await,
            "a session dialled before the reset is refused"
        );
        assert_eq!(pool.idle_count().await, 0);

        let fresh = test_session(3);
        pool.add_idle_session(Arc::clone(&fresh)).await;
        let reused = pool
            .get_idle_session()
            .await
            .expect("post-reset session pooled");
        assert!(Arc::ptr_eq(&reused.session, &fresh));
    }
}
