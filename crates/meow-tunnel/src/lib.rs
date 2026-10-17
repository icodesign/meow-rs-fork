//! Core routing engine for the meow-rs proxy kernel.
//!
//! TCP/UDP relay, rule-matching dispatch, and connection statistics.
//! [`Tunnel`] is the shared engine listeners hand connections to.

pub mod health_check;
pub mod match_engine;
pub mod relay;
pub mod rule_ir;
pub mod statistics;
pub mod tcp;
#[cfg(feature = "trace")]
pub mod trace;
pub mod tunnel;
pub mod udp;

pub use health_check::HealthCheckSupervisor;

/// No-op stand-ins for the `trace` module.
///
/// The instrumentation in `tcp.rs` / `tunnel.rs` calls the same names either
/// way, so those call sites stay free of `#[cfg]` noise. Every method here is
/// an empty inline function over a zero-sized guard, so the whole thing
/// compiles away — including [`trace::FlowGuard::now`], which skips the clock read
/// rather than returning an unused `Instant`.
#[cfg(not(feature = "trace"))]
pub mod trace {
    use meow_common::Metadata;
    use std::sync::Arc;
    use std::time::Instant;

    /// Placeholder for the recorder handle. Never constructed — without the
    /// feature [`crate::TunnelInner::trace_recorder`] always returns `None`.
    pub struct TraceRecorder(());

    /// Zero-sized no-op guard.
    pub struct FlowGuard;

    impl FlowGuard {
        #[must_use]
        #[inline]
        pub fn disabled() -> Self {
            Self
        }

        #[must_use]
        #[inline]
        pub fn begin(_recorder: Option<Arc<TraceRecorder>>) -> Self {
            Self
        }

        #[must_use]
        #[inline]
        pub fn is_recording(&self) -> bool {
            false
        }

        #[must_use]
        #[inline]
        pub fn now(&self) -> Option<Instant> {
            None
        }

        #[inline]
        pub fn stage<F>(&self, _name: &str, _started: Option<Instant>, _detail: F)
        where
            F: FnOnce() -> Option<String>,
        {
        }

        #[inline]
        pub fn observe(&self, _metadata: &Metadata) {}

        #[inline]
        pub fn start_stage(&self, _name: &str) {}

        #[inline]
        pub fn capture_request(&self, _bytes: &[u8]) {}

        #[inline]
        pub fn add_traffic(&self, _upload: usize, _download: usize) {}

        #[inline]
        pub fn set_resolved_ip(&self, _ip: &std::net::IpAddr) {}

        #[inline]
        pub fn set_outbound(&self, _name: &str) {}

        #[inline]
        pub fn attach_counters(&self, _counters: &Arc<crate::statistics::ConnCounters>) {}

        #[inline]
        pub fn succeed(&self) {}

        #[inline]
        pub fn fail(&self, _error: &dyn std::fmt::Display) {}
    }
}

pub use relay::{copy_bidirectional_buf, copy_bidirectional_buf_tracked, RELAY_BUF_SIZE};
pub use statistics::Statistics;
pub use tcp::{route_inbound_tcp, ConnectionGuard};
pub use tunnel::{
    OutboundFlush, PreHandleVerdict, ResolvedTarget, TrackedTcp, TunHandle, Tunnel, TunnelInner,
};
pub use udp::UdpFlushWatch;
