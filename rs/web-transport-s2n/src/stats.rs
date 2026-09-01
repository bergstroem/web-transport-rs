use std::time::Duration;

use s2n_quic::provider::event::{events, ConnectionInfo, ConnectionMeta, Subscriber};

/// Smoothed RTT and congestion window sampled from s2n-quic's
/// `recovery:metrics_updated` event, tracked per connection so
/// [`Session::stats`](crate::Session::stats) has something to read without
/// requiring the application to register its own event subscriber.
#[derive(Clone, Copy, Default)]
pub(crate) struct RecoveryContext {
    pub(crate) smoothed_rtt: Option<Duration>,
    pub(crate) congestion_window: Option<u32>,
}

/// Event subscriber installed on every endpoint this crate builds. Feeds
/// [`RecoveryContext`], which [`Session::stats`](crate::Session::stats) reads
/// back through `query_event_context`.
pub(crate) struct RecoverySubscriber;

impl Subscriber for RecoverySubscriber {
    type ConnectionContext = RecoveryContext;

    fn create_connection_context(
        &mut self,
        _meta: &ConnectionMeta,
        _info: &ConnectionInfo,
    ) -> Self::ConnectionContext {
        RecoveryContext::default()
    }

    fn on_recovery_metrics(
        &mut self,
        context: &mut Self::ConnectionContext,
        _meta: &ConnectionMeta,
        event: &events::RecoveryMetrics,
    ) {
        context.smoothed_rtt = Some(event.smoothed_rtt);
        context.congestion_window = Some(event.congestion_window);
    }
}

/// Connection-level statistics for a [`Session`](crate::Session).
///
/// Sourced from s2n-quic's recovery-metrics event rather than a pull-based
/// snapshot (s2n-quic has no `Connection::stats()` accessor); see
/// [`Session::query_event_context`](crate::Session::query_event_context) for
/// the general mechanism. Byte and packet counters are not tracked here and
/// fall back to the trait's `None` default.
pub struct SessionStats {
    pub(crate) rtt: Option<Duration>,
    pub(crate) congestion_window: Option<u32>,
}

impl web_transport_trait::Stats for SessionStats {
    fn rtt(&self) -> Option<Duration> {
        self.rtt
    }

    /// Estimated from the congestion window and smoothed RTT (`cwnd * 8 / rtt`),
    /// not a measured delivery rate.
    fn estimated_send_rate(&self) -> Option<u64> {
        let rtt_secs = self.rtt?.as_secs_f64();
        let cwnd = self.congestion_window?;
        (cwnd > 0 && rtt_secs > 0.0).then(|| (cwnd as f64 * 8.0 / rtt_secs) as u64)
    }
}
