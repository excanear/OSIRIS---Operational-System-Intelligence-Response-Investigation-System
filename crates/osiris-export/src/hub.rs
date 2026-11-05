//! Export hub (spec §5.4–§5.6): one bounded queue and one worker task per
//! exporter, plus an optional tenant host-set cache.
//!
//! Ingest calls [`ExportHub::offer`], which is synchronous: it filters, wraps
//! each kept record in an `Arc` once and `try_send`s it into every accepting
//! exporter's queue. A full queue drops and counts; `offer` never awaits and
//! never touches a lock a worker holds across I/O (the worker keeps its
//! counters in atomics and its health behind a short `std::sync::Mutex`).
//!
//! Each worker batches up to `batch_max` records or `flush_interval`, calls
//! `export` in its own task (so a panic is caught by the join and counted),
//! retries `Transient` errors with jittered exponential backoff, and on
//! cancellation makes one final attempt at what it holds plus what is queued,
//! within the 5 s shutdown budget.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use osiris_schema::{Alert, CanonicalEvent};
use osiris_tenancy::TenantStore;
use rand::Rng;
use serde::Serialize;
use tokio::sync::{mpsc, watch};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::{sleep, sleep_until, timeout_at, Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::config::{ExporterConfig, Filter, KindConfig};
use crate::error::ExportError;
use crate::exporter::Exporter;
use crate::record::ExportRecord;

/// How long workers get to flush on shutdown (spec §5.2).
const SHUTDOWN_FLUSH: Duration = Duration::from_secs(5);
/// A worker stops this much before the 5 s budget so it can count what it
/// could not flush before `shutdown()` aborts it.
const SHUTDOWN_MARGIN: Duration = Duration::from_millis(50);
/// Upper bound on one `hosts_of` call; on timeout the previous set is kept.
const TENANT_LOAD_TIMEOUT: Duration = Duration::from_secs(5);
/// Tenant host-set refresh period (spec §5.5).
const TENANT_REFRESH: Duration = Duration::from_secs(10);
/// At most one drop warning per exporter per this period.
const WARN_EVERY: Duration = Duration::from_secs(60);
const BACKOFF_BASE: Duration = Duration::from_millis(500);
const BACKOFF_CAP: Duration = Duration::from_secs(30);

type Rec = Arc<ExportRecord>;

/// Runtime settings of one exporter worker, derived from its config.
#[derive(Debug, Clone)]
pub struct WorkerSettings {
    pub name: String,
    pub kind: &'static str,
    pub filter: Filter,
    pub tenant_id: Option<Uuid>,
    pub queue_capacity: usize,
    pub batch_max: usize,
    pub flush_interval: Duration,
    pub max_retries: u32,
}

impl WorkerSettings {
    pub fn from_config(cfg: &ExporterConfig) -> WorkerSettings {
        let kind = match cfg.kind {
            KindConfig::File(_) => "file",
            KindConfig::Syslog(_) => "syslog",
            KindConfig::Otlp(_) => "otlp",
            KindConfig::Webhook(_) => "webhook",
        };
        WorkerSettings {
            name: cfg.name.clone(),
            kind,
            filter: Filter::from_config(&cfg.common),
            tenant_id: cfg.common.tenant_id,
            queue_capacity: cfg.common.queue_capacity,
            batch_max: cfg.common.batch_max,
            flush_interval: Duration::from_millis(cfg.common.flush_interval_ms),
            max_retries: cfg.common.max_retries,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExporterState {
    Ok,
    Degraded,
    Stopped,
}

/// One row of `GET /api/v1/exporters` (spec §5.6).
#[derive(Debug, Clone, Serialize)]
pub struct ExporterStatus {
    pub name: String,
    pub kind: &'static str,
    pub state: ExporterState,
    pub queued: u64,
    pub sent_records: u64,
    pub sent_batches: u64,
    pub send_errors: u64,
    pub dropped_queue_full: u64,
    pub dropped_after_retries: u64,
    pub dropped_permanent: u64,
    pub truncated: u64,
    pub panics: u64,
    /// Unix nanoseconds of the last successful batch.
    pub last_success_at: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Default)]
struct Counters {
    sent_records: AtomicU64,
    sent_batches: AtomicU64,
    send_errors: AtomicU64,
    dropped_queue_full: AtomicU64,
    dropped_after_retries: AtomicU64,
    dropped_permanent: AtomicU64,
    truncated: AtomicU64,
    panics: AtomicU64,
}

fn add(c: &AtomicU64, n: u64) {
    c.fetch_add(n, Ordering::Relaxed);
}

fn get(c: &AtomicU64) -> u64 {
    c.load(Ordering::Relaxed)
}

struct Health {
    state: ExporterState,
    last_success_at: Option<u64>,
    last_error: Option<String>,
}

/// State shared by `offer`, the worker and `status`. Never locked across I/O.
struct Shared {
    name: String,
    kind: &'static str,
    c: Counters,
    /// Records the worker holds or has in flight, not yet counted anywhere.
    /// Read by `shutdown()` if it has to abort the worker.
    in_hand: AtomicU64,
    health: Mutex<Health>,
    last_warn: Mutex<Option<std::time::Instant>>,
}

impl Shared {
    fn health(&self) -> std::sync::MutexGuard<'_, Health> {
        self.health.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn succeeded(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mut h = self.health();
        if h.state != ExporterState::Stopped {
            h.state = ExporterState::Ok;
        }
        h.last_success_at = Some(now);
    }

    fn failed(&self, message: String) {
        let mut h = self.health();
        if h.state != ExporterState::Stopped {
            h.state = ExporterState::Degraded;
        }
        h.last_error = Some(message);
    }

    fn set_stopped(&self) {
        self.health().state = ExporterState::Stopped;
    }

    /// Rate-limited drop warning carrying the running counters.
    fn warn_drops(&self) {
        {
            let mut last = self.last_warn.lock().unwrap_or_else(|p| p.into_inner());
            let now = std::time::Instant::now();
            if last.is_some_and(|t| now.duration_since(t) < WARN_EVERY) {
                return;
            }
            *last = Some(now);
        }
        tracing::warn!(
            exporter = %self.name,
            dropped_queue_full = get(&self.c.dropped_queue_full),
            dropped_after_retries = get(&self.c.dropped_after_retries),
            dropped_permanent = get(&self.c.dropped_permanent),
            panics = get(&self.c.panics),
            "exporter is dropping records"
        );
    }
}

struct WorkerHandle {
    filter: Filter,
    tenant_id: Option<Uuid>,
    tx: mpsc::Sender<Rec>,
    shared: Arc<Shared>,
}

impl WorkerHandle {
    /// Returns `true` if the record was dropped (and counted).
    fn push(&self, rec: Rec) -> bool {
        // `Closed` only happens after shutdown; still counted, never silent.
        if self.tx.try_send(rec).is_err() {
            add(&self.shared.c.dropped_queue_full, 1);
            return true;
        }
        false
    }

    fn depth(&self) -> u64 {
        (self.tx.max_capacity() - self.tx.capacity()) as u64
    }
}

/// Tenant id → host set, refreshed every [`TENANT_REFRESH`]. A tenant that has
/// not been loaded yet has no entry, so nothing from it is exported.
struct TenantCache {
    sets: RwLock<HashMap<Uuid, HashSet<Uuid>>>,
    /// Completed refresh rounds (successful or not); lets tests synchronise.
    rounds: watch::Sender<u64>,
}

impl TenantCache {
    fn new() -> Self {
        Self {
            sets: RwLock::new(HashMap::new()),
            rounds: watch::channel(0).0,
        }
    }
}

/// Fan-out point between ingest and the exporter workers.
pub struct ExportHub {
    workers: Vec<WorkerHandle>,
    tenants: Arc<TenantCache>,
    /// Any worker tenant-scoped? If not, `offer` skips the tenant lock.
    any_tenant: bool,
    cancel: CancellationToken,
    /// Worker tasks in `workers` order, then the refresher (if any).
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl ExportHub {
    /// Spawns one worker per exporter, and the tenant refresher if any worker
    /// is tenant-scoped. Must be called inside a tokio runtime.
    pub fn start(
        exporters: Vec<(WorkerSettings, Arc<dyn Exporter>)>,
        tenants: Option<Arc<dyn TenantStore>>,
        cancel: CancellationToken,
    ) -> Arc<ExportHub> {
        let cache = Arc::new(TenantCache::new());
        let mut workers = Vec::with_capacity(exporters.len());
        let mut tasks = Vec::with_capacity(exporters.len() + 1);
        let mut tenant_ids: Vec<Uuid> = Vec::new();

        for (s, exporter) in exporters {
            let (tx, rx) = mpsc::channel(s.queue_capacity.max(1));
            let shared = Arc::new(Shared {
                name: s.name.clone(),
                kind: s.kind,
                c: Counters::default(),
                in_hand: AtomicU64::new(0),
                health: Mutex::new(Health {
                    state: ExporterState::Ok,
                    last_success_at: None,
                    last_error: None,
                }),
                last_warn: Mutex::new(None),
            });
            if let Some(t) = s.tenant_id {
                if !tenant_ids.contains(&t) {
                    tenant_ids.push(t);
                }
            }
            let worker = Worker {
                shared: shared.clone(),
                exporter,
                batch_max: s.batch_max.max(1),
                flush_interval: s.flush_interval,
                max_retries: s.max_retries,
                cancel: cancel.clone(),
                stop_at: OnceLock::new(),
            };
            tasks.push(tokio::spawn(worker.run(rx)));
            workers.push(WorkerHandle {
                filter: s.filter,
                tenant_id: s.tenant_id,
                tx,
                shared,
            });
        }

        let any_tenant = !tenant_ids.is_empty();
        if any_tenant {
            match tenants {
                Some(store) => tasks.push(tokio::spawn(run_refresher(
                    store,
                    cache.clone(),
                    tenant_ids,
                    cancel.clone(),
                ))),
                None => tracing::error!(
                    "tenant-scoped exporters configured without a tenant store; \
                     they will export nothing"
                ),
            }
        }

        Arc::new(ExportHub {
            workers,
            tenants: cache,
            any_tenant,
            cancel,
            tasks: Mutex::new(tasks),
        })
    }

    /// Non-blocking enqueue of the kept events and alerts of one ingest batch.
    pub fn offer(&self, events: &[CanonicalEvent], alerts: &[Alert]) {
        if self.workers.is_empty() {
            return;
        }
        // Indices of workers that dropped something; warned after the tenant
        // guard is released. Allocates only when a drop happens.
        let mut dropped: Vec<usize> = Vec::new();
        {
            let sets = self
                .any_tenant
                .then(|| self.tenants.sets.read().unwrap_or_else(|p| p.into_inner()));
            let allowed = |w: &WorkerHandle, host: Uuid| match (w.tenant_id, &sets) {
                (None, _) => true,
                (Some(t), Some(sets)) => sets.get(&t).is_some_and(|hosts| hosts.contains(&host)),
                (Some(_), None) => false,
            };
            let mut push = |i: usize, w: &WorkerHandle, r: &Rec| {
                if w.push(r.clone()) && !dropped.contains(&i) {
                    dropped.push(i);
                }
            };
            for e in events {
                let mut rec: Option<Rec> = None;
                for (i, w) in self.workers.iter().enumerate() {
                    if w.filter.accepts_event(e) && allowed(w, e.host_id) {
                        let r = rec.get_or_insert_with(|| Arc::new(ExportRecord::Event(e.clone())));
                        push(i, w, r);
                    }
                }
            }
            for a in alerts {
                let mut rec: Option<Rec> = None;
                for (i, w) in self.workers.iter().enumerate() {
                    if w.filter.accepts_alert(a) && allowed(w, a.host_id()) {
                        let r = rec.get_or_insert_with(|| Arc::new(ExportRecord::Alert(a.clone())));
                        push(i, w, r);
                    }
                }
            }
        }
        for i in dropped {
            self.workers[i].shared.warn_drops();
        }
    }

    pub fn status(&self) -> Vec<ExporterStatus> {
        self.workers
            .iter()
            .map(|w| {
                let c = &w.shared.c;
                let h = w.shared.health();
                ExporterStatus {
                    name: w.shared.name.clone(),
                    kind: w.shared.kind,
                    state: h.state,
                    queued: w.depth(),
                    sent_records: get(&c.sent_records),
                    sent_batches: get(&c.sent_batches),
                    send_errors: get(&c.send_errors),
                    dropped_queue_full: get(&c.dropped_queue_full),
                    dropped_after_retries: get(&c.dropped_after_retries),
                    dropped_permanent: get(&c.dropped_permanent),
                    truncated: get(&c.truncated),
                    panics: get(&c.panics),
                    last_success_at: h.last_success_at,
                    last_error: h.last_error.clone(),
                }
            })
            .collect()
    }

    /// Cancels (idempotent) and waits up to 5 s in total for the workers to
    /// flush; whatever is still running then is aborted. Workers stop and
    /// count their own losses just before the deadline; for a worker that
    /// still has to be aborted, its queue depth and in-hand records are
    /// counted here as `dropped_after_retries`. All exporters end `STOPPED`.
    pub async fn shutdown(&self) {
        self.cancel.cancel();
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap_or_else(|p| p.into_inner()));
        let aborts: Vec<AbortHandle> = tasks.iter().map(JoinHandle::abort_handle).collect();
        let deadline = Instant::now() + SHUTDOWN_FLUSH;
        let joined = timeout_at(deadline, async {
            for t in tasks {
                let _ = t.await;
            }
        })
        .await;
        if joined.is_err() {
            tracing::warn!("exporters did not flush within 5 s; aborting");
            for (i, a) in aborts.iter().enumerate() {
                if a.is_finished() {
                    continue;
                }
                a.abort();
                if let Some(w) = self.workers.get(i) {
                    let lost = w.depth() + w.shared.in_hand.swap(0, Ordering::Relaxed);
                    if lost > 0 {
                        add(&w.shared.c.dropped_after_retries, lost);
                        w.shared.warn_drops();
                    }
                }
            }
        }
        for w in &self.workers {
            w.shared.set_stopped();
        }
    }

    #[cfg(test)]
    fn refresh_rounds(&self) -> watch::Receiver<u64> {
        self.tenants.rounds.subscribe()
    }
}

/// Reloads every tenant's host set every [`TENANT_REFRESH`]. The blocking
/// store call runs on the blocking pool; the write lock is held only for the
/// insert. On error the previous set (or none) is kept.
async fn run_refresher(
    store: Arc<dyn TenantStore>,
    cache: Arc<TenantCache>,
    tenant_ids: Vec<Uuid>,
    cancel: CancellationToken,
) {
    let mut tick = tokio::time::interval(TENANT_REFRESH);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = tick.tick() => {}
        }
        for &tenant in &tenant_ids {
            let s = store.clone();
            let load = tokio::task::spawn_blocking(move || s.hosts_of(tenant));
            // A hung store must not stall shutdown or later rounds; the
            // blocking call itself cannot be cancelled and is left to finish.
            let result = tokio::select! {
                biased;
                _ = cancel.cancelled() => return,
                r = tokio::time::timeout(TENANT_LOAD_TIMEOUT, load) => r,
            };
            match result {
                Ok(Ok(Ok(hosts))) => {
                    // The replaced set is dropped after the guard is released.
                    let _old = cache
                        .sets
                        .write()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(tenant, hosts);
                }
                Ok(Ok(Err(e))) => tracing::error!(
                    tenant_id = %tenant,
                    error = %e,
                    "exporter tenant host-set refresh failed; keeping the previous set"
                ),
                Ok(Err(e)) => tracing::error!(
                    tenant_id = %tenant,
                    error = %e,
                    "exporter tenant host-set refresh task failed; keeping the previous set"
                ),
                Err(_) => tracing::error!(
                    tenant_id = %tenant,
                    "exporter tenant host-set refresh timed out; keeping the previous set"
                ),
            }
        }
        cache.rounds.send_modify(|n| *n += 1);
    }
}

/// `0.5 s × 2^attempt`, capped at 30 s, ±20 % jitter.
fn backoff(attempt: u32) -> Duration {
    let base = BACKOFF_BASE
        .saturating_mul(2u32.saturating_pow(attempt.min(16)))
        .min(BACKOFF_CAP);
    base.mul_f64(rand::thread_rng().gen_range(0.8..=1.2))
}

/// Aborts the export task if the worker is dropped (shutdown abort) while
/// awaiting it, so a hung exporter does not outlive the hub.
struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

enum Delivery {
    Done,
    /// Cancelled during a backoff sleep; the batch is handed back uncounted.
    Interrupted(Vec<Rec>),
    /// The shutdown deadline passed while the export was in flight; the
    /// export was aborted and these records are not counted yet.
    Expired(u64),
}

struct Worker {
    shared: Arc<Shared>,
    exporter: Arc<dyn Exporter>,
    batch_max: usize,
    flush_interval: Duration,
    max_retries: u32,
    cancel: CancellationToken,
    /// Fixed the first time this worker observes cancellation.
    stop_at: OnceLock<Instant>,
}

impl Worker {
    /// The worker's own shutdown deadline: 5 s (minus a margin, so it can
    /// count its losses before `shutdown()` aborts it) after it first saw
    /// cancellation.
    fn stop_at(&self) -> Instant {
        *self
            .stop_at
            .get_or_init(|| Instant::now() + SHUTDOWN_FLUSH - SHUTDOWN_MARGIN)
    }

    /// Resolves once cancellation has fired and the stop deadline has passed.
    async fn expired(&self) {
        self.cancel.cancelled().await;
        sleep_until(self.stop_at()).await;
    }

    fn set_in_hand(&self, n: usize) {
        self.shared.in_hand.store(n as u64, Ordering::Relaxed);
    }

    async fn run(self, mut rx: mpsc::Receiver<Rec>) {
        let mut held: Vec<Rec> = Vec::with_capacity(self.batch_max);
        let mut lost = 0u64;
        'run: loop {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => break 'run,
                r = rx.recv() => match r {
                    Some(r) => held.push(r),
                    None => break 'run,
                },
            }
            self.set_in_hand(held.len());
            let deadline = Instant::now() + self.flush_interval;
            while held.len() < self.batch_max {
                tokio::select! {
                    biased;
                    _ = self.cancel.cancelled() => break 'run,
                    r = rx.recv() => match r {
                        Some(r) => held.push(r),
                        None => break 'run,
                    },
                    _ = sleep_until(deadline) => break,
                }
                self.set_in_hand(held.len());
            }
            let batch = std::mem::replace(&mut held, Vec::with_capacity(self.batch_max));
            match self.deliver(batch, self.max_retries).await {
                Delivery::Done => self.set_in_hand(0),
                Delivery::Interrupted(b) => {
                    held = b;
                    break 'run;
                }
                Delivery::Expired(n) => {
                    lost = n;
                    break 'run;
                }
            }
            if self.cancel.is_cancelled() {
                break 'run;
            }
        }
        self.final_flush(held, lost, rx).await;
        self.shared.set_stopped();
    }

    /// One attempt at everything held plus everything queued, bounded by the
    /// same stop deadline. Whatever is not delivered in time (including
    /// `lost`, an export aborted in flight) is counted `dropped_after_retries`.
    async fn final_flush(&self, mut held: Vec<Rec>, lost: u64, mut rx: mpsc::Receiver<Rec>) {
        rx.close();
        while let Ok(r) = rx.try_recv() {
            held.push(r);
        }
        let mut remaining = lost + held.len() as u64;
        self.shared.in_hand.store(remaining, Ordering::Relaxed);
        let deadline = self.stop_at();
        if Instant::now() < deadline {
            let _ = timeout_at(deadline, async {
                for chunk in held.chunks(self.batch_max) {
                    match self.deliver(chunk.to_vec(), 0).await {
                        // Retries are 0, so `Interrupted` cannot happen.
                        Delivery::Done | Delivery::Interrupted(_) => {
                            remaining -= chunk.len() as u64;
                            self.shared.in_hand.store(remaining, Ordering::Relaxed);
                        }
                        Delivery::Expired(_) => break,
                    }
                }
            })
            .await;
        }
        if remaining > 0 {
            add(&self.shared.c.dropped_after_retries, remaining);
            self.shared
                .failed("shutdown flush did not finish within 5 s".into());
            self.shared.warn_drops();
        }
        self.shared.in_hand.store(0, Ordering::Relaxed);
    }

    async fn deliver(&self, mut batch: Vec<Rec>, max_retries: u32) -> Delivery {
        let c = &self.shared.c;
        let mut attempt = 0u32;
        loop {
            let len = batch.len() as u64;
            let exporter = self.exporter.clone();
            let mut task = tokio::spawn(async move {
                let r = exporter.export(&batch).await;
                (batch, r)
            });
            // Aborts the export if the deadline passes or the worker is aborted.
            let _guard = AbortOnDrop(task.abort_handle());
            let joined = tokio::select! {
                biased;
                j = &mut task => j,
                _ = self.expired() => return Delivery::Expired(len),
            };
            match joined {
                Err(join) => {
                    let what = if join.is_panic() {
                        add(&c.panics, 1);
                        "exporter panicked"
                    } else {
                        "exporter task was cancelled"
                    };
                    add(&c.dropped_permanent, len);
                    tracing::error!(exporter = %self.shared.name, "{what}; batch dropped");
                    self.shared.failed(what.into());
                    self.shared.warn_drops();
                    return Delivery::Done;
                }
                Ok((_, Ok(outcome))) => {
                    add(&c.sent_records, len.saturating_sub(outcome.dropped));
                    add(&c.dropped_permanent, outcome.dropped);
                    add(&c.truncated, outcome.truncated);
                    add(&c.sent_batches, 1);
                    self.shared.succeeded();
                    if outcome.dropped > 0 {
                        self.shared.warn_drops();
                    }
                    return Delivery::Done;
                }
                Ok((_, Err(ExportError::Permanent(msg)))) => {
                    add(&c.send_errors, 1);
                    add(&c.dropped_permanent, len);
                    self.shared.failed(msg);
                    self.shared.warn_drops();
                    return Delivery::Done;
                }
                Ok((b, Err(ExportError::Transient(msg)))) => {
                    add(&c.send_errors, 1);
                    self.shared.failed(msg);
                    if attempt >= max_retries {
                        add(&c.dropped_after_retries, len);
                        self.shared.warn_drops();
                        return Delivery::Done;
                    }
                    let wait = backoff(attempt);
                    attempt += 1;
                    tokio::select! {
                        biased;
                        _ = self.cancel.cancelled() => return Delivery::Interrupted(b),
                        _ = sleep(wait) => {}
                    }
                    batch = b;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use async_trait::async_trait;
    use osiris_schema::{Category, EventType, HostRef, Severity, Source, SCHEMA_VERSION};
    use osiris_tenancy::{Tenant, TenantStoreError};
    use tokio::sync::Notify;
    use tokio::time::Instant;

    use super::*;
    use crate::config::CommonOptions;
    use crate::error::ExportError;
    use crate::exporter::ExportOutcome;
    use crate::record::{ExportRecord, Stream};

    // ---------- fixtures ----------

    fn event(host_id: Uuid) -> CanonicalEvent {
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id,
            boot_id: "b".to_string(),
            timestamp: 1000,
            monotonic_timestamp: 1000,
            event_type: EventType::ProcessExec,
            category: Category::Process,
            severity: Severity::Info,
            host: HostRef {
                host_id,
                hostname: "h".to_string(),
                distro: "d".to_string(),
                kernel_version: "k".to_string(),
                cloud: None,
            },
            user: None,
            session: None,
            process: None,
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: None,
            device: None,
            service: None,
            container: None,
            namespace: None,
            cgroup: None,
            kernel: None,
            source: Source::Synthetic,
            provider: "test".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    fn alert(host_id: Uuid) -> Alert {
        Alert::new(
            "r1",
            1,
            "h",
            Severity::High,
            1,
            host_id,
            vec!["why".into()],
            vec![Uuid::new_v4()],
        )
        .unwrap()
    }

    fn events(n: usize) -> Vec<CanonicalEvent> {
        let h = Uuid::new_v4();
        (0..n).map(|_| event(h)).collect()
    }

    fn ids(evs: &[CanonicalEvent]) -> Vec<Uuid> {
        evs.iter().map(|e| e.event_id).collect()
    }

    fn common() -> CommonOptions {
        CommonOptions {
            streams: vec![Stream::Events, Stream::Alerts],
            min_severity: Severity::Info,
            event_types: None,
            tenant_id: None,
            include_raw: false,
            queue_capacity: 100,
            batch_max: 10,
            flush_interval_ms: 1000,
            max_retries: 5,
        }
    }

    fn settings(
        name: &str,
        batch_max: usize,
        queue_capacity: usize,
        flush_ms: u64,
        max_retries: u32,
    ) -> WorkerSettings {
        WorkerSettings {
            name: name.to_string(),
            kind: "file",
            filter: Filter::from_config(&common()),
            tenant_id: None,
            queue_capacity,
            batch_max,
            flush_interval: Duration::from_millis(flush_ms),
            max_retries,
        }
    }

    // ---------- fake exporter ----------

    #[derive(Clone)]
    enum Step {
        Ok(ExportOutcome),
        Transient,
        Permanent,
        Panic,
        /// Signal `entered`, then wait for `release`.
        Block,
        /// Sleep on tokio time, then succeed.
        Sleep(Duration),
    }

    struct FakeExporter {
        script: Mutex<VecDeque<Step>>,
        fallback: Step,
        delivered: Mutex<Vec<Vec<Uuid>>>,
        attempts: Mutex<Vec<Instant>>,
        entered: Notify,
        release: Notify,
    }

    impl FakeExporter {
        fn new(script: Vec<Step>, fallback: Step) -> Arc<Self> {
            Arc::new(Self {
                script: Mutex::new(script.into()),
                fallback,
                delivered: Mutex::new(vec![]),
                attempts: Mutex::new(vec![]),
                entered: Notify::new(),
                release: Notify::new(),
            })
        }
        fn ok() -> Arc<Self> {
            Self::new(vec![], Step::Ok(ExportOutcome::default()))
        }
        fn delivered(&self) -> Vec<Vec<Uuid>> {
            self.delivered.lock().unwrap().clone()
        }
        fn flat(&self) -> Vec<Uuid> {
            self.delivered().into_iter().flatten().collect()
        }
        fn attempts(&self) -> Vec<Instant> {
            self.attempts.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Exporter for FakeExporter {
        fn name(&self) -> &str {
            "fake"
        }
        async fn export(&self, batch: &[Arc<ExportRecord>]) -> Result<ExportOutcome, ExportError> {
            self.attempts.lock().unwrap().push(Instant::now());
            let step = self
                .script
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| self.fallback.clone());
            let outcome = match step {
                Step::Ok(o) => o,
                Step::Transient => return Err(ExportError::Transient("dest down".into())),
                Step::Permanent => return Err(ExportError::Permanent("rejected".into())),
                Step::Panic => panic!("formatter exploded"),
                Step::Block => {
                    self.entered.notify_one();
                    self.release.notified().await;
                    ExportOutcome::default()
                }
                Step::Sleep(d) => {
                    tokio::time::sleep(d).await;
                    ExportOutcome::default()
                }
            };
            self.delivered
                .lock()
                .unwrap()
                .push(batch.iter().map(|r| r.id()).collect());
            Ok(outcome)
        }
    }

    // ---------- fake tenant store ----------

    struct FakeTenants {
        sets: Mutex<HashMap<Uuid, HashSet<Uuid>>>,
        fail: AtomicBool,
        calls: AtomicUsize,
        /// When set, the first `hosts_of` call blocks until a message arrives.
        gate: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    impl FakeTenants {
        fn new(tenant: Uuid, hosts: &[Uuid]) -> Arc<Self> {
            let mut m = HashMap::new();
            m.insert(tenant, hosts.iter().copied().collect());
            Arc::new(Self {
                sets: Mutex::new(m),
                fail: AtomicBool::new(false),
                calls: AtomicUsize::new(0),
                gate: Mutex::new(None),
            })
        }
        fn set(&self, tenant: Uuid, hosts: &[Uuid]) {
            self.sets
                .lock()
                .unwrap()
                .insert(tenant, hosts.iter().copied().collect());
        }
    }

    impl TenantStore for FakeTenants {
        fn create_tenant(&self, _: &str) -> Result<Tenant, TenantStoreError> {
            unimplemented!()
        }
        fn list_tenants(&self) -> Result<Vec<Tenant>, TenantStoreError> {
            unimplemented!()
        }
        fn get_tenant(&self, _: Uuid) -> Result<Option<Tenant>, TenantStoreError> {
            unimplemented!()
        }
        fn assign_host(&self, _: Uuid, _: Uuid) -> Result<(), TenantStoreError> {
            unimplemented!()
        }
        fn unassign_host(&self, _: Uuid) -> Result<(), TenantStoreError> {
            unimplemented!()
        }
        fn hosts_of(&self, tenant_id: Uuid) -> Result<HashSet<Uuid>, TenantStoreError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let gate = self.gate.lock().unwrap().take();
            if let Some(gate) = gate {
                // Real-time bound so a broken test cannot hang forever.
                gate.recv_timeout(std::time::Duration::from_secs(10))
                    .expect("gate released");
            }
            if self.fail.load(Ordering::SeqCst) {
                return Err(TenantStoreError::Backend("db locked".into()));
            }
            Ok(self
                .sets
                .lock()
                .unwrap()
                .get(&tenant_id)
                .cloned()
                .unwrap_or_default())
        }
        fn tenant_of(&self, _: Uuid) -> Result<Option<Uuid>, TenantStoreError> {
            unimplemented!()
        }
    }

    // ---------- helpers ----------

    fn start_one(s: WorkerSettings, exp: Arc<FakeExporter>) -> (Arc<ExportHub>, CancellationToken) {
        let cancel = CancellationToken::new();
        let hub = ExportHub::start(vec![(s, exp as Arc<dyn Exporter>)], None, cancel.clone());
        (hub, cancel)
    }

    fn st(hub: &ExportHub) -> ExporterStatus {
        hub.status().into_iter().next().unwrap()
    }

    async fn wait_rounds(hub: &ExportHub, n: u64) {
        let mut rx = hub.refresh_rounds();
        rx.wait_for(|r| *r >= n).await.unwrap();
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    fn start_tenant(
        tenant: Uuid,
        store: Arc<FakeTenants>,
        exp: Arc<FakeExporter>,
    ) -> Arc<ExportHub> {
        let mut s = settings("t", 10, 100, 100, 5);
        s.tenant_id = Some(tenant);
        ExportHub::start(
            vec![(s, exp as Arc<dyn Exporter>)],
            Some(store as Arc<dyn TenantStore>),
            CancellationToken::new(),
        )
    }

    // ---------- tests ----------

    #[tokio::test(start_paused = true)]
    async fn delivers_records_in_order_in_batches_of_batch_max() {
        let exp = FakeExporter::ok();
        let (hub, _c) = start_one(settings("a", 3, 100, 1000, 5), exp.clone());
        let evs = events(7);
        hub.offer(&evs, &[]);
        settle().await;
        let lens: Vec<usize> = exp.delivered().iter().map(Vec::len).collect();
        assert_eq!(lens, vec![3, 3, 1]);
        assert_eq!(exp.flat(), ids(&evs));
        let s = st(&hub);
        assert_eq!(s.sent_records, 7);
        assert_eq!(s.sent_batches, 3);
        assert_eq!(s.state, ExporterState::Ok);
        assert!(s.last_success_at.is_some());
        assert_eq!(s.queued, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn flushes_a_partial_batch_after_flush_interval() {
        let exp = FakeExporter::ok();
        let (hub, _c) = start_one(settings("a", 100, 100, 1000, 5), exp.clone());
        let evs = events(2);
        hub.offer(&evs, &[]);
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert!(exp.delivered().is_empty(), "flushed before flush_interval");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(exp.delivered(), vec![ids(&evs)]);
    }

    #[tokio::test(start_paused = true)]
    async fn queue_overflow_is_counted_not_blocking() {
        let exp = FakeExporter::new(vec![Step::Block], Step::Ok(ExportOutcome::default()));
        let (hub, _c) = start_one(settings("a", 2, 4, 1000, 5), exp.clone());

        // `offer` is a plain sync fn: the worker has not run yet, so the
        // queue takes 4 and nothing is in flight (10 - 4 - 0 dropped).
        let first = events(10);
        hub.offer(&first, &[]);
        let s = st(&hub);
        assert_eq!(s.dropped_queue_full, 10 - 4);
        assert_eq!(s.queued, 4);

        // The worker takes one batch (2) and blocks inside export.
        exp.entered.notified().await;
        assert_eq!(st(&hub).queued, 2);

        // With the exporter stuck, offer still returns at once: 2 free slots,
        // so 1 of 3 is dropped.
        let second = events(3);
        hub.offer(&second, &[]);
        let s = st(&hub);
        assert_eq!(s.dropped_queue_full, 6 + 1);
        assert_eq!(s.queued, 4);

        exp.release.notify_one();
        settle().await;
        let mut expect = ids(&first)[..4].to_vec();
        expect.extend_from_slice(&ids(&second)[..2]);
        assert_eq!(exp.flat(), expect);
        assert_eq!(st(&hub).sent_records, 6);
    }

    #[tokio::test(start_paused = true)]
    async fn transient_errors_retry_with_backoff_then_drop() {
        let exp = FakeExporter::new(vec![], Step::Transient);
        let (hub, _c) = start_one(settings("a", 10, 100, 100, 2), exp.clone());
        hub.offer(&events(3), &[]);
        tokio::time::sleep(Duration::from_secs(10)).await;
        let at = exp.attempts();
        assert_eq!(at.len(), 3, "1 attempt + max_retries 2");
        let g1 = at[1] - at[0];
        let g2 = at[2] - at[1];
        assert!(
            g1 >= Duration::from_millis(400) && g1 <= Duration::from_millis(600),
            "{g1:?}"
        );
        assert!(
            g2 >= Duration::from_millis(800) && g2 <= Duration::from_millis(1200),
            "{g2:?}"
        );
        let s = st(&hub);
        assert_eq!(s.dropped_after_retries, 3);
        assert_eq!(s.send_errors, 3);
        assert_eq!(s.sent_records, 0);
        assert_eq!(s.state, ExporterState::Degraded);
        assert!(s.last_error.unwrap().contains("dest down"));
    }

    #[tokio::test(start_paused = true)]
    async fn permanent_error_drops_without_retry() {
        let exp = FakeExporter::new(vec![Step::Permanent], Step::Ok(ExportOutcome::default()));
        let (hub, _c) = start_one(settings("a", 10, 100, 100, 5), exp.clone());
        hub.offer(&events(2), &[]);
        settle().await;
        assert_eq!(exp.attempts().len(), 1);
        let s = st(&hub);
        assert_eq!(s.dropped_permanent, 2);
        assert_eq!(s.dropped_after_retries, 0);
        assert_eq!(s.state, ExporterState::Degraded);
        assert!(s.last_error.unwrap().contains("rejected"));

        // The worker keeps going.
        let next = events(1);
        hub.offer(&next, &[]);
        settle().await;
        assert_eq!(exp.flat(), ids(&next));
        assert_eq!(st(&hub).state, ExporterState::Ok);
    }

    #[tokio::test(start_paused = true)]
    async fn panic_in_export_is_contained() {
        let exp = FakeExporter::new(vec![Step::Panic], Step::Ok(ExportOutcome::default()));
        let (hub, _c) = start_one(settings("a", 1, 100, 100, 5), exp.clone());
        let evs = events(2);
        hub.offer(&evs, &[]);
        settle().await;
        let s = st(&hub);
        assert_eq!(s.panics, 1);
        assert_eq!(s.dropped_permanent, 1);
        assert_eq!(exp.delivered(), vec![vec![evs[1].event_id]]);
        assert_eq!(s.sent_records, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn outcome_dropped_and_truncated_are_counted() {
        let exp = FakeExporter::new(
            vec![Step::Ok(ExportOutcome {
                dropped: 1,
                truncated: 2,
            })],
            Step::Ok(ExportOutcome::default()),
        );
        let (hub, _c) = start_one(settings("a", 5, 100, 100, 5), exp.clone());
        hub.offer(&events(5), &[]);
        settle().await;
        let s = st(&hub);
        assert_eq!(s.sent_records, 4);
        assert_eq!(s.dropped_permanent, 1);
        assert_eq!(s.truncated, 2);
        assert_eq!(s.sent_batches, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn filter_is_applied_per_exporter() {
        let all = FakeExporter::ok();
        let alerts_only = FakeExporter::ok();
        let mut sa = settings("alerts", 10, 100, 100, 5);
        let mut c = common();
        c.streams = vec![Stream::Alerts];
        sa.filter = Filter::from_config(&c);
        let hub = ExportHub::start(
            vec![
                (
                    settings("all", 10, 100, 100, 5),
                    all.clone() as Arc<dyn Exporter>,
                ),
                (sa, alerts_only.clone() as Arc<dyn Exporter>),
            ],
            None,
            CancellationToken::new(),
        );
        let h = Uuid::new_v4();
        let evs = vec![event(h), event(h)];
        let al = alert(h);
        hub.offer(&evs, std::slice::from_ref(&al));
        settle().await;
        assert_eq!(all.flat().len(), 3);
        assert_eq!(alerts_only.flat(), vec![al.alert_id()]);
        let names: Vec<String> = hub.status().into_iter().map(|s| s.name).collect();
        assert_eq!(names, vec!["all", "alerts"]);
    }

    #[tokio::test(start_paused = true)]
    async fn tenant_filter_never_exports_foreign_hosts() {
        let (tenant, h1, h2) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let store = FakeTenants::new(tenant, &[h1]);
        let exp = FakeExporter::ok();
        let hub = start_tenant(tenant, store, exp.clone());
        wait_rounds(&hub, 1).await;
        let (e1, e2) = (event(h1), event(h2));
        let (a1, a2) = (alert(h1), alert(h2));
        hub.offer(&[e1.clone(), e2], &[a1.clone(), a2]);
        settle().await;
        let got: HashSet<Uuid> = exp.flat().into_iter().collect();
        assert_eq!(got, HashSet::from([e1.event_id, a1.alert_id()]));
    }

    #[tokio::test(start_paused = true)]
    async fn tenant_filter_exports_nothing_before_first_load() {
        let (tenant, h1) = (Uuid::new_v4(), Uuid::new_v4());
        let store = FakeTenants::new(tenant, &[h1]);
        let (gate_tx, gate_rx) = std::sync::mpsc::channel();
        *store.gate.lock().unwrap() = Some(gate_rx);
        let exp = FakeExporter::ok();
        let hub = start_tenant(tenant, store.clone(), exp.clone());
        // Let the refresher enter the (blocked) first load.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        let before = event(h1);
        hub.offer(std::slice::from_ref(&before), &[]);
        assert_eq!(
            st(&hub).queued,
            0,
            "nothing may be queued before the first load"
        );
        gate_tx.send(()).unwrap();
        wait_rounds(&hub, 1).await;
        let after = event(h1);
        hub.offer(std::slice::from_ref(&after), &[]);
        settle().await;
        assert_eq!(exp.flat(), vec![after.event_id]);
    }

    #[tokio::test(start_paused = true)]
    async fn host_moved_out_stops_after_refresh() {
        let (tenant, h1, h2) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let store = FakeTenants::new(tenant, &[h1, h2]);
        let exp = FakeExporter::ok();
        let hub = start_tenant(tenant, store.clone(), exp.clone());
        wait_rounds(&hub, 1).await;
        let e_in = event(h2);
        hub.offer(std::slice::from_ref(&e_in), &[]);
        settle().await;
        assert_eq!(exp.flat(), vec![e_in.event_id]);

        store.set(tenant, &[h1]);
        tokio::time::advance(Duration::from_secs(10)).await;
        wait_rounds(&hub, 2).await;
        let (moved, stays) = (event(h2), event(h1));
        hub.offer(&[moved, stays.clone()], &[]);
        settle().await;
        assert_eq!(exp.flat(), vec![e_in.event_id, stays.event_id]);
    }

    #[tokio::test(start_paused = true)]
    async fn tenant_store_error_keeps_previous_set() {
        let (tenant, h1) = (Uuid::new_v4(), Uuid::new_v4());
        let store = FakeTenants::new(tenant, &[h1]);
        let exp = FakeExporter::ok();
        let hub = start_tenant(tenant, store.clone(), exp.clone());
        wait_rounds(&hub, 1).await;
        store.fail.store(true, Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(10)).await;
        wait_rounds(&hub, 2).await;
        assert!(store.calls.load(Ordering::SeqCst) >= 2);
        let e = event(h1);
        hub.offer(std::slice::from_ref(&e), &[]);
        settle().await;
        assert_eq!(exp.flat(), vec![e.event_id]);
    }

    #[tokio::test(start_paused = true)]
    async fn tenant_filter_without_a_store_exports_nothing() {
        let exp = FakeExporter::ok();
        let mut s = settings("t", 10, 100, 100, 5);
        s.tenant_id = Some(Uuid::new_v4());
        let hub = ExportHub::start(
            vec![(s, exp.clone() as Arc<dyn Exporter>)],
            None,
            CancellationToken::new(),
        );
        hub.offer(&events(3), &[]);
        settle().await;
        assert!(exp.delivered().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_flushes_held_records_within_5s() {
        // The first export takes 100 ms; shutdown starts meanwhile. The batch
        // in flight and everything still queued must be flushed.
        let exp = FakeExporter::new(
            vec![Step::Sleep(Duration::from_millis(100))],
            Step::Ok(ExportOutcome::default()),
        );
        let (hub, cancel) = start_one(settings("a", 2, 100, 60_000, 5), exp.clone());
        let evs = events(5);
        hub.offer(&evs, &[]);
        tokio::task::yield_now().await;
        let t0 = Instant::now();
        cancel.cancel();
        hub.shutdown().await;
        assert!(t0.elapsed() < Duration::from_secs(5));
        assert_eq!(exp.flat(), ids(&evs));
        let s = st(&hub);
        assert_eq!(s.state, ExporterState::Stopped);
        assert_eq!(s.sent_records, 5);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_flushes_a_partial_batch_waiting_for_flush_interval() {
        let exp = FakeExporter::ok();
        let (hub, cancel) = start_one(settings("a", 100, 100, 60_000, 5), exp.clone());
        let evs = events(3);
        hub.offer(&evs, &[]);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(exp.delivered().is_empty());
        cancel.cancel();
        hub.shutdown().await;
        assert_eq!(exp.flat(), ids(&evs));
        assert_eq!(st(&hub).state, ExporterState::Stopped);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_gives_up_on_a_hung_exporter_after_5s() {
        let exp = FakeExporter::new(vec![Step::Block], Step::Ok(ExportOutcome::default()));
        let (hub, cancel) = start_one(settings("a", 1, 100, 100, 5), exp.clone());
        // 1 in flight (stuck) + 2 queued.
        hub.offer(&events(3), &[]);
        exp.entered.notified().await;
        assert_eq!(st(&hub).queued, 2);
        let t0 = Instant::now();
        cancel.cancel();
        hub.shutdown().await;
        let took = t0.elapsed();
        assert!(
            took >= Duration::from_millis(4800) && took <= Duration::from_secs(5),
            "{took:?}"
        );
        let s = st(&hub);
        assert_eq!(s.state, ExporterState::Stopped);
        assert_eq!(s.dropped_after_retries, 3, "in-flight + queued are counted");
        assert_eq!(s.sent_records, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn worker_bounds_its_own_flush_when_cancelled_without_shutdown() {
        let exp = FakeExporter::new(vec![Step::Block], Step::Ok(ExportOutcome::default()));
        let (hub, cancel) = start_one(settings("a", 1, 100, 100, 5), exp.clone());
        hub.offer(&events(3), &[]);
        exp.entered.notified().await;
        cancel.cancel();
        tokio::time::sleep(Duration::from_secs(6)).await;
        let s = st(&hub);
        assert_eq!(s.state, ExporterState::Stopped);
        assert_eq!(s.dropped_after_retries, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_is_not_stalled_by_a_hung_tenant_store() {
        let tenant = Uuid::new_v4();
        let store = FakeTenants::new(tenant, &[]);
        let (gate_tx, gate_rx) = std::sync::mpsc::channel();
        *store.gate.lock().unwrap() = Some(gate_rx);
        let hub = start_tenant(tenant, store, FakeExporter::ok());
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        let t0 = std::time::Instant::now();
        hub.shutdown().await;
        assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
        gate_tx.send(()).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn transient_retry_sleep_is_cut_short_by_shutdown() {
        // Transient once, then OK: shutdown during the backoff sleep makes one
        // final attempt at once instead of waiting out the backoff.
        let exp = FakeExporter::new(vec![Step::Transient], Step::Ok(ExportOutcome::default()));
        let (hub, cancel) = start_one(settings("a", 10, 100, 10, 5), exp.clone());
        let evs = events(2);
        hub.offer(&evs, &[]);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(exp.attempts().len(), 1);
        let t0 = Instant::now();
        cancel.cancel();
        hub.shutdown().await;
        assert!(t0.elapsed() < Duration::from_millis(100));
        assert_eq!(exp.flat(), ids(&evs));
    }

    #[test]
    fn worker_settings_from_config() {
        let cfgs: Vec<ExporterConfig> = serde_yaml::from_str(
            "- {name: w1, kind: webhook, url: 'https://h/x', queue_capacity: 7, batch_max: 3, flush_interval_ms: 250, max_retries: 1, tenant_id: 6f1c1a8e-8a52-4c3e-9b4a-1f0d2e3c4b5a}",
        )
        .unwrap();
        let s = WorkerSettings::from_config(&cfgs[0]);
        assert_eq!(s.name, "w1");
        assert_eq!(s.kind, "webhook");
        assert_eq!(s.queue_capacity, 7);
        assert_eq!(s.batch_max, 3);
        assert_eq!(s.flush_interval, Duration::from_millis(250));
        assert_eq!(s.max_retries, 1);
        assert!(s.tenant_id.is_some());
    }

    #[test]
    fn backoff_doubles_from_half_a_second_and_caps_at_30s() {
        for attempt in 0..12u32 {
            let base = (0.5 * 2f64.powi(attempt as i32)).min(30.0);
            for _ in 0..50 {
                let d = backoff(attempt).as_secs_f64();
                assert!(
                    d >= base * 0.8 - 1e-9 && d <= base * 1.2 + 1e-9,
                    "{attempt}: {d}"
                );
            }
        }
    }

    #[test]
    fn status_serializes_state_screaming() {
        let v = serde_json::to_value(ExporterState::Degraded).unwrap();
        assert_eq!(v, serde_json::json!("DEGRADED"));
    }
}
