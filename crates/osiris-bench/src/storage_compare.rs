//! SQLite vs ClickHouse storage comparison (Phase 11c, design section 6).
//!
//! Every round fills a fresh store through `batch_write`, then times five
//! query shapes 20 times each. The same pre-generated events feed every
//! backend and round, so generation cost is outside the ingest timing and
//! both backends see identical data. Medians and a noise envelope
//! (`noise_pct` = (max - min) / median across rounds) are reported so a
//! difference inside the noise is never claimed.

use std::path::Path;
use std::time::Instant;

use osiris_query::EventQueryPlan;
use osiris_schema::{CanonicalEvent, EventType};
use osiris_storage::{QueryPlan, Storage};
use osiris_storage_clickhouse::{ClickHouseOptions, ClickHouseStorage};
use osiris_storage_sqlite::SqliteStorage;
use uuid::Uuid;

use crate::pipeline::{new_pipeline, scenario};
use crate::stats::{percentile, Record};

const HOSTS: usize = 8;
const SAMPLES: usize = 20;
pub const SHAPES: [&str; 5] = [
    "host_window",
    "event_type",
    "process_key",
    "residual",
    "get_event",
];

#[derive(Debug, Clone)]
pub struct Args {
    pub events: u64,
    pub rounds: usize,
    pub batch: usize,
    pub clickhouse_url: Option<String>,
}

/// What the five shapes look up; taken from the generated data.
struct Targets {
    host_id: Uuid,
    since: u64,
    until: u64,
    process_key: osiris_schema::ProcessKey,
    pid: u32,
    event_id: Uuid,
}

struct RoundResult {
    ingest_eps: f64,
    /// Per shape: the samples, in ms.
    samples: Vec<Vec<f64>>,
    bytes_per_event: f64,
}

fn sorted(mut v: Vec<f64>) -> Vec<f64> {
    v.sort_by(|a, b| a.total_cmp(b));
    v
}

fn median(v: &[f64]) -> f64 {
    percentile(&sorted(v.to_vec()), 50.0).unwrap_or(0.0)
}

/// (max - min) / median, in percent; 0 when the median is 0.
fn noise_pct(v: &[f64]) -> f64 {
    let m = median(v);
    if m <= 0.0 || v.is_empty() {
        return 0.0;
    }
    let max = v.iter().copied().fold(f64::MIN, f64::max);
    let min = v.iter().copied().fold(f64::MAX, f64::min);
    (max - min) / m * 100.0
}

fn generate(events: u64) -> Vec<CanonicalEvent> {
    let mut pipelines: Vec<_> = (0..HOSTS).map(|_| new_pipeline()).collect();
    let mut out = Vec::with_capacity(events as usize);
    let mut i = 0u64;
    while (out.len() as u64) < events {
        let p = &mut pipelines[(i as usize) % HOSTS];
        for raw in scenario(i) {
            if (out.len() as u64) < events {
                out.push(p.process(raw).event);
            }
        }
        i += 1;
    }
    out
}

fn targets(events: &[CanonicalEvent]) -> Targets {
    let exec = events
        .iter()
        .skip(events.len() / 2)
        .chain(events.iter())
        .find(|e| e.event_type == EventType::ProcessExec && e.process.is_some())
        .expect("generated data has a PROCESS_EXEC event with a process");
    let proc = exec.process.as_ref().expect("process");
    let host_id = exec.host_id;
    let (lo, hi) = events
        .iter()
        .filter(|e| e.host_id == host_id)
        .fold((u64::MAX, 0u64), |(lo, hi), e| {
            (lo.min(e.timestamp), hi.max(e.timestamp))
        });
    Targets {
        host_id,
        since: lo,
        until: lo + (hi - lo) / 10,
        process_key: proc.process_key,
        pid: proc.pid,
        event_id: exec.event_id,
    }
}

/// A shape that finds nothing would still yield a "valid" latency record, so
/// an empty result is a hard error of the bench run.
fn check_nonempty(backend: &str, shape: &str, rows: usize) {
    assert!(
        rows > 0,
        "storage-compare: shape `{shape}` returned no rows on {backend}"
    );
}

fn time_ms(f: &dyn Fn()) -> f64 {
    let t = Instant::now();
    f();
    t.elapsed().as_secs_f64() * 1000.0
}

fn measure(backend: &str, store: &dyn Storage, t: &Targets) -> Vec<Vec<f64>> {
    let window = EventQueryPlan {
        host_ids: Some(vec![t.host_id.to_string()]),
        since: Some(t.since),
        until: Some(t.until),
        ..EventQueryPlan::new()
    };
    let by_type = EventQueryPlan::with_filter("event_type = \"PROCESS_EXEC\"").expect("oql");
    let by_key = QueryPlan {
        process_key: Some(t.process_key),
        ..QueryPlan::new()
    };
    let residual = EventQueryPlan::with_filter(&format!(
        "event_type = \"PROCESS_EXEC\" AND process.pid = {}",
        t.pid
    ))
    .expect("oql");

    let shapes: [Box<dyn Fn() -> usize + '_>; 5] = [
        Box::new(|| std::hint::black_box(store.query_events(&window).expect("host_window")).len()),
        Box::new(|| std::hint::black_box(store.query_events(&by_type).expect("event_type")).len()),
        Box::new(|| std::hint::black_box(store.query(&by_key).expect("process_key")).len()),
        Box::new(|| std::hint::black_box(store.query_events(&residual).expect("residual")).len()),
        Box::new(|| {
            usize::from(
                std::hint::black_box(store.get_event(t.event_id).expect("get_event")).is_some(),
            )
        }),
    ];
    shapes
        .iter()
        .zip(SHAPES)
        .map(|(f, shape)| {
            // Warm-up, not sampled: doubles as the correctness check.
            check_nonempty(backend, shape, f());
            (0..SAMPLES)
                .map(|_| {
                    time_ms(&|| {
                        f();
                    })
                })
                .collect()
        })
        .collect()
}

fn fill(store: &dyn Storage, events: &[CanonicalEvent], batch: usize) -> f64 {
    let t = Instant::now();
    let mut written = 0u64;
    for chunk in events.chunks(batch.max(1)) {
        written += store.batch_write(chunk).expect("batch_write").written_count;
    }
    let secs = t.elapsed().as_secs_f64();
    assert_eq!(written, events.len() as u64, "every event must be stored");
    events.len() as f64 / secs
}

fn sqlite_footprint(db: &Path) -> u64 {
    let wal = db.with_file_name("events.db-wal");
    [db.to_path_buf(), wal]
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum()
}

fn sqlite_round(events: &[CanonicalEvent], t: &Targets, batch: usize) -> RoundResult {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("events.db");
    let store = SqliteStorage::open(&path).expect("open sqlite");
    let ingest_eps = fill(&store, events, batch);
    let bytes_per_event = sqlite_footprint(&path) as f64 / events.len() as f64;
    let samples = measure("sqlite", &store, t);
    RoundResult {
        ingest_eps,
        samples,
        bytes_per_event,
    }
}

fn clickhouse_round(
    url: &str,
    events: &[CanonicalEvent],
    t: &Targets,
    batch: usize,
) -> RoundResult {
    let store = ClickHouseStorage::open(ClickHouseOptions {
        url: url.to_string(),
        database: format!("osiris_bench_{}", Uuid::new_v4().simple()),
        ..ClickHouseOptions::default()
    })
    .expect("open clickhouse");
    let ingest_eps = fill(&store, events, batch);
    store.optimize().expect("optimize");
    let bytes_per_event = store.disk_bytes().expect("disk_bytes") as f64 / events.len() as f64;
    let samples = measure("clickhouse", &store, t);
    store.drop_database().expect("drop database");
    RoundResult {
        ingest_eps,
        samples,
        bytes_per_event,
    }
}

fn record(backend: &str, args: &Args, rounds: &[RoundResult]) -> Record {
    let eps: Vec<f64> = rounds.iter().map(|r| r.ingest_eps).collect();
    let mut metrics = serde_json::Map::new();
    let mut noise = serde_json::Map::new();
    metrics.insert("ingest_eps".into(), median(&eps).into());
    noise.insert("ingest_eps".into(), noise_pct(&eps).into());
    for (s, name) in SHAPES.iter().enumerate() {
        let all = sorted(rounds.iter().flat_map(|r| r.samples[s].clone()).collect());
        let p50s: Vec<f64> = rounds.iter().map(|r| median(&r.samples[s])).collect();
        metrics.insert(
            (*name).into(),
            serde_json::json!({
                "p50_ms": percentile(&all, 50.0),
                "p95_ms": percentile(&all, 95.0),
            }),
        );
        noise.insert((*name).into(), noise_pct(&p50s).into());
    }
    let bpe: Vec<f64> = rounds.iter().map(|r| r.bytes_per_event).collect();
    metrics.insert("bytes_per_event".into(), median(&bpe).into());
    metrics.insert("noise_pct".into(), noise.into());
    Record {
        bench: "storage_compare".to_string(),
        params: serde_json::json!({
            "backend": backend,
            "events": args.events,
            "batch": args.batch,
            "rounds": args.rounds,
        }),
        metrics: metrics.into(),
    }
}

pub fn run(args: Args) -> Vec<Record> {
    let events = generate(args.events);
    let t = targets(&events);
    let rounds = args.rounds.max(1);
    let mut out = vec![];

    let sqlite: Vec<RoundResult> = (0..rounds)
        .map(|_| sqlite_round(&events, &t, args.batch))
        .collect();
    out.push(record("sqlite", &args, &sqlite));

    match &args.clickhouse_url {
        Some(url) => {
            let ch: Vec<RoundResult> = (0..rounds)
                .map(|_| clickhouse_round(url, &events, &t, args.batch))
                .collect();
            out.push(record("clickhouse", &args, &ch));
        }
        None => eprintln!("storage-compare: no --clickhouse-url, running SQLite only"),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_only_run_emits_all_metrics() {
        let recs = run(Args {
            events: 2_000,
            rounds: 2,
            batch: 500,
            clickhouse_url: None,
        });
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.bench, "storage_compare");
        assert_eq!(r.params["backend"], "sqlite");
        assert!(r.metrics["ingest_eps"].as_f64().unwrap() > 0.0);
        for s in SHAPES {
            let p50 = r.metrics[s]["p50_ms"].as_f64().expect(s);
            let p95 = r.metrics[s]["p95_ms"].as_f64().expect(s);
            assert!(p50 <= p95, "{s}: p50 {p50} > p95 {p95}");
            assert!(r.metrics["noise_pct"][s].as_f64().is_some(), "{s} noise");
        }
        assert!(r.metrics["noise_pct"]["ingest_eps"].as_f64().is_some());
        assert!(r.metrics["bytes_per_event"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn measure_finds_rows_for_every_shape() {
        let events = generate(2_000);
        let t = targets(&events);
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStorage::open(dir.path().join("events.db")).unwrap();
        fill(&store, &events, 500);
        // Panics (via check_nonempty) if any shape returns nothing.
        let samples = measure("sqlite", &store, &t);
        assert_eq!(samples.len(), SHAPES.len());
    }

    #[test]
    #[should_panic(expected = "returned no rows on clickhouse")]
    fn empty_result_is_a_hard_error() {
        check_nonempty("clickhouse", "host_window", 0);
    }

    #[test]
    fn noise_is_range_over_median() {
        assert_eq!(noise_pct(&[90.0, 100.0, 110.0]), 20.0);
        assert_eq!(noise_pct(&[0.0, 0.0]), 0.0);
    }
}
