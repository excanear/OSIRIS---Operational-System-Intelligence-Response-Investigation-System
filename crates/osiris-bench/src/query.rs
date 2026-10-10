use std::time::Instant;

use osiris_schema::{Alert, CanonicalEvent, EventType, Severity};
use osiris_storage::{AlertQueryPlan, QueryPlan, Storage};
use osiris_storage_sqlite::SqliteStorage;
use uuid::Uuid;

use crate::pipeline::{new_pipeline, scenario};
use crate::stats::{percentile, Record};

const CHUNK: usize = 5000;
const REPS: usize = 5;

fn median_ms(mut f: impl FnMut()) -> f64 {
    let mut samples: Vec<f64> = (0..REPS)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    samples.sort_by(|a, b| a.total_cmp(b));
    percentile(&samples, 50.0).unwrap_or(0.0)
}

pub fn run(events: u64) -> Record {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = SqliteStorage::open(dir.path().join("events.db")).expect("open storage");
    let mut pipeline = new_pipeline();

    let fill = Instant::now();
    let mut chunk: Vec<CanonicalEvent> = Vec::with_capacity(CHUNK);
    let (mut generated, mut written, mut i) = (0u64, 0u64, 0u64);
    while generated < events {
        for raw in scenario(i) {
            chunk.push(pipeline.process(raw).event);
            generated += 1;
        }
        i += 1;
        if chunk.len() >= CHUNK {
            written += storage
                .batch_write(&chunk)
                .expect("batch_write")
                .written_count;
            chunk.clear();
        }
    }
    if !chunk.is_empty() {
        written += storage
            .batch_write(&chunk)
            .expect("batch_write")
            .written_count;
    }
    // One alert per 100 events, so the alerts query reads a populated table.
    let host_id = Uuid::new_v4();
    let alerts: Vec<Alert> = (0..(events / 100).max(1))
        .map(|i| {
            Alert::new(
                "bench_rule",
                1,
                "bench-hash",
                Severity::High,
                1_000_000_000 + i,
                host_id,
                vec!["bench alert".to_string()],
                vec![Uuid::new_v4()],
            )
            .expect("alert")
        })
        .collect();
    let alerts_written = storage
        .write_alerts(&alerts)
        .expect("write_alerts")
        .written_count;
    let fill_ms = fill.elapsed().as_secs_f64() * 1000.0;

    let list_ms = median_ms(|| {
        std::hint::black_box(storage.query(&QueryPlan::new()).expect("query"));
    });
    let exec_plan = QueryPlan {
        event_type: Some(EventType::ProcessExec),
        ..QueryPlan::new()
    };
    let exec_ms = median_ms(|| {
        std::hint::black_box(storage.query(&exec_plan).expect("query"));
    });
    let alerts_ms = median_ms(|| {
        std::hint::black_box(
            storage
                .query_alerts(&AlertQueryPlan::new())
                .expect("alerts"),
        );
    });

    Record {
        bench: "query".to_string(),
        params: serde_json::json!({ "events": events }),
        metrics: serde_json::json!({
            "events_generated": generated,
            "events_written": written,
            "fill_ms": fill_ms,
            "list_default": { "median_ms": list_ms },
            "process_exec": { "median_ms": exec_ms },
            "alerts": { "rows": alerts_written, "median_ms": alerts_ms },
        }),
    }
}
