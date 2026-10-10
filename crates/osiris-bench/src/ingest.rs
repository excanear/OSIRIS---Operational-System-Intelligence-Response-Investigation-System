//! Ingest bench: real osiris-server binary, real mTLS forwarder, paced load.
use std::collections::VecDeque;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use osiris_real_linux_tests::stack::{Stack, StackOptions};
use osiris_schema::HostRef;
use osiris_transport::client::{run_forwarder, ForwarderConfig};
use uuid::Uuid;

use crate::stats::{summarize, Pacer, Record};

/// A read-only handle on events.db, opened once and reused by `poll_markers`.
fn open_reader(db: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open events.db read-only")
}

/// Returns latencies (ms) of markers now visible in events.db, removing them
/// from `pending`.
pub(crate) fn poll_markers(
    conn: &rusqlite::Connection,
    pending: &mut Vec<(Uuid, Instant)>,
) -> Vec<f64> {
    let mut seen = vec![];
    pending.retain(|(id, sent)| {
        let found = conn
            .query_row(
                "SELECT 1 FROM events WHERE event_id = ?1",
                [id.to_string()],
                |_| Ok(()),
            )
            .is_ok();
        if found {
            seen.push(sent.elapsed().as_secs_f64() * 1000.0);
        }
        !found
    });
    seen
}

/// Server-only stack; the bench itself plays the agent, shipping over the
/// real mTLS listener with the real forwarder (`drive`).
pub fn run(rate: u64, duration_s: u64) -> Record {
    let stack = Stack::start(StackOptions {
        bench_agent: Some(Uuid::new_v4()),
        ..Default::default()
    });
    drive(&stack, rate, duration_s)
}

fn drive(stack: &Stack, rate: u64, duration_s: u64) -> Record {
    let host = HostRef {
        host_id: stack.host_id().unwrap(),
        hostname: "bench".into(),
        distro: "bench".into(),
        kernel_version: "bench".into(),
        cloud: None,
    };
    let mut pipeline = osiris_pipeline::Pipeline::new(host, "bench-boot".into());
    let spool = stack.dir().join("bench-spool.ndjson");
    std::fs::File::create(&spool).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();
    let d = stack.dir();
    let cfg = ForwarderConfig::new(
        stack.agent_addr(),
        "localhost",
        d.join("pki/ca.pem"),
        d.join("pki/agent.pem"),
        d.join("pki/agent.key"),
        spool.clone(),
    );
    rt.spawn(run_forwarder(cfg, cancel.clone()));

    let mut out = std::fs::OpenOptions::new()
        .append(true)
        .open(&spool)
        .unwrap();
    let reader = open_reader(&stack.events_db());
    let mut pacer = Pacer::new(rate);
    let mut max_behind = 0u64;
    let mut markers_sent = 0u64;
    let (start, end) = (Instant::now(), Duration::from_secs(duration_s));
    let mut sent = 0u64;
    let mut next_marker = Duration::ZERO;
    let mut pending = vec![];
    let mut latencies = vec![];
    // exec chains only: the generator reuses fixed pids in every scenario, so the richer mix
    // piles ever more edges onto the same few process keys and measures that, not ingest.
    let mut queue = VecDeque::new();
    let mut scenario_i = 0u64;
    while start.elapsed() < end {
        max_behind = max_behind.max(pacer.behind(start.elapsed()));
        let n = pacer.due(start.elapsed());
        let mut buf = String::new();
        let mut batch_markers = vec![];
        for _ in 0..n {
            if queue.is_empty() {
                queue.extend(osiris_generator::exec_chain_scenario(scenario_i));
                scenario_i += 1;
            }
            let ev = pipeline.process(queue.pop_front().unwrap()).event;
            if start.elapsed() >= next_marker {
                batch_markers.push(ev.event_id);
                next_marker += Duration::from_millis(100);
            }
            buf.push_str(&serde_json::to_string(&ev).unwrap());
            buf.push('\n');
            sent += 1;
        }
        out.write_all(buf.as_bytes()).unwrap();
        // Stamped once the bytes are in the spool, so driver time is not counted as server latency.
        let written_at = Instant::now();
        markers_sent += batch_markers.len() as u64;
        pending.extend(batch_markers.into_iter().map(|id| (id, written_at)));
        latencies.extend(poll_markers(&reader, &mut pending));
        if pacer.behind(start.elapsed()) == 0 {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let send_elapsed = start.elapsed();
    // Drain: give stragglers up to 30 s, then count the rest as not delivered.
    let drain_end = Instant::now() + Duration::from_secs(30);
    while !pending.is_empty() && Instant::now() < drain_end {
        latencies.extend(poll_markers(&reader, &mut pending));
        std::thread::sleep(Duration::from_millis(50));
    }
    // Server-side throughput: what reached events.db over the whole run (send + drain).
    let run_elapsed = start.elapsed();
    let stored: u64 = reader
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .unwrap_or(0);
    cancel.cancel();
    let achieved = sent as f64 / send_elapsed.as_secs_f64();
    let delivered = summarize(&mut latencies);
    // The driver could not keep pace if it ever lagged by more than one slice.
    let saturated = max_behind > pacer.slice();
    Record {
        bench: "ingest".into(),
        params: serde_json::json!({"rate": rate, "duration_s": duration_s}),
        metrics: serde_json::json!({
            "sent": sent,
            "target_eps": rate,
            "achieved_eps": achieved,
            "saturated": saturated,
            "max_behind_events": max_behind,
            "stored_events": stored,
            "stored_eps_over_run": stored as f64 / run_elapsed.as_secs_f64(),
            "markers_sent": markers_sent,
            "markers_lost": pending.len(),
            // Percentiles cover only markers that became visible; lost markers
            // are censored at the 30 s drain bound and are NOT in these numbers.
            "latency_ms_delivered_only": delivered,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_latency_is_measured_from_send_to_first_visibility() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("events.db");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TABLE events (event_id TEXT PRIMARY KEY)")
            .unwrap();
        let id = uuid::Uuid::new_v4();
        let mut pending = vec![(id, std::time::Instant::now())];
        let reader = open_reader(&db);
        assert!(poll_markers(&reader, &mut pending).is_empty());
        conn.execute(
            "INSERT INTO events (event_id) VALUES (?1)",
            [id.to_string()],
        )
        .unwrap();
        let seen = poll_markers(&reader, &mut pending);
        assert_eq!(seen.len(), 1);
        assert!(pending.is_empty());
    }
}
