use std::time::Instant;

use osiris_pipeline::Pipeline;
use osiris_schema::HostRef;
use osiris_sensor_api::{ProcessExecRaw, RawEvent, RawEventSource};
use uuid::Uuid;

/// Plan Global Constraints #10's lightweight benchmark substitute: measures
/// synthetic events/sec through the real Pipeline (not a criterion
/// harness) and asserts against a generous floor so a severe regression
/// fails CI, while printing the actual numbers for a human to judge trend
/// over time (`cargo test -p osiris-e2e-tests --test perf_smoke -- --nocapture`
/// to see them).
#[test]
fn pipeline_processes_synthetic_events_above_a_generous_throughput_floor() {
    let host = HostRef {
        host_id: Uuid::new_v4(),
        hostname: "perf-test-host".to_string(),
        distro: "test".to_string(),
        kernel_version: "test".to_string(),
        cloud: None,
    };
    let mut pipeline = Pipeline::new(host, "perf-boot".to_string());

    const N: u64 = 10_000;
    let start = Instant::now();
    for i in 0..N {
        let raw = RawEvent::ProcessExec(ProcessExecRaw {
            pid: (i % 60_000) as u32 + 1,
            ppid: 1,
            uid: 1000,
            exe_path: "/usr/bin/example".to_string(),
            comm: "example".to_string(),
            timestamp_ns: i,
            start_time_mono: i,
            source: RawEventSource::Synthetic,
        });
        let result = pipeline.process(raw);
        std::hint::black_box(&result);
    }
    let elapsed = start.elapsed();
    let events_per_sec = N as f64 / elapsed.as_secs_f64();

    println!(
        "pipeline throughput: {} events in {:?} = {:.0} events/sec",
        N, elapsed, events_per_sec
    );

    // Generous floor: a synthetic ProcessExec through Normalize/Enrich/
    // Validate/Prioritize with no I/O should comfortably clear a few
    // thousand events/sec even on a slow CI runner. This is a regression
    // guard, not a performance target — ARCHITECTURE.md §19's real budgets
    // require production hardware and traffic to set meaningfully.
    assert!(
        events_per_sec > 1000.0,
        "pipeline throughput regressed badly: {:.0} events/sec (floor: 1000)",
        events_per_sec
    );
}
