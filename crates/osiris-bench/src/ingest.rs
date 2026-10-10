use crate::stats::Record;

/// Stub; replaced in Task 7.
pub fn run(rate: u64, duration_s: u64) -> Record {
    Record {
        bench: "ingest".to_string(),
        params: serde_json::json!({ "rate": rate, "duration_s": duration_s }),
        metrics: serde_json::json!({ "skipped": "implemented in Task 7" }),
    }
}
