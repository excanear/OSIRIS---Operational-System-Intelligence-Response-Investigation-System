/// A process that started after the observation (plus 2 s slack) is a different process.
pub fn process_started_by(start_ns: u64, observed_at_ns: u64) -> bool {
    start_ns <= observed_at_ns.saturating_add(2_000_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn started_by_cases() {
        assert!(process_started_by(100, 100));
        assert!(process_started_by(1_000_000_000, 0));
        assert!(!process_started_by(3_000_000_000, 0));
    }
}
