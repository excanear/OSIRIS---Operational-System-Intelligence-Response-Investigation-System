//! Kernel-clock → wall-clock conversion shared by every eBPF sensor.

/// realtime − monotonic, in ns: added to a `bpf_ktime_get_ns()` value
/// (CLOCK_MONOTONIC) it gives wall-clock time. Callers resample it for
/// every record (two vDSO clock reads), because CLOCK_MONOTONIC does not
/// follow a wall-clock step and stops during suspend: an offset sampled
/// once would misstamp every later event by the step. If
/// `clock_gettime(CLOCK_MONOTONIC)` fails it returns 0 and warns once.
#[cfg(target_os = "linux")]
pub fn boot_wall_offset_ns() -> i128 {
    static CLOCK_WARNING: std::sync::Once = std::sync::Once::new();
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec for the duration of the
    // call; CLOCK_MONOTONIC is always supported on Linux.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0);
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        // Called per record: warn once, not once per event.
        CLOCK_WARNING.call_once(|| {
            tracing::warn!(
                error = %error,
                "clock_gettime(CLOCK_MONOTONIC) failed; eBPF event timestamps will be \
                 monotonic, not wall-clock"
            );
        });
        return 0;
    }
    wall - (i128::from(ts.tv_sec) * 1_000_000_000 + i128::from(ts.tv_nsec))
}

/// Off Linux an object never loads, so the offset is never used.
#[cfg(not(target_os = "linux"))]
pub fn boot_wall_offset_ns() -> i128 {
    0
}

#[cfg(test)]
mod tests {
    /// The real offset is realtime − monotonic: positive on any host whose
    /// clock is past the epoch by more than its uptime, and stable between
    /// two back-to-back samples when no step happens.
    #[cfg(target_os = "linux")]
    #[test]
    fn boot_wall_offset_is_realtime_minus_monotonic() {
        let a = super::boot_wall_offset_ns();
        let b = super::boot_wall_offset_ns();
        assert!(a > 0, "offset {a}");
        assert!((a - b).abs() < 1_000_000_000, "offsets {a} and {b}");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn boot_wall_offset_is_zero_off_linux() {
        assert_eq!(super::boot_wall_offset_ns(), 0);
    }
}
