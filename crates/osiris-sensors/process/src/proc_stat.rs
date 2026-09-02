/// Parses the `starttime` field (field 22, 1-indexed) out of the content
/// of /proc/<pid>/stat. The `comm` field (field 2) is parenthesized and may
/// itself contain spaces, so parsing must skip past the matching `)`
/// before splitting the remainder on whitespace, per `man proc`.
pub fn parse_proc_stat_starttime(content: &str) -> Option<u64> {
    let close_paren = content.rfind(')')?;
    let rest = &content[close_paren + 1..];
    // rest starts with " state ppid pgrp session tty_nr tpgid flags ...";
    // field 3 (state) is rest's token 0; starttime (field 22) is token 19.
    let fields: Vec<&str> = rest.split_whitespace().collect();
    fields.get(19)?.parse().ok()
}

/// Reads and parses /proc/<pid>/stat for the given pid. Returns None on any
/// platform/pid where the path doesn't exist (e.g. this dev machine,
/// Windows) rather than erroring — the caller falls back to the audit
/// record's own timestamp (process_key still gets a usable, if less
/// precise, start_time_mono either way — plan Global Constraints).
pub fn read_process_start_time(pid: u32) -> Option<u64> {
    let content = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    parse_proc_stat_starttime(&content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_starttime_from_a_realistic_proc_stat_line() {
        // 44-field layout; starttime (field 22) is 1234567 here. comm
        // deliberately contains a space to exercise the paren-skip logic.
        let line = "5678 (my process) S 1234 5678 5678 0 -1 4194304 100 0 0 0 1 2 0 0 20 0 1 0 1234567 0 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0 0 0 0 0 0 0 0 0";
        assert_eq!(parse_proc_stat_starttime(line), Some(1_234_567));
    }

    #[test]
    fn read_process_start_time_returns_none_when_proc_path_absent() {
        // No /proc filesystem on this dev machine — must return None, not
        // panic or error.
        assert_eq!(read_process_start_time(u32::MAX), None);
    }
}
