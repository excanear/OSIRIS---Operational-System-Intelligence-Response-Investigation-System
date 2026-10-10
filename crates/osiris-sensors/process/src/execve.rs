//! argv from audit `type=EXECVE` records.
//!
//! The kernel (`audit_log_execve_info`) logs `argc=N` and then each
//! argument as `aI=<value>`, where `<value>` is `"quoted"` when every byte
//! is printable ASCII other than `"`, and unquoted uppercase hex otherwise
//! (a space is enough). A long argument is split as `aI_len=<bytes>
//! aI[0]=<chunk> aI[1]=<chunk> ...`, and a long argv spills over several
//! EXECVE records of the same event; only the first carries `argc`.
//!
//! Caps (one exec's argv must not grow memory or event size without
//! bound — `ARG_MAX` allows megabytes): at most [`MAX_ARGS`] arguments and
//! [`MAX_ARGV_BYTES`] decoded bytes are kept; the argument crossing the
//! byte limit is cut there and later ones are dropped, so the result is
//! always a prefix of the real argv.

use std::collections::BTreeMap;

use osiris_fileutil::audit_kv::ENRICHMENT_SEPARATOR;

/// Most argv entries kept per exec; later arguments are dropped.
pub const MAX_ARGS: usize = 128;
/// Most decoded argv bytes kept per exec, summed over the kept arguments.
pub const MAX_ARGV_BYTES: usize = 16 * 1024;

#[derive(Debug, Default)]
struct Arg {
    kept: Vec<u8>,
    /// Decoded bytes the kernel logged for this argument (before the cap).
    received: usize,
    /// `aI_len` for an argument the kernel split into `aI[n]` chunks.
    split_len: Option<usize>,
    /// Logged whole as `aI=`.
    whole: bool,
}

impl Arg {
    fn is_done(&self) -> bool {
        self.whole || self.split_len.is_some_and(|len| self.received >= len)
    }

    /// Logged by the kernel but none of it kept (the byte cap was spent).
    fn dropped(&self) -> bool {
        self.kept.is_empty() && self.received > 0
    }
}

/// Accumulates one exec's EXECVE record(s).
#[derive(Debug, Default)]
pub struct ArgvCollector {
    argc: Option<usize>,
    args: BTreeMap<usize, Arg>,
    kept_bytes: usize,
}

impl ArgvCollector {
    /// Feeds one `type=EXECVE` line. Anything after auditd's ENRICHED
    /// separator is auditd's, not the kernel's, and is ignored.
    pub fn feed(&mut self, line: &str) {
        let kernel_fields = line.split(ENRICHMENT_SEPARATOR).next().unwrap_or_default();
        // Quoted values never contain whitespace (see module doc), so
        // whitespace splitting is exact for EXECVE records.
        for token in kernel_fields.split_whitespace() {
            let Some((key, value)) = token.split_once('=') else {
                continue;
            };
            if key == "argc" {
                self.argc = value.parse().ok();
                continue;
            }
            let Some(rest) = key.strip_prefix('a') else {
                continue;
            };
            if let Some(index) = rest.strip_suffix("_len") {
                if let (Ok(index), Ok(len)) = (index.parse::<usize>(), value.parse()) {
                    if index < MAX_ARGS {
                        self.args.entry(index).or_default().split_len = Some(len);
                    }
                }
            } else if let Some((index, _chunk)) = rest.split_once('[') {
                if let Ok(index) = index.parse() {
                    self.append(index, value, false);
                }
            } else if let Ok(index) = rest.parse() {
                self.append(index, value, true);
            }
        }
    }

    fn append(&mut self, index: usize, value: &str, whole: bool) {
        if index >= MAX_ARGS {
            return;
        }
        let decoded = decode_value(value);
        let room = MAX_ARGV_BYTES - self.kept_bytes;
        let take = decoded.len().min(room);
        let arg = self.args.entry(index).or_default();
        arg.whole |= whole;
        arg.received += decoded.len();
        arg.kept.extend_from_slice(&decoded[..take]);
        self.kept_bytes += take;
    }

    /// Every argument this collector will keep has been fully logged.
    pub fn is_complete(&self) -> bool {
        let Some(argc) = self.argc else {
            return false;
        };
        (0..argc.min(MAX_ARGS)).all(|i| self.args.get(&i).is_some_and(Arg::is_done))
    }

    /// The kept argv prefix, `argv[0]` first. Bytes that are not UTF-8
    /// are replaced (U+FFFD), matching how the rest of the schema carries
    /// paths.
    pub fn into_argv(self) -> Vec<String> {
        let wanted = self.argc.unwrap_or(MAX_ARGS).min(MAX_ARGS);
        (0..wanted)
            .map_while(|i| self.args.get(&i).filter(|a| !a.dropped()))
            .map(|arg| String::from_utf8_lossy(&arg.kept).into_owned())
            .collect()
    }
}

/// `"text"` -> text; uppercase hex -> its bytes; anything else (which the
/// kernel does not emit) is kept as printed.
fn decode_value(value: &str) -> Vec<u8> {
    if let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        return inner.as_bytes().to_vec();
    }
    let is_hex = !value.is_empty()
        && value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b));
    if !is_hex {
        return value.as_bytes().to_vec();
    }
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        _ => b - b'A' + 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv_of(lines: &[&str]) -> (bool, Vec<String>) {
        let mut c = ArgvCollector::default();
        for l in lines {
            c.feed(l);
        }
        (c.is_complete(), c.into_argv())
    }

    #[test]
    fn quoted_and_hex_values_decode() {
        let (done, argv) = argv_of(&[
            r#"type=EXECVE msg=audit(1.0:1): argc=3 a0="/bin/sh" a1="-c" a2=74727565206F7369726973"#,
        ]);
        assert!(done);
        assert_eq!(argv, ["/bin/sh", "-c", "true osiris"]);
    }

    /// A value that only looks like hex is still literal when quoted.
    #[test]
    fn a_quoted_hex_looking_value_stays_literal() {
        let (_, argv) = argv_of(&[r#"type=EXECVE msg=audit(1.0:1): argc=1 a0="CAFE""#]);
        assert_eq!(argv, ["CAFE"]);
    }

    /// Kernel format for one argument longer than a record can hold:
    /// `aI_len` plus ordered `aI[n]` chunks, possibly across records.
    #[test]
    fn a_split_argument_is_joined_across_records_and_completes_at_its_len() {
        let mut c = ArgvCollector::default();
        c.feed(r#"type=EXECVE msg=audit(1.0:1): argc=2 a0="echo" a1_len=10 a1[0]=68656C6C6F"#);
        assert!(!c.is_complete(), "a1 has 5 of 10 bytes");
        c.feed(r#"type=EXECVE msg=audit(1.0:1):  a1[1]="world""#);
        assert!(c.is_complete());
        assert_eq!(c.into_argv(), ["echo", "helloworld"]);
    }

    #[test]
    fn incomplete_until_every_argument_up_to_argc_is_seen() {
        let mut c = ArgvCollector::default();
        c.feed(r#"type=EXECVE msg=audit(1.0:1): argc=3 a0="a" a1="b""#);
        assert!(!c.is_complete());
        c.feed(r#"type=EXECVE msg=audit(1.0:1):  a2="c""#);
        assert!(c.is_complete());
    }

    #[test]
    fn an_empty_argument_is_kept() {
        let (done, argv) =
            argv_of(&[r#"type=EXECVE msg=audit(1.0:1): argc=3 a0="x" a1="" a2="y""#]);
        assert!(done);
        assert_eq!(argv, ["x", "", "y"]);
    }

    #[test]
    fn enrichment_after_the_gs_separator_is_ignored() {
        let (_, argv) =
            argv_of(&["type=EXECVE msg=audit(1.0:1): argc=1 a0=\"ls\"\u{1d}a1=\"bogus\""]);
        assert_eq!(argv, ["ls"]);
    }

    #[test]
    fn invalid_utf8_is_replaced_not_dropped() {
        let (_, argv) = argv_of(&["type=EXECVE msg=audit(1.0:1): argc=1 a0=41FF42"]);
        assert_eq!(argv, ["A\u{FFFD}B"]);
    }

    #[test]
    fn the_byte_cap_cuts_the_crossing_argument_and_drops_the_rest() {
        let big = "x".repeat(MAX_ARGV_BYTES - 2);
        let line =
            format!(r#"type=EXECVE msg=audit(1.0:1): argc=4 a0="{big}" a1="abcd" a2="efgh" a3="""#);
        let (done, argv) = argv_of(&[&line]);
        assert!(done, "dropped arguments still count as logged");
        assert_eq!(argv.len(), 2);
        assert_eq!(argv[1], "ab");
        assert_eq!(argv.iter().map(String::len).sum::<usize>(), MAX_ARGV_BYTES);
    }

    #[test]
    fn the_argument_cap_keeps_the_first_max_args() {
        let args: String = (0..MAX_ARGS + 5)
            .map(|i| format!(" a{i}=\"{i}\""))
            .collect();
        let line = format!("type=EXECVE msg=audit(1.0:1): argc={}{args}", MAX_ARGS + 5);
        let (done, argv) = argv_of(&[&line]);
        assert!(done);
        assert_eq!(argv.len(), MAX_ARGS);
        assert_eq!(argv[MAX_ARGS - 1], (MAX_ARGS - 1).to_string());
    }

    #[test]
    fn without_argc_the_record_is_never_complete_but_still_yields_argv() {
        let (done, argv) = argv_of(&[r#"type=EXECVE msg=audit(1.0:1): a0="ls""#]);
        assert!(!done);
        assert_eq!(argv, ["ls"]);
    }
}
