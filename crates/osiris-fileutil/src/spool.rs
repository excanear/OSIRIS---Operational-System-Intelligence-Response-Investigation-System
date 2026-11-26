//! Spool file identity, rotation naming and reader cursors (Phase 13a,
//! spec §5.2b).
//!
//! Each spool file the Agent writes begins with a header line
//! `{"osiris_spool":"<id>"}`. The id names the file across renames, using
//! only file contents, with no inode APIs, so the same logic runs on every
//! platform. The Agent rotates `<spool>` to `<spool>.1` (replacing any
//! older `.1`) and starts a fresh `<spool>` with a new id. A reader persists
//! a [`SpoolCursor`] `(id, offset)` and asks [`locate`] which file that
//! cursor now points into.
//!
//! Std-only on purpose: this crate is a dependency leaf. The id is an
//! opaque token supplied by the writer (a uuid string), so the header is
//! built and recognised with plain string handling, not serde.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

const HEADER_PREFIX: &str = "{\"osiris_spool\":\"";
const HEADER_SUFFIX: &str = "\"}";
/// Upper bound on how much of a file's first line is examined. A real
/// header is ~54 bytes; this only stops a huge legacy first line being read
/// in full just to learn that it is not a header.
const MAX_HEADER_LINE: u64 = 1024;

/// The header line (with its `\n`) that starts a spool file with id `id`.
/// `id` must be a plain token with no `"`, `\` or whitespace, such as a uuid.
pub fn header_line(id: &str) -> String {
    debug_assert!(is_plain_id(id), "spool id must be a plain token: {id:?}");
    format!("{HEADER_PREFIX}{id}{HEADER_SUFFIX}\n")
}

/// True if `line` (with or without its line terminator) is a spool header.
pub fn is_header_line(line: &[u8]) -> bool {
    header_id(line).is_some()
}

fn header_id(line: &[u8]) -> Option<&str> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let text = std::str::from_utf8(line).ok()?;
    let id = text
        .strip_prefix(HEADER_PREFIX)?
        .strip_suffix(HEADER_SUFFIX)?;
    is_plain_id(id).then_some(id)
}

fn is_plain_id(id: &str) -> bool {
    !id.is_empty()
        && !id
            .chars()
            .any(|c| c == '"' || c == '\\' || c.is_whitespace() || c.is_control())
}

/// The id in `path`'s header. `None` if the file is missing, empty, or its
/// first line is not a header (a legacy, pre-13a spool).
pub fn read_spool_id(path: &Path) -> std::io::Result<Option<String>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    read_spool_id_from(file)
}

/// The id in the header at the start of `reader` (a spool file positioned
/// at 0). Lets a reader check the id of the very handle it then reads
/// from, so a rotation between choosing a path and opening it is caught.
pub fn read_spool_id_from(reader: impl Read) -> std::io::Result<Option<String>> {
    let mut first = Vec::new();
    BufReader::new(reader.take(MAX_HEADER_LINE)).read_until(b'\n', &mut first)?;
    Ok(header_id(&first).map(str::to_owned))
}

/// Where a rotated spool goes: `<spool>.1`.
pub fn rotated_path(spool: &Path) -> PathBuf {
    let mut name = spool.as_os_str().to_owned();
    name.push(".1");
    PathBuf::from(name)
}

/// A reader's durable position: which spool file (`id`; `None` = a legacy
/// file without a header) and the byte offset read up to in it.
///
/// A reader must store the id [`read_spool_id`] gave for the file it is
/// actually reading. The Agent never exposes a headered spool without its
/// header (it writes each new spool to a temporary file and renames it
/// into place), so `id: None` only ever describes a genuine legacy file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpoolCursor {
    pub id: Option<String>,
    pub offset: u64,
}

/// What [`SpoolCursor::load`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CursorLoad {
    /// No cursor file: this reader has no position yet. Pass `None` to
    /// [`locate`], which answers [`SpoolPosition::Start`].
    Missing,
    /// A cursor file exists but cannot be read or parsed. The position is a
    /// real unknown: treat it as [`SpoolPosition::Lost`] (count and log the
    /// loss), then restart the current file at 0.
    Garbled,
    /// A valid cursor.
    Loaded(SpoolCursor),
}

impl SpoolCursor {
    /// Reads a cursor stored by [`SpoolCursor::store`]: `"<id> <offset>"`.
    /// A bare number is a legacy (pre-13a) offset file, `{ id: None,
    /// offset }`.
    pub fn load(path: &Path) -> CursorLoad {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return CursorLoad::Missing,
            Err(_) => return CursorLoad::Garbled,
        };
        let mut parts = text.split_whitespace();
        let cursor = match (parts.next(), parts.next(), parts.next()) {
            (Some(offset), None, None) => offset
                .parse()
                .ok()
                .map(|offset| SpoolCursor { id: None, offset }),
            (Some(id), Some(offset), None) if is_plain_id(id) => {
                offset.parse().ok().map(|offset| SpoolCursor {
                    id: Some(id.to_owned()),
                    offset,
                })
            }
            _ => None,
        };
        cursor.map_or(CursorLoad::Garbled, CursorLoad::Loaded)
    }

    /// Stores the cursor durably: written to `<path>.tmp`, `sync_all`ed,
    /// then renamed over `path`, so a crash leaves the old or the new
    /// cursor, never a torn one.
    pub fn store(&self, path: &Path) -> std::io::Result<()> {
        let text = match &self.id {
            Some(id) => format!("{id} {}", self.offset),
            None => self.offset.to_string(),
        };
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }
}

/// Where a reader should resume, as decided by [`locate`].
#[derive(Debug, PartialEq, Eq)]
pub enum SpoolPosition {
    /// The reader has no cursor yet (`locate(spool, None)`, i.e.
    /// [`CursorLoad::Missing`]): begin `<spool>` at 0. Not a loss.
    Start,
    /// Still `<spool>`: keep reading it from `offset`.
    Current { offset: u64 },
    /// The cursor's file was rotated to `<spool>.1`: finish it from
    /// `offset`, then start `<spool>` at 0.
    Rotated { offset: u64 },
    /// The cursor's file is gone (the reader fell more than one rotation
    /// behind, or the files were removed or truncated): its unread tail is
    /// lost. Count and log it, then begin `<spool>` at 0.
    Lost,
}

/// Finds the file `cursor` refers to; `None` (no cursor yet) is always
/// `Start`. Otherwise ids are compared with [`read_spool_id`], and
/// `None == None` matches (legacy files):
/// 1. `<spool>` exists, is non-empty and its id matches → `Current`;
/// 2. `<spool>.1` exists and its id matches → `Rotated`;
/// 3. `<spool>` is missing or empty, the cursor has no id and offset 0 →
///    `Current { offset: 0 }` (a legacy reader that has read nothing);
/// 4. otherwise → `Lost`, including a legacy cursor with offset > 0 whose
///    file is now missing or empty and is not `.1` (the bytes it pointed
///    past are gone).
///
/// The Agent renames `<spool>` to `.1` and then renames a ready-made,
/// headered file into `<spool>`, so between the two `<spool>` is missing.
/// Step 3 comes after step 2, which sends a legacy cursor to a legacy `.1`
/// in that window instead of losing its tail.
pub fn locate(spool: &Path, cursor: Option<&SpoolCursor>) -> std::io::Result<SpoolPosition> {
    let Some(cursor) = cursor else {
        return Ok(SpoolPosition::Start);
    };
    let offset = cursor.offset;
    let current_has_content = match std::fs::metadata(spool) {
        Ok(meta) => meta.len() > 0,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e),
    };
    let current_id = read_spool_id(spool)?;
    if current_has_content && cursor.id == current_id {
        return Ok(SpoolPosition::Current { offset });
    }
    let rotated = rotated_path(spool);
    if rotated.exists() && cursor.id == read_spool_id(&rotated)? {
        return Ok(SpoolPosition::Rotated { offset });
    }
    if !current_has_content && cursor.id.is_none() && offset == 0 {
        return Ok(SpoolPosition::Current { offset: 0 });
    }
    Ok(SpoolPosition::Lost)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID_A: &str = "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
    const ID_B: &str = "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c";
    const EVENT: &str = "{\"event_id\":\"x\"}\n";

    fn write(path: &Path, header: Option<&str>, events: usize) {
        let mut text = header.map(header_line).unwrap_or_default();
        for _ in 0..events {
            text.push_str(EVENT);
        }
        std::fs::write(path, text).unwrap();
    }

    fn cursor(id: Option<&str>, offset: u64) -> SpoolCursor {
        SpoolCursor {
            id: id.map(str::to_owned),
            offset,
        }
    }

    #[test]
    fn header_round_trips() {
        let line = header_line(ID_A);
        assert_eq!(line, format!("{{\"osiris_spool\":\"{ID_A}\"}}\n"));
        assert!(is_header_line(line.as_bytes()));
        assert!(is_header_line(line.trim_end().as_bytes()));
        assert!(!is_header_line(EVENT.as_bytes()));
        assert!(!is_header_line(b"{\"osiris_spool\":\"\"}\n"));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.ndjson");
        write(&path, Some(ID_A), 2);
        assert_eq!(read_spool_id(&path).unwrap().as_deref(), Some(ID_A));
    }

    #[test]
    fn legacy_file_has_no_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.ndjson");
        assert_eq!(read_spool_id(&path).unwrap(), None, "missing file");
        std::fs::write(&path, "").unwrap();
        assert_eq!(read_spool_id(&path).unwrap(), None, "empty file");
        write(&path, None, 3);
        assert_eq!(read_spool_id(&path).unwrap(), None, "legacy file");
        assert_eq!(
            rotated_path(&path),
            dir.path().join("spool.ndjson.1"),
            "rotated name"
        );
    }

    fn loaded(path: &Path) -> SpoolCursor {
        match SpoolCursor::load(path) {
            CursorLoad::Loaded(cursor) => cursor,
            other => panic!("expected a loaded cursor, got {other:?}"),
        }
    }

    #[test]
    fn cursor_store_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.offset");
        let with_id = cursor(Some(ID_A), 12345);
        with_id.store(&path).unwrap();
        assert_eq!(loaded(&path), with_id);
        let legacy = cursor(None, 77);
        legacy.store(&path).unwrap();
        assert_eq!(loaded(&path), legacy);
        assert!(!dir.path().join("spool.offset.tmp").exists());
    }

    #[test]
    fn cursor_loads_legacy_bare_offset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.offset");
        std::fs::write(&path, "4096").unwrap();
        assert_eq!(loaded(&path), cursor(None, 4096));
        // A legacy "0" is a real position (offset 0 of a legacy file), not
        // "no cursor".
        std::fs::write(&path, "0").unwrap();
        assert_eq!(loaded(&path), cursor(None, 0));
    }

    #[test]
    fn cursor_missing_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.offset");
        assert_eq!(SpoolCursor::load(&path), CursorLoad::Missing);
    }

    #[test]
    fn cursor_garbled_is_garbled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.offset");
        for garbled in ["", "abc", "id 12 extra", "id notanumber", "-5", "a\"b 3"] {
            std::fs::write(&path, garbled).unwrap();
            assert_eq!(SpoolCursor::load(&path), CursorLoad::Garbled, "{garbled:?}");
        }
        // Unreadable (here: a directory where the file should be).
        let dir_path = dir.path().join("dir.offset");
        std::fs::create_dir(&dir_path).unwrap();
        assert_eq!(SpoolCursor::load(&dir_path), CursorLoad::Garbled);
    }

    #[test]
    fn no_cursor_is_start() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        assert_eq!(
            locate(&spool, None).unwrap(),
            SpoolPosition::Start,
            "no spool"
        );
        write(&spool, Some(ID_A), 2);
        write(&rotated_path(&spool), Some(ID_B), 2);
        assert_eq!(
            locate(&spool, None).unwrap(),
            SpoolPosition::Start,
            "headered"
        );
        write(&spool, None, 2);
        assert_eq!(
            locate(&spool, None).unwrap(),
            SpoolPosition::Start,
            "legacy"
        );
    }

    #[test]
    fn locate_current_when_ids_match() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        write(&spool, Some(ID_A), 2);
        write(&rotated_path(&spool), Some(ID_B), 2);
        assert_eq!(
            locate(&spool, Some(&cursor(Some(ID_A), 70))).unwrap(),
            SpoolPosition::Current { offset: 70 }
        );
    }

    #[test]
    fn locate_rotated_when_cursor_matches_dot1() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        write(&spool, Some(ID_B), 1);
        write(&rotated_path(&spool), Some(ID_A), 2);
        assert_eq!(
            locate(&spool, Some(&cursor(Some(ID_A), 70))).unwrap(),
            SpoolPosition::Rotated { offset: 70 }
        );
        // Between the Agent's two renames the current file is missing.
        std::fs::remove_file(&spool).unwrap();
        assert_eq!(
            locate(&spool, Some(&cursor(Some(ID_A), 70))).unwrap(),
            SpoolPosition::Rotated { offset: 70 }
        );
    }

    #[test]
    fn locate_lost_when_neither_matches() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        write(&spool, Some(ID_B), 1);
        assert_eq!(
            locate(&spool, Some(&cursor(Some(ID_A), 70))).unwrap(),
            SpoolPosition::Lost,
            "no .1"
        );
        write(
            &rotated_path(&spool),
            Some("0193a1b2-0000-7000-8000-000000000000"),
            1,
        );
        assert_eq!(
            locate(&spool, Some(&cursor(Some(ID_A), 70))).unwrap(),
            SpoolPosition::Lost,
            ".1 is a newer file"
        );
        assert_eq!(
            locate(&spool, Some(&cursor(None, 70))).unwrap(),
            SpoolPosition::Lost,
            "legacy cursor, both files have headers"
        );
    }

    #[test]
    fn legacy_cursor_on_legacy_file_is_current() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        write(&spool, None, 3);
        assert_eq!(
            locate(&spool, Some(&cursor(None, 34))).unwrap(),
            SpoolPosition::Current { offset: 34 }
        );
        // A legacy reader that has read nothing, on a missing spool.
        std::fs::remove_file(&spool).unwrap();
        assert_eq!(
            locate(&spool, Some(&cursor(None, 0))).unwrap(),
            SpoolPosition::Current { offset: 0 }
        );
    }

    #[test]
    fn legacy_cursor_past_a_missing_or_empty_spool_is_lost() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        assert_eq!(
            locate(&spool, Some(&cursor(None, 34))).unwrap(),
            SpoolPosition::Lost,
            "missing"
        );
        std::fs::write(&spool, "").unwrap();
        assert_eq!(
            locate(&spool, Some(&cursor(None, 34))).unwrap(),
            SpoolPosition::Lost,
            "empty"
        );
    }

    #[test]
    fn legacy_cursor_after_first_rotation_is_rotated() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.ndjson");
        write(&spool, Some(ID_A), 1);
        write(&rotated_path(&spool), None, 3);
        assert_eq!(
            locate(&spool, Some(&cursor(None, 34))).unwrap(),
            SpoolPosition::Rotated { offset: 34 }
        );
        // Same between the Agent's two renames (current missing).
        std::fs::remove_file(&spool).unwrap();
        assert_eq!(
            locate(&spool, Some(&cursor(None, 34))).unwrap(),
            SpoolPosition::Rotated { offset: 34 }
        );
    }
}
