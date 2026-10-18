//! Loader for the process BPF object (`<object_dir>/process.bpf.o`).
//!
//! [`ProcessProgram::load`] reads the object and its `.sha256` sidecar once,
//! checks the digest ([`verify_object`]), reads the object's
//! `schema_version` global out of the ELF before anything reaches the kernel,
//! and only then hands the *same verified bytes* to `aya` — the file is never
//! re-read, so it cannot be swapped between check and load. `SELF_TGID[0]` is
//! set before either tracepoint is attached, so the agent never sees its own
//! exec/exit events.
//!
//! The schema read is a small bounds-checked ELF64 symbol lookup
//! ([`object_schema_version`]), OS-neutral and unit-tested. `aya` does not
//! expose the parsed object's globals, and Global Constraint #1 forbids
//! adding `object`/`aya-obj` as direct dependencies.

use std::path::{Path, PathBuf};

use crate::integrity::{verify_object, IntegrityError};
use crate::record::SCHEMA_VERSION;

/// Object file name inside the configured object directory.
pub const OBJECT_FILE: &str = "process.bpf.o";
/// Integrity sidecar file name (lowercase hex SHA-256 of [`OBJECT_FILE`]).
pub const SIDECAR_FILE: &str = "process.bpf.o.sha256";
/// Name of the `.rodata` global carrying the object's record schema version.
pub const SCHEMA_SYMBOL: &str = "schema_version";

/// Why the process program could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The object or its sidecar is absent (or unreadable).
    #[error("bpf object file missing: {}", .0.display())]
    MissingObject(PathBuf),
    /// The object does not match its sidecar digest.
    #[error("bpf object integrity check failed: {0}")]
    Integrity(#[from] IntegrityError),
    /// The object was built for a different record schema.
    #[error("bpf object schema version {object} does not match expected {expected}")]
    SchemaMismatch { object: u32, expected: u32 },
    /// Parsing, verifying or loading the object failed.
    #[error("bpf load failed: {0}")]
    Load(String),
    /// Attaching a program failed.
    #[error("bpf attach failed: {0}")]
    Attach(String),
}

/// The loaded and attached process exec/exit programs plus their maps.
///
/// Dropping it detaches both tracepoints and closes every map.
pub struct ProcessProgram {
    #[cfg(target_os = "linux")]
    pub(crate) inner: linux::Inner,
    /// Off Linux a program can never be loaded, so the type is uninhabited.
    #[cfg(not(target_os = "linux"))]
    pub(crate) never: std::convert::Infallible,
}

impl ProcessProgram {
    /// Verify, schema-check and load `<object_dir>/process.bpf.o`, set
    /// `SELF_TGID[0] = self_tgid`, then attach `handle_exec` and
    /// `handle_exit`.
    pub fn load(object_dir: &Path, self_tgid: u32) -> Result<Self, LoadError> {
        let object_path = object_dir.join(OBJECT_FILE);
        check_regular_file(&object_path)?;
        #[cfg(target_os = "linux")]
        {
            let bytes = read_verified(object_dir, &object_path)?;
            Ok(Self {
                inner: linux::Inner::load(&bytes, self_tgid)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self_tgid;
            Err(LoadError::Load("eBPF requires Linux".to_string()))
        }
    }

    /// Ring-buffer reservations the BPF side failed (sum over CPUs of
    /// `DROPS[0]`). Returns 0 if the map cannot be read.
    pub fn drops(&self) -> u64 {
        self.drop_counter().get()
    }

    /// A shareable handle on the `DROPS` map that stays usable after the
    /// program has been moved into [`crate::spawn_reader`].
    pub fn drop_counter(&self) -> DropCounter {
        #[cfg(target_os = "linux")]
        {
            DropCounter {
                map: std::sync::Arc::clone(&self.inner.drops),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            match self.never {}
        }
    }
}

/// Cloneable, thread-safe reader of the BPF-side drop counter (`DROPS[0]`).
#[derive(Clone)]
pub struct DropCounter {
    #[cfg(target_os = "linux")]
    map: std::sync::Arc<aya::maps::PerCpuArray<aya::maps::MapData, u64>>,
}

impl DropCounter {
    /// Sum over CPUs of `DROPS[0]` (saturating); 0 if the map cannot be read.
    /// Off Linux there is no map and it is always 0.
    pub fn get(&self) -> u64 {
        #[cfg(target_os = "linux")]
        {
            self.map
                .get(&0, 0)
                .map(|per_cpu| per_cpu.iter().fold(0u64, |acc, v| acc.saturating_add(*v)))
                .unwrap_or(0)
        }
        #[cfg(not(target_os = "linux"))]
        {
            0
        }
    }
}

impl std::fmt::Debug for DropCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DropCounter").finish_non_exhaustive()
    }
}

/// Map an I/O error on `path`: only `NotFound` means the file is missing;
/// anything else (permission denied, is a directory, …) names the cause.
fn io_error(path: &Path, err: std::io::Error) -> LoadError {
    if err.kind() == std::io::ErrorKind::NotFound {
        LoadError::MissingObject(path.to_path_buf())
    } else {
        LoadError::Load(format!("cannot read {}: {err}", path.display()))
    }
}

/// `path` must exist and be a regular file (checked before touching aya).
fn check_regular_file(path: &Path) -> Result<(), LoadError> {
    let meta = std::fs::metadata(path).map_err(|e| io_error(path, e))?;
    if meta.is_file() {
        Ok(())
    } else {
        Err(LoadError::Load(format!(
            "cannot read {}: not a regular file",
            path.display()
        )))
    }
}

/// Read the object and sidecar, verify the digest and the schema version,
/// and return the verified object bytes.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn read_verified(object_dir: &Path, object_path: &Path) -> Result<Vec<u8>, LoadError> {
    let bytes = std::fs::read(object_path).map_err(|e| io_error(object_path, e))?;
    let sidecar_path = object_dir.join(SIDECAR_FILE);
    let sidecar = std::fs::read(&sidecar_path).map_err(|e| io_error(&sidecar_path, e))?;
    let sidecar = String::from_utf8(sidecar).map_err(|_| {
        LoadError::Load(format!(
            "cannot read {}: not valid UTF-8",
            sidecar_path.display()
        ))
    })?;
    verify_object(&bytes, &sidecar)?;
    check_schema(&bytes)?;
    Ok(bytes)
}

/// Compare the object's `schema_version` global with [`SCHEMA_VERSION`].
fn check_schema(object: &[u8]) -> Result<(), LoadError> {
    let found = object_schema_version(object).ok_or_else(|| {
        LoadError::Load(format!(
            "bpf object has no readable `{SCHEMA_SYMBOL}` global"
        ))
    })?;
    if found != SCHEMA_VERSION {
        return Err(LoadError::SchemaMismatch {
            object: found,
            expected: SCHEMA_VERSION,
        });
    }
    Ok(())
}

/// Read the 4-byte initial value of the `schema_version` symbol from an ELF64
/// relocatable object (either endianness). Returns None for anything that is
/// not a well-formed ELF64 with such a symbol in a `.rodata*` section; every
/// offset is bounds-checked, so arbitrary bytes never panic.
pub fn object_schema_version(elf: &[u8]) -> Option<u32> {
    let rd = Reader::new(elf)?;
    let shoff = usize::try_from(rd.u64(0x28)?).ok()?;
    let shentsize = usize::from(rd.u16(0x3a)?);
    let shnum = usize::from(rd.u16(0x3c)?);
    let shstrndx = usize::from(rd.u16(0x3e)?);
    if shentsize < 64 {
        return None;
    }
    let section = |i: usize| -> Option<Section> {
        if i >= shnum {
            return None;
        }
        let base = shoff.checked_add(i.checked_mul(shentsize)?)?;
        Some(Section {
            name: rd.u32(base)?,
            kind: rd.u32(base + 4)?,
            offset: usize::try_from(rd.u64(base + 24)?).ok()?,
            size: usize::try_from(rd.u64(base + 32)?).ok()?,
            link: usize::try_from(rd.u32(base + 40)?).ok()?,
        })
    };
    let shstr = section(shstrndx)?;
    let symtab = (0..shnum).find_map(|i| section(i).filter(|s| s.kind == SHT_SYMTAB))?;
    let strtab = section(symtab.link)?;
    let symbols = elf.get(symtab.offset..symtab.offset.checked_add(symtab.size)?)?;
    for sym in symbols.as_chunks::<24>().0 {
        let srd = Reader {
            bytes: sym.as_slice(),
            le: rd.le,
        };
        if rd.cstr(strtab, usize::try_from(srd.u32(0)?).ok()?) != Some(SCHEMA_SYMBOL.as_bytes()) {
            continue;
        }
        let target = section(usize::from(srd.u16(6)?))?;
        let target_name = rd.cstr(shstr, usize::try_from(target.name).ok()?)?;
        if !target_name.starts_with(b".rodata") || target.kind != SHT_PROGBITS {
            return None;
        }
        let value = usize::try_from(srd.u64(8)?).ok()?;
        if value.checked_add(4)? > target.size {
            return None;
        }
        return rd.u32(target.offset.checked_add(value)?);
    }
    None
}

const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;

#[derive(Clone, Copy)]
struct Section {
    name: u32,
    kind: u32,
    offset: usize,
    size: usize,
    link: usize,
}

/// Bounds-checked fixed-endian reads over a byte slice.
struct Reader<'a> {
    bytes: &'a [u8],
    le: bool,
}

impl<'a> Reader<'a> {
    /// Accept only ELF64 (`EI_CLASS` 2) with a known `EI_DATA`.
    fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.get(0..4)? != b"\x7fELF" || *bytes.get(4)? != 2 {
            return None;
        }
        let le = match *bytes.get(5)? {
            1 => true,
            2 => false,
            _ => return None,
        };
        Some(Self { bytes, le })
    }

    fn array<const N: usize>(&self, at: usize) -> Option<[u8; N]> {
        self.bytes.get(at..at.checked_add(N)?)?.try_into().ok()
    }

    fn u16(&self, at: usize) -> Option<u16> {
        let b = self.array(at)?;
        Some(if self.le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }

    fn u32(&self, at: usize) -> Option<u32> {
        let b = self.array(at)?;
        Some(if self.le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }

    fn u64(&self, at: usize) -> Option<u64> {
        let b = self.array(at)?;
        Some(if self.le {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    }

    /// The NUL-terminated string at `index` within string-table `table`.
    fn cstr(&self, table: Section, index: usize) -> Option<&'a [u8]> {
        let end = table.offset.checked_add(table.size)?;
        let s = self.bytes.get(table.offset.checked_add(index)?..end)?;
        let nul = s.iter().position(|&b| b == 0)?;
        Some(&s[..nul])
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::sync::Arc;

    use aya::maps::{Array, MapData, PerCpuArray, RingBuf};
    use aya::programs::TracePoint;
    use aya::{Ebpf, EbpfLoader};

    use super::LoadError;

    /// Programs (with their attach links) and the two maps the reader needs.
    pub(crate) struct Inner {
        pub(crate) events: RingBuf<MapData>,
        pub(crate) drops: Arc<PerCpuArray<MapData, u64>>,
        /// Owns the programs and links; kept alive for the attachment's life.
        _ebpf: Ebpf,
    }

    impl Inner {
        pub(crate) fn load(bytes: &[u8], self_tgid: u32) -> Result<Self, LoadError> {
            let mut ebpf = EbpfLoader::new()
                .load(bytes)
                .map_err(|e| LoadError::Load(e.to_string()))?;

            let self_map = ebpf
                .map_mut("SELF_TGID")
                .ok_or_else(|| LoadError::Load("map SELF_TGID not found".to_string()))?;
            let mut self_tgid_map: Array<_, u32> = Array::try_from(self_map)
                .map_err(|e| LoadError::Load(format!("SELF_TGID: {e}")))?;
            self_tgid_map
                .set(0, self_tgid, 0)
                .map_err(|e| LoadError::Load(format!("SELF_TGID: {e}")))?;

            for (prog, event) in [
                ("handle_exec", "sched_process_exec"),
                ("handle_exit", "sched_process_exit"),
            ] {
                let tp: &mut TracePoint = ebpf
                    .program_mut(prog)
                    .ok_or_else(|| LoadError::Load(format!("program {prog} not found")))?
                    .try_into()
                    .map_err(|e| LoadError::Load(format!("{prog}: {e}")))?;
                tp.load()
                    .map_err(|e| LoadError::Load(format!("{prog}: {e}")))?;
                tp.attach("sched", event)
                    .map_err(|e| LoadError::Attach(format!("{prog} -> sched/{event}: {e}")))?;
            }

            let events = ebpf
                .take_map("EVENTS")
                .ok_or_else(|| LoadError::Load("map EVENTS not found".to_string()))?;
            let events =
                RingBuf::try_from(events).map_err(|e| LoadError::Load(format!("EVENTS: {e}")))?;
            let drops = ebpf
                .take_map("DROPS")
                .ok_or_else(|| LoadError::Load("map DROPS not found".to_string()))?;
            let drops =
                PerCpuArray::try_from(drops).map_err(|e| LoadError::Load(format!("DROPS: {e}")))?;

            Ok(Self {
                events,
                drops: Arc::new(drops),
                _ebpf: ebpf,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_reports_missing_object() {
        let dir = tempfile::tempdir().unwrap();
        let err = ProcessProgram::load(dir.path(), 1)
            .err()
            .expect("load must fail");
        assert!(matches!(err, LoadError::MissingObject(_)), "{err:?}");
    }

    #[test]
    fn drop_counter_is_shareable() {
        fn assert_shareable<T: Clone + Send + Sync + 'static>() {}
        assert_shareable::<DropCounter>();
    }

    #[test]
    fn only_not_found_is_missing_object() {
        // Object path is a directory: a distinct error naming the cause.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(OBJECT_FILE)).unwrap();
        let err = ProcessProgram::load(dir.path(), 1)
            .err()
            .expect("load must fail");
        assert!(
            matches!(&err, LoadError::Load(m) if m.contains(OBJECT_FILE) && m.contains("not a regular file")),
            "{err:?}"
        );

        // Missing sidecar: NotFound, so MissingObject naming the sidecar.
        let dir = tempfile::tempdir().unwrap();
        let obj = dir.path().join(OBJECT_FILE);
        std::fs::write(&obj, b"obj").unwrap();
        let err = read_verified(dir.path(), &obj).unwrap_err();
        assert!(
            matches!(&err, LoadError::MissingObject(p) if p.ends_with(SIDECAR_FILE)),
            "{err:?}"
        );

        // Non-UTF-8 sidecar: distinct error naming the sidecar.
        std::fs::write(dir.path().join(SIDECAR_FILE), [0xff, 0xfe, 0x00]).unwrap();
        let err = read_verified(dir.path(), &obj).unwrap_err();
        assert!(
            matches!(&err, LoadError::Load(m) if m.contains(SIDECAR_FILE) && m.contains("UTF-8")),
            "{err:?}"
        );

        // Sidecar is a directory: not reported as missing.
        let dir = tempfile::tempdir().unwrap();
        let obj = dir.path().join(OBJECT_FILE);
        std::fs::write(&obj, b"obj").unwrap();
        std::fs::create_dir(dir.path().join(SIDECAR_FILE)).unwrap();
        let err = read_verified(dir.path(), &obj).unwrap_err();
        assert!(
            matches!(&err, LoadError::Load(m) if m.contains(SIDECAR_FILE)),
            "{err:?}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn load_off_linux_reports_linux_required() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(OBJECT_FILE), b"x").unwrap();
        let err = ProcessProgram::load(dir.path(), 1)
            .err()
            .expect("load must fail");
        assert!(
            matches!(&err, LoadError::Load(m) if m == "eBPF requires Linux"),
            "{err:?}"
        );
    }

    /// Minimal ELF64 relocatable: null, `rodata_name` (holding `value` at
    /// offset 4, after 4 bytes of other data), .symtab, .strtab, .shstrtab.
    fn elf(le: bool, rodata_name: &str, sym_name: &str, value: u32) -> Vec<u8> {
        let w16 = |v: u16| if le { v.to_le_bytes() } else { v.to_be_bytes() };
        let w32 = |v: u32| if le { v.to_le_bytes() } else { v.to_be_bytes() };
        let w64 = |v: u64| if le { v.to_le_bytes() } else { v.to_be_bytes() };

        let mut rodata = vec![0xAA; 4];
        rodata.extend_from_slice(&w32(value));
        let strtab = format!("\0other\0{sym_name}\0").into_bytes();
        let sym_name_off = 7u32;
        let shstrtab = format!("\0{rodata_name}\0.symtab\0.strtab\0.shstrtab\0").into_bytes();
        let n_rodata = 1u32;
        let n_symtab = n_rodata + rodata_name.len() as u32 + 1;
        let n_strtab = n_symtab + 8;
        let n_shstrtab = n_strtab + 8;

        let mut symtab = vec![0u8; 24]; // null symbol
        for (name, value_off) in [(1u32, 0u64), (sym_name_off, 4u64)] {
            symtab.extend_from_slice(&w32(name));
            symtab.extend_from_slice(&[0x11, 0]); // GLOBAL OBJECT
            symtab.extend_from_slice(&w16(1)); // section 1 (rodata)
            symtab.extend_from_slice(&w64(value_off));
            symtab.extend_from_slice(&w64(4));
        }

        let mut out = vec![0u8; 64];
        let mut place = |data: &[u8]| {
            let off = out.len() as u64;
            out.extend_from_slice(data);
            off
        };
        let o_rodata = place(&rodata);
        let o_symtab = place(&symtab);
        let o_strtab = place(&strtab);
        let o_shstrtab = place(&shstrtab);
        let shoff = out.len() as u64;
        let mut sh = |name: u32, kind: u32, off: u64, size: u64, link: u32, entsize: u64| {
            out.extend_from_slice(&w32(name));
            out.extend_from_slice(&w32(kind));
            out.extend_from_slice(&w64(0));
            out.extend_from_slice(&w64(0));
            out.extend_from_slice(&w64(off));
            out.extend_from_slice(&w64(size));
            out.extend_from_slice(&w32(link));
            out.extend_from_slice(&w32(0));
            out.extend_from_slice(&w64(8));
            out.extend_from_slice(&w64(entsize));
        };
        sh(0, 0, 0, 0, 0, 0);
        sh(n_rodata, 1, o_rodata, rodata.len() as u64, 0, 0);
        sh(n_symtab, 2, o_symtab, symtab.len() as u64, 3, 24);
        sh(n_strtab, 3, o_strtab, strtab.len() as u64, 0, 0);
        sh(n_shstrtab, 3, o_shstrtab, shstrtab.len() as u64, 0, 0);

        out[0..4].copy_from_slice(b"\x7fELF");
        out[4] = 2;
        out[5] = if le { 1 } else { 2 };
        out[6] = 1;
        out[0x28..0x30].copy_from_slice(&w64(shoff));
        out[0x3a..0x3c].copy_from_slice(&w16(64));
        out[0x3c..0x3e].copy_from_slice(&w16(5));
        out[0x3e..0x40].copy_from_slice(&w16(4));
        out
    }

    #[test]
    fn schema_version_read_from_object() {
        assert_eq!(
            object_schema_version(&elf(true, ".rodata", "schema_version", 1)),
            Some(1)
        );
        assert_eq!(
            object_schema_version(&elf(false, ".rodata", "schema_version", 7)),
            Some(7)
        );
        assert_eq!(
            object_schema_version(&elf(true, ".data", "schema_version", 1)),
            None
        );
        assert_eq!(
            object_schema_version(&elf(true, ".rodata", "other_sym", 1)),
            None
        );
        assert_eq!(object_schema_version(b"not an elf"), None);
        assert_eq!(object_schema_version(&[]), None);
        // Every truncation of a valid object is rejected without panicking.
        let good = elf(true, ".rodata", "schema_version", 1);
        for len in 0..good.len() {
            let _ = object_schema_version(&good[..len]);
        }
    }

    #[test]
    fn schema_check_reports_mismatch() {
        assert!(check_schema(&elf(true, ".rodata", "schema_version", SCHEMA_VERSION)).is_ok());
        assert!(matches!(
            check_schema(&elf(true, ".rodata", "schema_version", 9)),
            Err(LoadError::SchemaMismatch {
                object: 9,
                expected: SCHEMA_VERSION
            })
        ));
        assert!(matches!(check_schema(b"junk"), Err(LoadError::Load(_))));
    }
}
