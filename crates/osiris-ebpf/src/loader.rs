//! Spec-driven loader for one BPF object (`<object_dir>/<spec.object_file>`).
//!
//! An [`ObjectSpec`] names the object file, the record schema version it
//! must carry and the tracepoints to attach. [`LoadedObject::load`] reads
//! the object and its `.sha256` sidecar ([`sidecar_name`]) once, checks the
//! digest ([`verify_object`]), reads the object's `schema_version` global
//! out of the ELF and compares it with `spec.expected_schema` before
//! anything reaches the kernel, and only then hands the *same verified
//! bytes* to `aya` — the file is never re-read, so it cannot be swapped
//! between check and load. `SELF_TGID[0]` is set before any tracepoint is
//! attached, so the agent never sees its own events.
//!
//! Every object uses the same map names: `EVENTS` (ring buffer), `DROPS`
//! (per-CPU reservation-failure counter) and `SELF_TGID` (one-entry array).
//!
//! The schema read is a small bounds-checked ELF64 symbol lookup
//! ([`object_schema_version`]), OS-neutral and unit-tested. `aya` does not
//! expose the parsed object's globals, and Global Constraint #1 forbids
//! adding `object`/`aya-obj` as direct dependencies.

use std::path::{Path, PathBuf};

use crate::integrity::{verify_object, IntegrityError};
use crate::net_record::NET_SCHEMA_VERSION;
use crate::record::PROCESS_SCHEMA_VERSION;

/// Name of the `.rodata` global carrying the object's record schema version.
pub const SCHEMA_SYMBOL: &str = "schema_version";

/// What one BPF object is: its file, its record schema and its programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectSpec {
    /// File name inside the configured object directory.
    pub object_file: &'static str,
    /// The `schema_version` global the object must carry.
    pub expected_schema: u32,
    /// (program name, tracepoint category, tracepoint name)
    pub tracepoints: &'static [(&'static str, &'static str, &'static str)],
}

/// The process exec/exit object.
pub const PROCESS_OBJECT: ObjectSpec = ObjectSpec {
    object_file: "process.bpf.o",
    expected_schema: PROCESS_SCHEMA_VERSION,
    tracepoints: &[
        ("handle_exec", "sched", "sched_process_exec"),
        ("handle_exit", "sched", "sched_process_exit"),
    ],
};

/// The TCP connect/accept/close object.
pub const NET_OBJECT: ObjectSpec = ObjectSpec {
    object_file: "net.bpf.o",
    expected_schema: NET_SCHEMA_VERSION,
    tracepoints: &[
        ("handle_state", "sock", "inet_sock_set_state"),
        ("handle_accept4_exit", "syscalls", "sys_exit_accept4"),
        ("handle_accept_exit", "syscalls", "sys_exit_accept"),
    ],
};

/// Integrity sidecar file name for `object_file`: `<object_file>.sha256`
/// (lowercase hex SHA-256 of the object, first token).
pub fn sidecar_name(object_file: &str) -> String {
    format!("{object_file}.sha256")
}

/// Where to find the BPF objects, and which tgid (the agent's own) the
/// in-kernel self-filter drops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfSettings {
    pub object_dir: PathBuf,
    pub self_tgid: u32,
}

/// Why a BPF object could not be loaded. Every message names the object
/// file it concerns.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The object or its sidecar is absent (the full path is shown).
    #[error("bpf object file missing: {}", .0.display())]
    MissingObject(PathBuf),
    /// The object does not match its sidecar digest.
    #[error("bpf object {file} integrity check failed: {source}")]
    Integrity {
        file: String,
        source: IntegrityError,
    },
    /// The object was built for a different record schema.
    #[error("bpf object {file} schema version {object} does not match expected {expected}")]
    SchemaMismatch {
        file: String,
        object: u32,
        expected: u32,
    },
    /// Parsing, verifying or loading the object failed (the message starts
    /// with, or contains, the object file name).
    #[error("bpf load failed: {0}")]
    Load(String),
    /// Attaching a program failed: `<object_file>: <prog>: <err>`.
    #[error("bpf attach failed: {0}")]
    Attach(String),
}

/// One loaded BPF object: its attached programs plus the `EVENTS` ring
/// buffer and `DROPS` counter.
///
/// Dropping it detaches every tracepoint and closes every map.
pub struct LoadedObject {
    #[cfg(target_os = "linux")]
    pub(crate) inner: linux::Inner,
    /// Off Linux an object can never be loaded, so the type is uninhabited.
    #[cfg(not(target_os = "linux"))]
    pub(crate) never: std::convert::Infallible,
}

impl LoadedObject {
    /// Verify, schema-check (against `spec.expected_schema`) and load
    /// `<object_dir>/<spec.object_file>`, set `SELF_TGID[0] = self_tgid`,
    /// then attach every tracepoint in `spec.tracepoints`, in order.
    pub fn load(object_dir: &Path, spec: &ObjectSpec, self_tgid: u32) -> Result<Self, LoadError> {
        let object_path = object_dir.join(spec.object_file);
        check_regular_file(&object_path)?;
        #[cfg(target_os = "linux")]
        {
            let bytes = read_verified(object_dir, spec)?;
            Ok(Self {
                inner: linux::Inner::load(&bytes, spec, self_tgid)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self_tgid;
            Err(LoadError::Load("eBPF requires Linux".to_string()))
        }
    }

    /// A shareable handle on the `DROPS` map that stays usable after the
    /// object has been moved into [`crate::spawn_reader`].
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

/// Read the object and its sidecar, verify the digest and the schema
/// version, and return the verified object bytes.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn read_verified(object_dir: &Path, spec: &ObjectSpec) -> Result<Vec<u8>, LoadError> {
    let object_path = object_dir.join(spec.object_file);
    let bytes = std::fs::read(&object_path).map_err(|e| io_error(&object_path, e))?;
    let sidecar_path = object_dir.join(sidecar_name(spec.object_file));
    let sidecar = std::fs::read(&sidecar_path).map_err(|e| io_error(&sidecar_path, e))?;
    let sidecar = String::from_utf8(sidecar).map_err(|_| {
        LoadError::Load(format!(
            "cannot read {}: not valid UTF-8",
            sidecar_path.display()
        ))
    })?;
    verify_object(&bytes, &sidecar).map_err(|source| LoadError::Integrity {
        file: spec.object_file.to_string(),
        source,
    })?;
    check_schema(&bytes, spec)?;
    Ok(bytes)
}

/// Compare the object's `schema_version` global with
/// `spec.expected_schema`.
fn check_schema(object: &[u8], spec: &ObjectSpec) -> Result<(), LoadError> {
    let found = object_schema_version(object).ok_or_else(|| {
        LoadError::Load(format!(
            "bpf object {} has no readable `{SCHEMA_SYMBOL}` global",
            spec.object_file
        ))
    })?;
    if found != spec.expected_schema {
        return Err(LoadError::SchemaMismatch {
            file: spec.object_file.to_string(),
            object: found,
            expected: spec.expected_schema,
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
        let at = |field: usize| base.checked_add(field);
        Some(Section {
            name: rd.u32(base)?,
            kind: rd.u32(at(4)?)?,
            offset: usize::try_from(rd.u64(at(24)?)?).ok()?,
            size: usize::try_from(rd.u64(at(32)?)?).ok()?,
            link: usize::try_from(rd.u32(at(40)?)?).ok()?,
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

    use super::{LoadError, ObjectSpec};

    /// Programs (with their attach links) and the two maps the reader needs.
    pub(crate) struct Inner {
        pub(crate) events: RingBuf<MapData>,
        pub(crate) drops: Arc<PerCpuArray<MapData, u64>>,
        /// Owns the programs and links; kept alive for the attachment's life.
        _ebpf: Ebpf,
    }

    impl Inner {
        pub(crate) fn load(
            bytes: &[u8],
            spec: &ObjectSpec,
            self_tgid: u32,
        ) -> Result<Self, LoadError> {
            let file = spec.object_file;
            let load_err = |what: &str| LoadError::Load(format!("{file}: {what}"));
            let mut ebpf = EbpfLoader::new()
                .load(bytes)
                .map_err(|e| load_err(&e.to_string()))?;

            let self_map = ebpf
                .map_mut("SELF_TGID")
                .ok_or_else(|| load_err("map SELF_TGID not found"))?;
            let mut self_tgid_map: Array<_, u32> =
                Array::try_from(self_map).map_err(|e| load_err(&format!("SELF_TGID: {e}")))?;
            self_tgid_map
                .set(0, self_tgid, 0)
                .map_err(|e| load_err(&format!("SELF_TGID: {e}")))?;

            for &(prog, category, name) in spec.tracepoints {
                let tp: &mut TracePoint = ebpf
                    .program_mut(prog)
                    .ok_or_else(|| load_err(&format!("program {prog} not found")))?
                    .try_into()
                    .map_err(|e| load_err(&format!("{prog}: {e}")))?;
                tp.load().map_err(|e| load_err(&format!("{prog}: {e}")))?;
                tp.attach(category, name).map_err(|e| {
                    LoadError::Attach(format!("{file}: {prog}: {category}/{name}: {e}"))
                })?;
            }

            let events = ebpf
                .take_map("EVENTS")
                .ok_or_else(|| load_err("map EVENTS not found"))?;
            let events =
                RingBuf::try_from(events).map_err(|e| load_err(&format!("EVENTS: {e}")))?;
            let drops = ebpf
                .take_map("DROPS")
                .ok_or_else(|| load_err("map DROPS not found"))?;
            let drops =
                PerCpuArray::try_from(drops).map_err(|e| load_err(&format!("DROPS: {e}")))?;

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

    const TEST_OBJECT: ObjectSpec = ObjectSpec {
        object_file: "x.bpf.o",
        expected_schema: 99,
        tracepoints: &[("handle_x", "sched", "sched_process_exec")],
    };

    /// The process object's sidecar, as 11b-1 named it.
    const PROCESS_SIDECAR: &str = "process.bpf.o.sha256";

    #[test]
    fn sidecar_name_appends_sha256() {
        assert_eq!(sidecar_name("net.bpf.o"), "net.bpf.o.sha256");
        assert_eq!(sidecar_name(PROCESS_OBJECT.object_file), PROCESS_SIDECAR);
    }

    /// The process object keeps 11b-1's file and its two tracepoints.
    #[test]
    fn process_object_spec_is_11b1s() {
        assert_eq!(PROCESS_OBJECT.object_file, "process.bpf.o");
        assert_eq!(PROCESS_OBJECT.expected_schema, PROCESS_SCHEMA_VERSION);
        assert_eq!(
            PROCESS_OBJECT.tracepoints,
            [
                ("handle_exec", "sched", "sched_process_exec"),
                ("handle_exit", "sched", "sched_process_exit"),
            ]
        );
    }

    /// The net object: its own file, schema 1 and the three hooks.
    #[test]
    fn net_object_spec_names() {
        assert_eq!(NET_OBJECT.object_file, "net.bpf.o");
        assert_eq!(NET_OBJECT.expected_schema, 1);
        assert_eq!(
            NET_OBJECT.tracepoints,
            [
                ("handle_state", "sock", "inet_sock_set_state"),
                ("handle_accept4_exit", "syscalls", "sys_exit_accept4"),
                ("handle_accept_exit", "syscalls", "sys_exit_accept"),
            ]
        );
    }

    #[test]
    fn load_reports_missing_object_with_its_file_name() {
        let dir = tempfile::tempdir().unwrap();
        let err = LoadedObject::load(dir.path(), &TEST_OBJECT, 1)
            .err()
            .expect("load must fail");
        assert!(
            matches!(&err, LoadError::MissingObject(p) if p.ends_with("x.bpf.o")),
            "{err:?}"
        );
    }

    #[test]
    fn load_rejects_schema_mismatch_against_spec() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let object = elf(true, ".rodata", "schema_version", 9);
        std::fs::write(dir.path().join("x.bpf.o"), &object).unwrap();
        std::fs::write(
            dir.path().join("x.bpf.o.sha256"),
            format!("{}  x.bpf.o\n", hex::encode(Sha256::digest(&object))),
        )
        .unwrap();
        let err = LoadedObject::load(dir.path(), &TEST_OBJECT, 1)
            .err()
            .expect("load must fail");
        #[cfg(target_os = "linux")]
        assert!(
            matches!(
                &err,
                LoadError::SchemaMismatch {
                    object: 9,
                    expected: 99,
                    ..
                }
            ),
            "{err:?}"
        );
        #[cfg(not(target_os = "linux"))]
        assert!(
            matches!(&err, LoadError::Load(m) if m.contains("eBPF requires Linux")),
            "{err:?}"
        );
    }

    #[test]
    fn load_reports_missing_object() {
        let dir = tempfile::tempdir().unwrap();
        let err = LoadedObject::load(dir.path(), &PROCESS_OBJECT, 1)
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
        std::fs::create_dir(dir.path().join(PROCESS_OBJECT.object_file)).unwrap();
        let err = LoadedObject::load(dir.path(), &PROCESS_OBJECT, 1)
            .err()
            .expect("load must fail");
        assert!(
            matches!(&err, LoadError::Load(m) if m.contains(PROCESS_OBJECT.object_file) && m.contains("not a regular file")),
            "{err:?}"
        );

        // Missing sidecar: NotFound, so MissingObject naming the sidecar.
        let dir = tempfile::tempdir().unwrap();
        let obj = dir.path().join(PROCESS_OBJECT.object_file);
        std::fs::write(&obj, b"obj").unwrap();
        let err = read_verified(dir.path(), &PROCESS_OBJECT).unwrap_err();
        assert!(
            matches!(&err, LoadError::MissingObject(p) if p.ends_with(PROCESS_SIDECAR)),
            "{err:?}"
        );

        // Non-UTF-8 sidecar: distinct error naming the sidecar.
        std::fs::write(dir.path().join(PROCESS_SIDECAR), [0xff, 0xfe, 0x00]).unwrap();
        let err = read_verified(dir.path(), &PROCESS_OBJECT).unwrap_err();
        assert!(
            matches!(&err, LoadError::Load(m) if m.contains(PROCESS_SIDECAR) && m.contains("UTF-8")),
            "{err:?}"
        );

        // Sidecar is a directory: not reported as missing.
        let dir = tempfile::tempdir().unwrap();
        let obj = dir.path().join(PROCESS_OBJECT.object_file);
        std::fs::write(&obj, b"obj").unwrap();
        std::fs::create_dir(dir.path().join(PROCESS_SIDECAR)).unwrap();
        let err = read_verified(dir.path(), &PROCESS_OBJECT).unwrap_err();
        assert!(
            matches!(&err, LoadError::Load(m) if m.contains(PROCESS_SIDECAR)),
            "{err:?}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn load_off_linux_reports_linux_required() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(PROCESS_OBJECT.object_file), b"x").unwrap();
        let err = LoadedObject::load(dir.path(), &PROCESS_OBJECT, 1)
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

    /// A section-header offset near the top of the address space must be
    /// rejected, never overflow (debug builds would panic on `base + n`).
    #[test]
    fn huge_section_header_offset_is_rejected_without_panicking() {
        let good = elf(true, ".rodata", "schema_version", 1);
        for shoff in [u64::MAX, u64::MAX - 3, u64::MAX - 39, u64::MAX - 63] {
            for shstrndx in [0u16, 4] {
                let mut bad = good.clone();
                bad[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
                bad[0x3e..0x40].copy_from_slice(&shstrndx.to_le_bytes());
                assert_eq!(object_schema_version(&bad), None, "shoff {shoff:#x}");
            }
        }
    }

    #[test]
    fn integrity_error_names_the_object() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("process.bpf.o"), b"obj").unwrap();
        std::fs::write(dir.path().join(PROCESS_SIDECAR), "00".repeat(32)).unwrap();
        let err = read_verified(dir.path(), &PROCESS_OBJECT).unwrap_err();
        assert!(
            matches!(&err, LoadError::Integrity { file, .. } if file == "process.bpf.o"),
            "{err:?}"
        );
        assert!(err.to_string().contains("process.bpf.o"), "{err}");
    }

    #[test]
    fn schema_check_reports_mismatch() {
        let current = elf(true, ".rodata", "schema_version", PROCESS_SCHEMA_VERSION);
        assert!(check_schema(&current, &PROCESS_OBJECT).is_ok());
        let err =
            check_schema(&elf(true, ".rodata", "schema_version", 9), &PROCESS_OBJECT).unwrap_err();
        assert!(
            matches!(
                &err,
                LoadError::SchemaMismatch {
                    file,
                    object: 9,
                    expected: PROCESS_SCHEMA_VERSION
                } if file == "process.bpf.o"
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains("process.bpf.o"), "{err}");
        let err = check_schema(b"junk", &PROCESS_OBJECT).unwrap_err();
        assert!(
            matches!(&err, LoadError::Load(m) if m.contains("process.bpf.o")),
            "{err:?}"
        );
    }
}
