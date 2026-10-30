//! Real-kernel load of `fs.bpf.o` (Linux, root, `$OSIRIS_BPF_DIR`).
//!
//! Ignored by default: the real-Linux workflow runs these as root with
//! `--include-ignored --test-threads=1` after `tools/real-linux/setup.sh`
//! has built the objects into `$OSIRIS_BPF_DIR` (serially: the chroot test
//! changes the whole process's root for a moment). Every test name starts
//! with `fs_object_loads_and_attaches`, which the unprivileged unit-test
//! step skips. They prove the verifier accepts every fs program, that they
//! attach, that one watched create is staged at the LSM hook and emitted
//! at syscall exit with its path, pid and inode, that the agent's own
//! operations are filtered in the kernel, and that the ancestor walk sees
//! a watched directory past the task's root (chroot) and through a
//! detached mount without presenting a wrong absolute path.

#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use osiris_ebpf::{
    decode_fs, dev_from_user, dev_to_user, spawn_reader, FsEvent, FsKind, LoadedObject,
    ReaderError, FS_OBJECT,
};
use tokio_util::sync::CancellationToken;

const WAIT: Duration = Duration::from_secs(5);

/// Load fs.bpf.o with `self_tgid`, as root.
fn load(self_tgid: u32) -> LoadedObject {
    // SAFETY: geteuid() takes no arguments and cannot fail.
    assert_eq!(unsafe { libc::geteuid() }, 0, "must run as root");
    let bpf_dir = PathBuf::from(
        std::env::var_os("OSIRIS_BPF_DIR")
            .expect("OSIRIS_BPF_DIR is unset: build the objects with tools/ebpf/build.sh"),
    );
    match LoadedObject::load(&bpf_dir, &FS_OBJECT, self_tgid) {
        Ok(obj) => obj,
        Err(e) => {
            // Display keeps the verifier log's line breaks.
            eprintln!("{e}");
            panic!("loading fs.bpf.o failed (error above)");
        }
    }
}

/// A canonical temp dir, inserted into `obj`'s WATCH map.
fn watched_dir(obj: &mut LoadedObject) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = std::fs::canonicalize(dir.path()).expect("canonical temp dir");
    let meta = std::fs::metadata(&path).expect("stat temp dir");
    obj.insert_watch(dev_from_user(meta.dev()), meta.ino())
        .expect("insert watch");
    obj.set_watch_flags(0).expect("set watch flags");
    (dir, path)
}

/// The loaded object's events, read on the reader thread.
struct Events {
    rx: mpsc::Receiver<FsEvent>,
    cancel: CancellationToken,
    reader: JoinHandle<Result<(), ReaderError>>,
}

impl Events {
    fn start(obj: LoadedObject) -> Self {
        let (tx, rx) = mpsc::channel::<FsEvent>();
        let cancel = CancellationToken::new();
        let reader = spawn_reader(obj, decode_fs, cancel.clone(), move |r| {
            if let Ok(ev) = r {
                let _ = tx.send(ev);
            }
        })
        .expect("spawn reader");
        Self { rx, cancel, reader }
    }

    /// The first event matching `want` within `WAIT`, and every other
    /// event seen before it.
    fn wait_for(&self, want: impl Fn(&FsEvent) -> bool) -> (Option<FsEvent>, Vec<FsEvent>) {
        let deadline = Instant::now() + WAIT;
        let mut seen = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return (None, seen);
            }
            match self.rx.recv_timeout(left) {
                Ok(ev) if want(&ev) => return (Some(ev), seen),
                Ok(ev) => seen.push(ev),
                Err(_) => return (None, seen),
            }
        }
    }

    /// Every event arriving within `for_how_long`.
    fn drain(&self, for_how_long: Duration) -> Vec<FsEvent> {
        let deadline = Instant::now() + for_how_long;
        let mut seen = Vec::new();
        while let Ok(ev) = self
            .rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            seen.push(ev);
        }
        seen
    }

    /// Stop the reader and check it ended cleanly.
    fn stop(self) {
        self.cancel.cancel();
        let joined = self.reader.join();
        assert!(
            matches!(joined, Ok(Ok(()))),
            "reader ended badly: {joined:?}"
        );
    }
}

fn bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_encoded_bytes().to_vec()
}

/// `name=count` (or `name=n/a`) for each verified-instruction count.
fn insn_list(counts: &[(String, Option<u32>)]) -> String {
    counts
        .iter()
        .map(|(name, n)| match n {
            Some(n) => format!("{name}={n}"),
            None => format!("{name}=n/a"),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn run(cmd: &str, args: &[&OsStr]) {
    let status = Command::new(cmd).args(args).status().expect(cmd);
    assert!(status.success(), "{cmd} {args:?}: {status}");
}

#[test]
#[ignore = "needs root, a BPF-capable kernel and $OSIRIS_BPF_DIR (real-Linux workflow)"]
fn fs_object_loads_and_attaches() {
    // self_tgid 0: this test's own create must be seen.
    let mut obj = load(0);
    println!(
        "osiris-ebpf: fs skipped attach points: {:?}",
        obj.skipped_attach_points()
    );
    // The verifier's processed-instruction counts (kernel 5.16+): the
    // kprobes carry the walk; the tracepoints are small.
    let (kprobes, tracepoints): (Vec<_>, Vec<_>) = obj
        .verified_instruction_counts()
        .into_iter()
        .partition(|(name, _)| name.starts_with("kp_"));
    println!(
        "osiris-ebpf: fs verified insns (kprobes): {}",
        insn_list(&kprobes)
    );
    let tp_max = tracepoints.iter().filter_map(|(_, n)| *n).max();
    println!(
        "osiris-ebpf: fs verified insns (tracepoints): {} programs, max {tp_max:?}",
        tracepoints.len()
    );
    // The full list, without the notice prefix (artifact/log only).
    println!(
        "fs verified insns (tracepoints): {}",
        insn_list(&tracepoints)
    );

    let (_dir, dir_path) = watched_dir(&mut obj);
    let events = Events::start(obj);

    let probe = dir_path.join("probe.txt");
    File::create(&probe).expect("create probe file");
    let probe_meta = std::fs::metadata(&probe).expect("stat probe");
    let want_path = bytes(&probe);
    let pid = std::process::id();

    let (found, seen) =
        events.wait_for(|ev| ev.kind == FsKind::Create && ev.path == want_path && ev.pid == pid);
    events.stop();

    let ev = found.unwrap_or_else(|| {
        panic!(
            "no CREATE of {} by pid {pid} within 5 s; other events: {seen:?}",
            probe.display()
        )
    });
    println!("osiris-ebpf: fs create event: {ev:?}");
    assert!(ev.ret >= 0, "only successes are emitted: {ev:?}");
    assert!(!ev.path_truncated, "{ev:?}");
    assert!(ev.old_path.is_none(), "{ev:?}");
    // File::create opens O_WRONLY|O_CREAT|O_TRUNC, so security_file_open
    // filled in the new inode.
    let inode = ev
        .inode
        .expect("security_file_open fills the CREATE's inode");
    assert_eq!(inode.ino, probe_meta.ino(), "{ev:?}");
    // The kernel dev_t, in user-space encoding, is the file's st_dev
    // (ext4 on the runners; btrfs/overlayfs would differ).
    assert_eq!(dev_to_user(inode.dev), probe_meta.dev(), "{ev:?}");
    assert_eq!(inode.mode & 0o170000, 0o100000, "regular file: {ev:?}");
}

/// SELF_TGID set to this process: its own create in a watched directory is
/// dropped in the kernel, while a child's (`touch`) is emitted.
#[test]
#[ignore = "needs root, a BPF-capable kernel and $OSIRIS_BPF_DIR (real-Linux workflow)"]
fn fs_object_loads_and_attaches_with_self_filter() {
    let pid = std::process::id();
    let mut obj = load(pid);
    let (_dir, dir_path) = watched_dir(&mut obj);
    let events = Events::start(obj);

    let own = dir_path.join("own.txt");
    File::create(&own).expect("create own file");
    let child = dir_path.join("child.txt");
    run("touch", &[child.as_os_str()]);
    let (own_bytes, child_bytes) = (bytes(&own), bytes(&child));

    let (found, mut seen) =
        events.wait_for(|ev| ev.kind == FsKind::Create && ev.path == child_bytes);
    // The own create happened before the child ran; give a straggler a
    // moment anyway.
    seen.extend(events.drain(Duration::from_millis(300)));
    events.stop();

    let ev = found.unwrap_or_else(|| {
        panic!(
            "no CREATE of {} by touch within 5 s; other events: {seen:?}",
            child.display()
        )
    });
    println!(
        "osiris-ebpf: fs self-filter: child create seen from pid {}",
        ev.pid
    );
    assert_ne!(ev.pid, pid, "{ev:?}");
    let own_events: Vec<&FsEvent> = seen
        .iter()
        .filter(|e| e.pid == pid || e.path == own_bytes)
        .collect();
    assert!(
        own_events.is_empty(),
        "the agent's own operations must not be emitted: {own_events:?}"
    );
}

/// Restores the process root on drop: `chroot(".")` with the working
/// directory still at the real `/` (a chroot does not move it).
struct ChrootGuard;

impl Drop for ChrootGuard {
    fn drop(&mut self) {
        std::os::unix::fs::chroot(".").expect("leave the chroot");
    }
}

/// A create by a task chrooted into a subdirectory of a watched directory:
/// the walk goes on past the task's root and still finds the watched
/// ancestor. The path is the one the task sees (`/payload`, as d_path()
/// reports it inside the chroot).
#[test]
#[ignore = "needs root, a BPF-capable kernel and $OSIRIS_BPF_DIR (real-Linux workflow)"]
fn fs_object_loads_and_attaches_sees_past_a_chroot() {
    let mut obj = load(0);
    let (_dir, dir_path) = watched_dir(&mut obj);
    let jail = dir_path.join("jail");
    std::fs::create_dir(&jail).expect("create jail");
    let events = Events::start(obj);

    let cwd = std::env::current_dir().expect("cwd");
    std::env::set_current_dir("/").expect("cd /");
    let created = {
        std::os::unix::fs::chroot(&jail).expect("chroot");
        let _guard = ChrootGuard;
        File::create("/payload").map(drop)
    };
    std::env::set_current_dir(&cwd).expect("restore cwd");
    created.expect("create /payload inside the chroot");
    assert!(jail.join("payload").exists(), "created inside the jail");

    let pid = std::process::id();
    let (found, seen) = events.wait_for(|ev| ev.kind == FsKind::Create && ev.pid == pid);
    events.stop();
    let ev = found.unwrap_or_else(|| {
        panic!("no CREATE from inside the chroot within 5 s; other events: {seen:?}")
    });
    println!(
        "osiris-ebpf: fs chroot create: path {:?} truncated {}",
        String::from_utf8_lossy(&ev.path),
        ev.path_truncated
    );
    assert_eq!(ev.path, b"/payload", "{ev:?}");
    assert!(!ev.path_truncated, "{ev:?}");
}

/// A create through a detached (lazily unmounted) bind mount of a watched
/// directory: the event is emitted and its path is a truncated tail, never
/// presented as an absolute path.
#[test]
#[ignore = "needs root, a BPF-capable kernel and $OSIRIS_BPF_DIR (real-Linux workflow)"]
fn fs_object_loads_and_attaches_sees_through_a_detached_mount() {
    let mut obj = load(0);
    let (_dir, dir_path) = watched_dir(&mut obj);
    let mnt_dir = tempfile::tempdir().expect("mountpoint dir");
    let mnt = std::fs::canonicalize(mnt_dir.path()).expect("canonical mountpoint");
    run(
        "mount",
        &[OsStr::new("--bind"), dir_path.as_os_str(), mnt.as_os_str()],
    );
    let held = File::open(&mnt).expect("open the bind mount's root");
    run("umount", &[OsStr::new("-l"), mnt.as_os_str()]);
    let events = Events::start(obj);

    // /proc/self/fd/<n> leads into the detached mount.
    let via = PathBuf::from(format!("/proc/self/fd/{}/payload", held.as_raw_fd()));
    File::create(&via).expect("create through the detached mount");
    assert!(dir_path.join("payload").exists(), "same directory");

    let pid = std::process::id();
    let (found, seen) = events.wait_for(|ev| ev.kind == FsKind::Create && ev.pid == pid);
    events.stop();
    drop(held);
    let ev = found.unwrap_or_else(|| {
        panic!("no CREATE through the detached mount within 5 s; other events: {seen:?}")
    });
    println!(
        "osiris-ebpf: fs detached-mount create: path {:?} truncated {}",
        String::from_utf8_lossy(&ev.path),
        ev.path_truncated
    );
    assert!(ev.path_truncated, "outside the task's root: {ev:?}");
    assert_eq!(
        ev.path, b"payload",
        "the tail, without a leading '/': {ev:?}"
    );
}
