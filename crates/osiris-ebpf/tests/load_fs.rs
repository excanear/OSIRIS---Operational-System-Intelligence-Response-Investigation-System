//! Real-kernel load of `fs.bpf.o` (Linux, root, `$OSIRIS_BPF_DIR`).
//!
//! Ignored by default: the real-Linux workflow runs it as root with
//! `--include-ignored` after `tools/real-linux/setup.sh` has built the
//! objects into `$OSIRIS_BPF_DIR`. It proves the verifier accepts every fs
//! program, that they attach, and that one watched create is staged at the
//! LSM hook and emitted at syscall exit with its path and pid.

#![cfg(target_os = "linux")]

use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use osiris_ebpf::{
    decode_fs, dev_from_user, spawn_reader, FsEvent, FsKind, LoadedObject, FS_OBJECT,
};
use tokio_util::sync::CancellationToken;

#[test]
#[ignore = "needs root, a BPF-capable kernel and $OSIRIS_BPF_DIR (real-Linux workflow)"]
fn fs_object_loads_and_attaches() {
    // SAFETY: geteuid() takes no arguments and cannot fail.
    assert_eq!(unsafe { libc::geteuid() }, 0, "must run as root");
    let bpf_dir = PathBuf::from(
        std::env::var_os("OSIRIS_BPF_DIR")
            .expect("OSIRIS_BPF_DIR is unset: build the objects with tools/ebpf/build.sh"),
    );

    // self_tgid 0: this test's own create must be seen.
    let mut obj = match LoadedObject::load(&bpf_dir, &FS_OBJECT, 0) {
        Ok(obj) => obj,
        Err(e) => {
            // Display keeps the verifier log's line breaks.
            eprintln!("{e}");
            panic!("loading fs.bpf.o failed (error above)");
        }
    };
    println!(
        "osiris-ebpf: fs skipped attach points: {:?}",
        obj.skipped_attach_points()
    );

    let dir = tempfile::tempdir().expect("temp dir");
    let dir_path = std::fs::canonicalize(dir.path()).expect("canonical temp dir");
    let meta = std::fs::metadata(&dir_path).expect("stat temp dir");
    obj.insert_watch(dev_from_user(meta.dev()), meta.ino())
        .expect("insert watch");
    obj.set_watch_flags(0).expect("set watch flags");

    let (tx, rx) = mpsc::channel::<FsEvent>();
    let cancel = CancellationToken::new();
    let reader = spawn_reader(obj, decode_fs, cancel.clone(), move |r| {
        if let Ok(ev) = r {
            let _ = tx.send(ev);
        }
    })
    .expect("spawn reader");

    let probe = dir_path.join("probe.txt");
    std::fs::File::create(&probe).expect("create probe file");
    let probe_ino = std::fs::metadata(&probe).expect("stat probe").ino();
    let want_path = probe.as_os_str().as_encoded_bytes().to_vec();
    let pid = std::process::id();

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut seen = Vec::new();
    let found = loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break None;
        }
        match rx.recv_timeout(left) {
            Ok(ev) if ev.kind == FsKind::Create && ev.path == want_path && ev.pid == pid => {
                break Some(ev)
            }
            Ok(ev) => seen.push(ev),
            Err(_) => break None,
        }
    };
    cancel.cancel();
    let joined = reader.join();

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
    assert_eq!(inode.ino, probe_ino, "{ev:?}");
    assert_eq!(inode.mode & 0o170000, 0o100000, "regular file: {ev:?}");
    assert!(
        matches!(joined, Ok(Ok(()))),
        "reader ended badly: {joined:?}"
    );
}
