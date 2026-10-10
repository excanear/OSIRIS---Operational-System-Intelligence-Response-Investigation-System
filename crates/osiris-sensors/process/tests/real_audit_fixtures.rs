//! Real auditd records captured on GitHub Actions Ubuntu runners
//! (Phase 10, GH run 38016185683), fed through the same assembler the
//! Process/Exec sensor runs.

use std::time::{Duration, Instant};

use osiris_sensors_process::execve::{MAX_ARGS, MAX_ARGV_BYTES};
use osiris_sensors_process::ExecAssembler;

fn assemble(fixture: &str) -> Vec<osiris_sensor_api::ProcessExecRaw> {
    let mut asm = ExecAssembler::new(Duration::from_millis(500));
    let now = Instant::now();
    let mut out: Vec<_> = fixture.lines().flat_map(|l| asm.offer(l, now)).collect();
    out.extend(asm.flush());
    out
}

/// `/bin/sh -c 'true <marker>'` run from bash: two execve groups (bash,
/// then the sh it execs in place). The marker exists only in the EXECVE
/// records — `a2` is uppercase hex because it contains a space.
#[test]
fn ubuntu_2404_sh_c_exec_carries_its_argv_from_the_execve_record() {
    let events = assemble(include_str!("fixtures/ubuntu2404-exec-sh-c-marker.log"));
    assert_eq!(events.len(), 2, "two execve groups, one non-exec SYSCALL");

    let bash = &events[0];
    assert_eq!(bash.pid, 8404);
    assert_eq!(bash.exe_path, "/usr/bin/bash");
    assert_eq!(
        bash.cmdline,
        [
            "/bin/bash",
            "-c",
            "/bin/sh -c 'true osirisp10cfe49a0ea24b4218aad021ee0c8b56d2'"
        ]
    );

    let sh = &events[1];
    assert_eq!(sh.pid, 8404);
    assert_eq!(sh.ppid, 8363);
    assert_eq!(sh.comm, "sh");
    assert_eq!(sh.exe_path, "/usr/bin/dash");
    assert_eq!(
        sh.cmdline,
        [
            "/bin/sh",
            "-c",
            "true osirisp10cfe49a0ea24b4218aad021ee0c8b56d2"
        ]
    );
}

/// A linker invocation with argc=253 that the kernel spread over three
/// EXECVE records of the same serial (continuation records carry no
/// argc). The argv is kept in order and bounded by the sensor's caps.
#[test]
fn ubuntu_2204_multi_record_execve_is_joined_in_order_and_capped() {
    let events = assemble(include_str!(
        "fixtures/ubuntu2204-exec-multi-record-argv.log"
    ));
    assert_eq!(events.len(), 1);
    let cc = &events[0];
    assert_eq!(cc.exe_path, "/usr/bin/x86_64-linux-gnu-gcc-11");
    assert_eq!(cc.cmdline.len(), MAX_ARGS, "253 args capped at MAX_ARGS");
    assert_eq!(cc.cmdline[0], "cc");
    assert_eq!(cc.cmdline[1], "-m64");
    // a97 opens the second EXECVE record: joining must not shift indices.
    assert_eq!(
        cc.cmdline[97],
        "/root/osiris-target/release/deps/libopenssl_sys-d72ff96ccd064d98.rlib"
    );
    let bytes: usize = cc.cmdline.iter().map(String::len).sum();
    assert!(bytes <= MAX_ARGV_BYTES);
}
