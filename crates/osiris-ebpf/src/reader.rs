//! Ring-buffer reader thread for a loaded [`ProcessProgram`].
//!
//! Runs on a dedicated `std::thread` (never an async worker): it drains every
//! available record, decodes each with [`decode`] and hands the result to the
//! callback, then `poll(2)`s the ring-buffer fd for at most
//! [`POLL_TIMEOUT_MS`] so cancellation is observed within that bound. The
//! program (and so both tracepoint attachments) is dropped when the thread
//! ends.

use std::thread::JoinHandle;

use tokio_util::sync::CancellationToken;

use crate::loader::ProcessProgram;
use crate::record::{DecodeError, Record};

/// Upper bound on one `poll(2)` wait (Global Constraint #5: ≤ 500 ms).
pub const POLL_TIMEOUT_MS: i32 = 500;

/// While draining, cancellation is checked after this many records, so a
/// flood of events cannot hold off shutdown.
pub const CANCEL_CHECK_EVERY: u32 = 256;

/// Why the reader thread failed to start or stopped other than by
/// cancellation.
#[derive(Debug, thiserror::Error)]
pub enum ReaderError {
    /// `poll(2)` on the ring-buffer fd failed.
    #[error("ring buffer poll failed: {0}")]
    Poll(std::io::Error),
    /// The reader thread could not be started.
    #[error("cannot spawn eBPF reader thread: {0}")]
    Spawn(std::io::Error),
}

/// Start the reader thread. The thread returns `Ok(())` once `cancel` is
/// cancelled. Failing to start it is [`ReaderError::Spawn`]; the program is
/// then dropped, detaching both tracepoints.
pub fn spawn_reader(
    prog: ProcessProgram,
    cancel: CancellationToken,
    on_record: impl FnMut(Result<Record, DecodeError>) + Send + 'static,
) -> Result<JoinHandle<Result<(), ReaderError>>, ReaderError> {
    std::thread::Builder::new()
        .name("osiris-ebpf-reader".to_string())
        .spawn(move || run(prog, cancel, on_record))
        .map_err(ReaderError::Spawn)
}

#[cfg(target_os = "linux")]
fn run(
    mut prog: ProcessProgram,
    cancel: CancellationToken,
    mut on_record: impl FnMut(Result<Record, DecodeError>),
) -> Result<(), ReaderError> {
    use std::os::fd::AsRawFd;

    use crate::record::decode;

    let events = &mut prog.inner.events;
    let fd = events.as_raw_fd();
    loop {
        // Drain everything already published before sleeping, checking
        // cancellation every CANCEL_CHECK_EVERY records.
        let mut drained: u32 = 0;
        while let Some(item) = events.next() {
            on_record(decode(&item));
            drop(item);
            drained = drained.wrapping_add(1);
            if drained.is_multiple_of(CANCEL_CHECK_EVERY) && cancel.is_cancelled() {
                return Ok(());
            }
        }
        if cancel.is_cancelled() {
            return Ok(());
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is a valid, initialised pollfd for the duration of
        // the call and nfds is 1; `fd` stays open because `prog` owns it.
        let rc = unsafe { libc::poll(&mut pfd, 1, POLL_TIMEOUT_MS) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                return Err(ReaderError::Poll(err));
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run(
    prog: ProcessProgram,
    _cancel: CancellationToken,
    _on_record: impl FnMut(Result<Record, DecodeError>),
) -> Result<(), ReaderError> {
    match prog.never {}
}
