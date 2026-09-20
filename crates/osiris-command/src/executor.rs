use crate::guard::Refusal;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailCode {
    TargetChanged,
    Unverifiable,
    NotFound,
    DestinationExists,
    Io,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecDetail {
    pub summary: String,
    pub quarantine_id: Option<Uuid>,
    pub sha256: Option<String>,
    pub signal: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecFailure {
    pub code: FailCode,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandResult {
    Refused { reason: Refusal },
    DryRunOk { would_do: String },
    Executed { detail: ExecDetail },
    Failed { code: FailCode, message: String },
}

pub trait ActionExecutor: Send + Sync {
    fn terminate(
        &self,
        pid: u32,
        exe_path: &str,
        observed_at_ns: u64,
        dry_run: bool,
    ) -> Result<ExecDetail, ExecFailure>;
    fn quarantine(
        &self,
        path: &str,
        inode: u64,
        device_id: u64,
        dry_run: bool,
    ) -> Result<ExecDetail, ExecFailure>;
    fn restore(&self, id: Uuid, dry_run: bool) -> Result<ExecDetail, ExecFailure>;
}

/// Test double: records every call and can be made to fail.
#[derive(Default)]
pub struct FakeExecutor {
    pub calls: Mutex<Vec<String>>,
    pub fail_with: Option<FailCode>,
}

impl FakeExecutor {
    fn respond(&self, call: String, dry_run: bool) -> Result<ExecDetail, ExecFailure> {
        self.calls.lock().expect("calls lock").push(call.clone());
        if let Some(code) = self.fail_with {
            return Err(ExecFailure {
                code,
                message: format!("fake failure: {call}"),
            });
        }
        Ok(ExecDetail {
            summary: if dry_run {
                format!("would {call}")
            } else {
                call
            },
            quarantine_id: None,
            sha256: None,
            signal: None,
        })
    }
}

impl ActionExecutor for FakeExecutor {
    fn terminate(
        &self,
        pid: u32,
        exe_path: &str,
        observed_at_ns: u64,
        dry_run: bool,
    ) -> Result<ExecDetail, ExecFailure> {
        self.respond(
            format!("terminate pid={pid} exe={exe_path} observed_at_ns={observed_at_ns} dry_run={dry_run}"),
            dry_run,
        )
    }
    fn quarantine(
        &self,
        path: &str,
        inode: u64,
        device_id: u64,
        dry_run: bool,
    ) -> Result<ExecDetail, ExecFailure> {
        self.respond(
            format!("quarantine path={path} inode={inode} device_id={device_id} dry_run={dry_run}"),
            dry_run,
        )
    }
    fn restore(&self, id: Uuid, dry_run: bool) -> Result<ExecDetail, ExecFailure> {
        self.respond(format!("restore id={id} dry_run={dry_run}"), dry_run)
    }
}
