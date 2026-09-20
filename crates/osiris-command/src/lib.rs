pub mod envelope;
pub mod executor;
pub mod guard;
pub mod identity;
pub mod keys;
pub mod replay;
pub mod runner;

pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use envelope::{sign, verify, Command, CommandAction, CommandError, SignedCommand};
pub use executor::{
    ActionExecutor, CommandResult, ExecDetail, ExecFailure, FailCode, FakeExecutor,
};
pub use guard::{Guard, ProtectedTargets, Refusal};
pub use identity::process_started_by;
pub use replay::ReplayStore;
pub use runner::run_command;
