// Implemented in Task 2.
//
// Minimal placeholders below (not in the brief's literal text) so that
// `lib.rs`'s `pub use store::{BootstrapAdmin, SqliteUserStore, UserStore,
// UserStoreError};` compiles ahead of Task 2's real implementation. See
// task-1-report.md for the deviation note.

/// Placeholder — implemented in Task 2.
#[derive(Debug, thiserror::Error)]
pub enum UserStoreError {
    #[error("not yet implemented")]
    NotImplemented,
}

/// Placeholder — implemented in Task 2.
pub trait UserStore {}

/// Placeholder — implemented in Task 2.
pub struct SqliteUserStore;

/// Placeholder — implemented in Task 2.
pub struct BootstrapAdmin;
