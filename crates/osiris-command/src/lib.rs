pub mod envelope;
pub mod keys;

pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use envelope::{sign, verify, Command, CommandAction, CommandError, SignedCommand};
