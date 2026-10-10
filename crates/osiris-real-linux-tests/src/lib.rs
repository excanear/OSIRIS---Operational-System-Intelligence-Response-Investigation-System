//! Phase 10 dev tooling: drives the production `osiris-server` / `osiris-agent`
//! binaries as child processes. Nothing shipped depends on this crate.
pub mod json;
pub mod paths;
pub mod render;
pub mod seed;
pub mod stack;
