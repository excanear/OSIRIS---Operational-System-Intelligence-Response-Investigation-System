//! Authenticated Agent→Server event transport (Phase 9a, ARCHITECTURE.md §8.3).
//!
//! * [`frame`]  — length-prefixed, zstd-compressed JSON frames with hard size limits.
//! * [`wire`]   — the messages that cross the stream.
//! * [`pki`]    — issue a CA, server and agent certificates (agent certs carry a host id).
//! * [`tls`]    — rustls (TLS 1.3, mutual auth) configuration from PEM files.
//! * [`client`] — the Forwarder: tails the Agent's spool and ships batches with acks.
//! * [`server`] — the Listener: accepts enrolled Agents and hands batches to a handler.

pub mod client;
pub mod frame;
pub mod pki;
pub mod server;
pub mod tls;
pub mod wire;

/// SAN URI prefix binding an Agent certificate to exactly one host id.
pub const HOST_URI_PREFIX: &str = "urn:osiris:host:";
