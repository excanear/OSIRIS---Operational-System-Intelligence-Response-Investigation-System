use osiris_schema::CanonicalEvent;
use serde::{Deserialize, Serialize};

/// Agent → Server.
#[derive(Debug, Serialize, Deserialize)]
pub enum ClientMsg {
    Batch {
        seq: u64,
        events: Vec<CanonicalEvent>,
    },
}

/// Server → Agent.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServerMsg {
    /// The batch was durably processed.
    Ack { seq: u64 },
    /// The batch was not processed. `permanent` means retrying can never
    /// succeed (e.g. an event's host id does not match the certificate), so the
    /// Agent must skip it instead of retrying forever.
    Nack {
        seq: u64,
        reason: String,
        permanent: bool,
    },
}

/// Server → Agent on the control connection.
#[derive(Debug, Serialize, Deserialize)]
pub enum ControlServerMsg {
    Command(osiris_command::SignedCommand),
    Ping,
}

/// Agent → Server on the control connection.
#[derive(Debug, Serialize, Deserialize)]
pub enum ControlClientMsg {
    Hello {
        agent_version: String,
    },
    Result {
        command_id: uuid::Uuid,
        result: osiris_command::CommandResult,
    },
    Pong,
}
