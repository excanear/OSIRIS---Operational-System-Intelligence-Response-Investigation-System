use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Category {
    Process,
    File,
    Network,
    Dns,
    Identity,
    Privilege,
    Systemd,
    Persistence,
    KernelModule,
    Container,
    Security,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Source {
    Ebpf,
    Audit,
    Fanotify,
    Procfs,
    Dbus,
    ContainerApi,
    Synthetic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    ProcessExec,
    ProcessFork,
    ProcessExit,
    FileCreate,
    FileDelete,
    FileRename,
    FileMove,
    FileModify,
    FileWrite,
    FileExecute,
    FilePermissionChange,
    FileOwnerChange,
    FileAttributeChange,
    SocketCreate,
    SocketBind,
    SocketListen,
    NetworkConnect,
    NetworkAccept,
    NetworkClose,
    DnsQuery,
    SessionLogin,
    SessionLogout,
    SessionCreate,
    SessionTerminate,
    PrivilegeUidChange,
    PrivilegeGidChange,
    PrivilegeCapabilityChange,
    PrivilegeSudo,
    PrivilegeSetuid,
    ServiceCreate,
    ServiceModify,
    ServiceStart,
    ServiceStop,
    ServiceDelete,
    TimerCreate,
    TimerModify,
    PersistenceCreated,
    PersistenceModified,
    PersistenceRemoved,
    ModuleLoad,
    ModuleUnload,
    ContainerCreate,
    ContainerStart,
    ContainerStop,
    ContainerDestroy,
    LsmDenial,
    CapabilityUse,
    AgentHealth,
    SensorHealth,
    AgentStart,
    AgentStop,
}

impl EventType {
    /// Maps each event_type to its category, per ARCHITECTURE.md §9.3.
    pub fn category(self) -> Category {
        use EventType::*;
        match self {
            ProcessExec | ProcessFork | ProcessExit => Category::Process,
            FileCreate | FileDelete | FileRename | FileMove | FileModify | FileWrite
            | FileExecute | FilePermissionChange | FileOwnerChange | FileAttributeChange => {
                Category::File
            }
            SocketCreate | SocketBind | SocketListen | NetworkConnect | NetworkAccept
            | NetworkClose => Category::Network,
            DnsQuery => Category::Dns,
            SessionLogin | SessionLogout | SessionCreate | SessionTerminate => Category::Identity,
            PrivilegeUidChange
            | PrivilegeGidChange
            | PrivilegeCapabilityChange
            | PrivilegeSudo
            | PrivilegeSetuid => Category::Privilege,
            ServiceCreate | ServiceModify | ServiceStart | ServiceStop | ServiceDelete
            | TimerCreate | TimerModify => Category::Systemd,
            PersistenceCreated | PersistenceModified | PersistenceRemoved => Category::Persistence,
            ModuleLoad | ModuleUnload => Category::KernelModule,
            ContainerCreate | ContainerStart | ContainerStop | ContainerDestroy => {
                Category::Container
            }
            LsmDenial | CapabilityUse => Category::Security,
            AgentHealth | SensorHealth | AgentStart | AgentStop => Category::System,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_as_screaming_snake_case() {
        let json = serde_json::to_string(&EventType::ProcessExec).unwrap();
        assert_eq!(json, "\"PROCESS_EXEC\"");
    }

    #[test]
    fn category_mapping_matches_spec() {
        assert_eq!(EventType::NetworkConnect.category(), Category::Network);
        assert_eq!(EventType::FileCreate.category(), Category::File);
        assert_eq!(EventType::AgentHealth.category(), Category::System);
    }
}
