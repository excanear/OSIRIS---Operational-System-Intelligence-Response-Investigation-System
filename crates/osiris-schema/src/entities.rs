use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::event_type::Severity;
use crate::process_key::ProcessKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudContext {
    pub provider: String,
    pub instance_id: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRef {
    pub host_id: Uuid,
    pub hostname: String,
    pub distro: String,
    pub kernel_version: String,
    pub cloud: Option<CloudContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRef {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub username: Option<String>,
    pub loginuid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRef {
    pub session_id: String,
    pub tty: Option<String>,
    pub remote_addr: Option<String>,
    pub auth_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRef {
    pub process_key: ProcessKey,
    pub pid: u32,
    pub exe_path: String,
    pub cmdline: Vec<String>,
    pub exe_hash: Option<String>,
    pub start_time_mono: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadRef {
    pub tid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRef {
    pub path: String,
    pub previous_path: Option<String>,
    pub inode: Option<u64>,
    pub size: Option<u64>,
    pub mode: Option<u32>,
    pub owner_uid: Option<u32>,
    pub owner_gid: Option<u32>,
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NetworkDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRef {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: String,
    pub direction: NetworkDirection,
    pub bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRef {
    pub query: String,
    pub qtype: String,
    pub response_ips: Vec<String>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRef {
    pub device_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRef {
    pub unit_name: String,
    pub unit_type: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodRef {
    pub pod_name: String,
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRef {
    pub container_id: String,
    pub image: String,
    pub runtime: String,
    pub pod_ref: Option<PodRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceRef {
    pub pid_ns: u64,
    pub net_ns: u64,
    pub mnt_ns: u64,
    pub user_ns: u64,
    pub ipc_ns: u64,
    pub uts_ns: u64,
    pub cgroup_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CgroupVersion {
    V1,
    V2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgroupRef {
    pub cgroup_path: String,
    pub cgroup_id: u64,
    pub version: CgroupVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelRef {
    pub module_name: Option<String>,
    pub syscall_nr: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAnnotation {
    pub score: i32,
    pub severity: Severity,
    pub reasons: Vec<String>,
    pub rule_ids: Vec<String>,
}
