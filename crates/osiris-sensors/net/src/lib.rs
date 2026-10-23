pub mod ebpf_backend;
pub mod fd_scan;
pub mod poller;
pub mod proc_tcp;
pub mod sensor;

pub use ebpf_backend::{net_to_raw, render_addr};
/// Lives in `osiris-ebpf` (shared with the process sensor); re-exported so
/// callers can name it as `osiris_sensors_net::EbpfSettings`.
pub use osiris_ebpf::EbpfSettings;
pub use poller::NetworkPoller;
pub use sensor::NetworkSensor;
