//! Optional Kubernetes context enrichment (ARCHITECTURE.md §21.3): resolves
//! `container_id -> pod -> namespace` from the node's own kubelet and serves
//! it to the pipeline through `osiris_pipeline::PodLookup`. Any failure
//! degrades to "no pod_ref"; never a startup or pipeline failure.

mod cache;
mod kubelet;
mod parse;
mod refresh;

pub use kubelet::{FetchError, KubeletClient, KubeletConfig, FETCH_TIMEOUT, MAX_BODY_LEN};
pub use refresh::{refresh_once, refresh_once_result, spawn_refresher};

pub use cache::{PodCache, MAX_CACHE_ENTRIES};
pub use parse::{parse_pod_list, MAX_NAME_LEN};
