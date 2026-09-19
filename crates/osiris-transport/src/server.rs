//! The Server side of the transport: accepts mutually-authenticated Agent
//! connections, binds each to the host id in its certificate, and hands batches
//! to a [`BatchHandler`].

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use osiris_schema::{CanonicalEvent, EntityRef};
use rustls::pki_types::CertificateDer;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use x509_parser::extensions::GeneralName;

use crate::frame::{read_frame, write_frame, FrameError};
use crate::wire::{ClientMsg, ServerMsg};
use crate::HOST_URI_PREFIX;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// An Agent that sends nothing for this long is disconnected (it reconnects).
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_CONNECTIONS: usize = 1024;
/// Most concurrent connections from one peer IP.
const MAX_CONNECTIONS_PER_IP: usize = 16;

/// Processes a batch that has already been authenticated and host-checked.
/// `Ok` means the batch was durably handled (it is then acknowledged).
#[async_trait]
pub trait BatchHandler: Send + Sync {
    async fn handle(&self, host_id: Uuid, events: Vec<CanonicalEvent>) -> Result<(), String>;
}

/// True when every host claim inside `e` (its envelope, its `host` block and
/// any host-carrying relationship endpoint) names `host_id`.
pub fn event_belongs_to_host(e: &CanonicalEvent, host_id: Uuid) -> bool {
    let ref_ok = |r: &EntityRef| match r {
        EntityRef::File { host_id: h, .. } | EntityRef::User { host_id: h, .. } => *h == host_id,
        _ => true,
    };
    e.host_id == host_id
        && e.host.host_id == host_id
        && e.relationships
            .iter()
            .all(|r| ref_ok(&r.from) && ref_ok(&r.to))
}

/// Tracks concurrent connections per peer IP; dropping the guard releases the slot.
#[derive(Default)]
struct IpCounter(Mutex<HashMap<IpAddr, usize>>);

struct IpGuard {
    counter: Arc<IpCounter>,
    ip: IpAddr,
}

impl IpCounter {
    fn acquire(self: &Arc<Self>, ip: IpAddr, max: usize) -> Option<IpGuard> {
        let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let n = map.entry(ip).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(IpGuard {
            counter: self.clone(),
            ip,
        })
    }
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut map = self.counter.0.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = map.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// The host id an Agent certificate is bound to (its `urn:osiris:host:<uuid>` SAN).
pub fn host_id_from_cert(der: &CertificateDer<'_>) -> Option<Uuid> {
    let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).ok()?;
    let san = cert.subject_alternative_name().ok()??;
    san.value.general_names.iter().find_map(|name| match name {
        GeneralName::URI(uri) => uri.strip_prefix(HOST_URI_PREFIX)?.parse().ok(),
        _ => None,
    })
}

pub struct Listener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    revoked: Arc<HashSet<Uuid>>,
}

impl Listener {
    pub async fn bind(
        addr: &str,
        tls: Arc<rustls::ServerConfig>,
        revoked: HashSet<Uuid>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
            acceptor: TlsAcceptor::from(tls),
            revoked: Arc::new(revoked),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accepts connections until `cancel` fires.
    pub async fn run(self, handler: Arc<dyn BatchHandler>, cancel: CancellationToken) {
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let per_ip = Arc::new(IpCounter::default());
        loop {
            let accepted = tokio::select! {
                r = self.listener.accept() => r,
                _ = cancel.cancelled() => return,
            };
            let (stream, peer) = match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(error = %e, "agent listener accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                tracing::warn!(%peer, "agent listener at its connection limit; refusing");
                continue;
            };
            let Some(ip_guard) = per_ip.acquire(peer.ip(), MAX_CONNECTIONS_PER_IP) else {
                tracing::warn!(%peer, "too many concurrent connections from this address; refusing");
                continue;
            };
            let acceptor = self.acceptor.clone();
            let revoked = self.revoked.clone();
            let handler = handler.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ip_guard = ip_guard;
                if let Err(reason) = serve(stream, acceptor, revoked, handler, cancel).await {
                    tracing::info!(%peer, %reason, "agent connection closed");
                }
            });
        }
    }
}

async fn serve(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    revoked: Arc<HashSet<Uuid>>,
    handler: Arc<dyn BatchHandler>,
    cancel: CancellationToken,
) -> Result<(), String> {
    let mut tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream))
        .await
        .map_err(|_| "tls handshake timed out".to_string())?
        .map_err(|e| format!("tls handshake failed: {e}"))?;

    let host_id = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(host_id_from_cert)
        .ok_or("client certificate carries no osiris host id")?;
    if revoked.contains(&host_id) {
        return Err(format!("host {host_id} is revoked"));
    }
    tracing::info!(%host_id, "agent connected");

    loop {
        let msg = tokio::select! {
            r = tokio::time::timeout(IDLE_TIMEOUT, read_frame::<_, ClientMsg>(&mut tls)) => match r {
                Err(_) => return Err("idle timeout".to_string()),
                Ok(Err(FrameError::Closed)) => return Ok(()),
                Ok(Err(e)) => return Err(e.to_string()),
                Ok(Ok(msg)) => msg,
            },
            _ = cancel.cancelled() => return Ok(()),
        };
        let ClientMsg::Batch { seq, events } = msg;

        // An enrolled Agent may only speak for its own host: tenant isolation
        // keys on `host_id`. Drop offending events, ingest the rest.
        let total = events.len();
        let events: Vec<CanonicalEvent> = events
            .into_iter()
            .filter(|e| event_belongs_to_host(e, host_id))
            .collect();
        let dropped = total - events.len();
        if dropped > 0 {
            tracing::error!(%host_id, dropped, accepted = events.len(), "dropped events whose host claims do not match the client certificate");
        }
        let result = if events.is_empty() {
            Ok(())
        } else {
            handler.handle(host_id, events).await
        };
        let reply = match result {
            Ok(()) => ServerMsg::Ack { seq },
            Err(detail) => {
                tracing::error!(%host_id, %detail, "batch ingest failed");
                ServerMsg::Nack {
                    seq,
                    reason: "ingest failed".to_string(),
                    permanent: false,
                }
            }
        };
        write_frame(&mut tls, &reply)
            .await
            .map_err(|e| e.to_string())?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osiris_schema::{EntityRelationship, Relation};

    fn event(host: Uuid) -> CanonicalEvent {
        use osiris_schema::{Category, EventType, HostRef, Severity, Source, SCHEMA_VERSION};
        CanonicalEvent {
            event_id: Uuid::now_v7(),
            schema_version: SCHEMA_VERSION.to_string(),
            host_id: host,
            boot_id: "b".to_string(),
            timestamp: 1,
            monotonic_timestamp: 1,
            event_type: EventType::ProcessExec,
            category: Category::Process,
            severity: Severity::Info,
            host: HostRef {
                host_id: host,
                hostname: "h".to_string(),
                distro: "d".to_string(),
                kernel_version: "k".to_string(),
                cloud: None,
            },
            user: None,
            session: None,
            process: None,
            parent_process: None,
            thread: None,
            file: None,
            network: None,
            dns: None,
            device: None,
            service: None,
            container: None,
            namespace: None,
            cgroup: None,
            kernel: None,
            source: Source::Synthetic,
            provider: "t".to_string(),
            raw_event: None,
            relationships: vec![],
            tags: vec![],
            risk: None,
            event_data: serde_json::json!({}),
        }
    }

    #[test]
    fn host_claims_must_all_match() {
        let h = Uuid::new_v4();
        let other = Uuid::new_v4();
        assert!(event_belongs_to_host(&event(h), h));
        assert!(!event_belongs_to_host(&event(other), h));
        let mut e = event(h);
        e.host.host_id = other;
        assert!(!event_belongs_to_host(&e, h));
        let mut e = event(h);
        e.relationships.push(EntityRelationship {
            from: EntityRef::User {
                host_id: other,
                uid: 0,
            },
            to: EntityRef::Ip {
                addr: "1.2.3.4".into(),
            },
            relation: Relation::ConnectedTo,
            event_id: e.event_id,
            timestamp: 1,
        });
        assert!(!event_belongs_to_host(&e, h));
        e.relationships[0].from = EntityRef::User { host_id: h, uid: 0 };
        assert!(event_belongs_to_host(&e, h));
    }

    #[test]
    fn per_ip_cap_is_enforced_and_released() {
        let c = Arc::new(IpCounter::default());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let g1 = c.acquire(ip, 2).unwrap();
        let _g2 = c.acquire(ip, 2).unwrap();
        assert!(c.acquire(ip, 2).is_none());
        drop(g1);
        assert!(c.acquire(ip, 2).is_some());
    }
}
