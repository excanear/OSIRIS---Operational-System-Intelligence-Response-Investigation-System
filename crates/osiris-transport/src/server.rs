//! The Server side of the transport: accepts mutually-authenticated Agent
//! connections, binds each to the host id in its certificate, and hands batches
//! to a [`BatchHandler`].

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use osiris_schema::CanonicalEvent;
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

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// An Agent that sends nothing for this long is disconnected (it reconnects).
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_CONNECTIONS: usize = 1024;

/// Processes a batch that has already been authenticated and host-checked.
/// `Ok` means the batch was durably handled (it is then acknowledged).
#[async_trait]
pub trait BatchHandler: Send + Sync {
    async fn handle(&self, host_id: Uuid, events: Vec<CanonicalEvent>) -> Result<(), String>;
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
        loop {
            let accepted = tokio::select! {
                r = self.listener.accept() => r,
                _ = cancel.cancelled() => return,
            };
            let (stream, peer) = match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(error = %e, "agent listener accept failed");
                    continue;
                }
            };
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                tracing::warn!(%peer, "agent listener at its connection limit; refusing");
                continue;
            };
            let acceptor = self.acceptor.clone();
            let revoked = self.revoked.clone();
            let handler = handler.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let _permit = permit;
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

        let reply = if let Some(bad) = events.iter().find(|e| e.host_id != host_id) {
            // An enrolled Agent may only speak for its own host: tenant isolation
            // keys on `host_id`.
            tracing::warn!(%host_id, claimed = %bad.host_id, "rejecting batch: event host_id does not match the certificate");
            ServerMsg::Nack {
                seq,
                reason: "event host_id does not match the client certificate".to_string(),
                permanent: true,
            }
        } else {
            match handler.handle(host_id, events).await {
                Ok(()) => ServerMsg::Ack { seq },
                Err(reason) => ServerMsg::Nack {
                    seq,
                    reason,
                    permanent: false,
                },
            }
        };
        write_frame(&mut tls, &reply)
            .await
            .map_err(|e| e.to_string())?;
    }
}
