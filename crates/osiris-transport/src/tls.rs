//! rustls configuration from PEM files. TLS 1.3 only, mutual authentication.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("no certificate found in {0}")]
    NoCert(String),
    #[error("no private key found in {0}")]
    NoKey(String),
    #[error("tls configuration error: {0}")]
    Rustls(String),
}

fn read_err(path: &Path, source: std::io::Error) -> TlsError {
    TlsError::Read {
        path: path.display().to_string(),
        source,
    }
}

pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let bytes = std::fs::read(path).map_err(|e| read_err(path, e))?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut bytes.as_slice())
        .collect::<Result<_, _>>()
        .map_err(|e| read_err(path, e))?;
    if certs.is_empty() {
        return Err(TlsError::NoCert(path.display().to_string()));
    }
    Ok(certs)
}

pub fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let bytes = std::fs::read(path).map_err(|e| read_err(path, e))?;
    rustls_pemfile::private_key(&mut bytes.as_slice())
        .map_err(|e| read_err(path, e))?
        .ok_or_else(|| TlsError::NoKey(path.display().to_string()))
}

fn roots(ca_path: &Path) -> Result<RootCertStore, TlsError> {
    let mut store = RootCertStore::empty();
    for cert in load_certs(ca_path)? {
        store
            .add(cert)
            .map_err(|e| TlsError::Rustls(e.to_string()))?;
    }
    Ok(store)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Server side: presents `cert`/`key` and REQUIRES a client certificate signed
/// by `client_ca`.
pub fn server_config(
    cert: &Path,
    key: &Path,
    client_ca: &Path,
) -> Result<Arc<ServerConfig>, TlsError> {
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots(client_ca)?), provider())
            .build()
            .map_err(|e| TlsError::Rustls(e.to_string()))?;
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Rustls(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(load_certs(cert)?, load_key(key)?)
        .map_err(|e| TlsError::Rustls(e.to_string()))?;
    Ok(Arc::new(config))
}

/// Server side for a public-facing listener (the API/Console): presents
/// `cert`/`key`, TLS 1.3 only, NO client authentication, ALPN `h2`/`http/1.1`.
pub fn server_config_no_client_auth(
    cert: &Path,
    key: &Path,
) -> Result<Arc<ServerConfig>, TlsError> {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Rustls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(load_certs(cert)?, load_key(key)?)
        .map_err(|e| TlsError::Rustls(e.to_string()))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Client side: trusts only `ca` and presents `cert`/`key`.
pub fn client_config(ca: &Path, cert: &Path, key: &Path) -> Result<Arc<ClientConfig>, TlsError> {
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Rustls(e.to_string()))?
        .with_root_certificates(roots(ca)?)
        .with_client_auth_cert(load_certs(cert)?, load_key(key)?)
        .map_err(|e| TlsError::Rustls(e.to_string()))?;
    Ok(Arc::new(config))
}
