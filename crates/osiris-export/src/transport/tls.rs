//! Client-side TLS configuration shared by the syslog and HTTP transports.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};

use crate::error::ConfigError;

fn err(msg: impl Into<String>) -> ConfigError {
    ConfigError::new("tls", msg)
}

fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, ConfigError> {
    let bytes = std::fs::read(path)
        .map_err(|e| err(format!("cannot read `{}`: {}", path.display(), e.kind())))?;
    rustls_pemfile::certs(&mut bytes.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            err(format!(
                "`{}` is not valid PEM certificates",
                path.display()
            ))
        })
}

fn read_key(path: &Path) -> Result<PrivateKeyDer<'static>, ConfigError> {
    let bytes = std::fs::read(path)
        .map_err(|e| err(format!("cannot read `{}`: {}", path.display(), e.kind())))?;
    rustls_pemfile::private_key(&mut bytes.as_slice())
        .map_err(|_| {
            err(format!(
                "`{}` is not a valid PEM private key",
                path.display()
            ))
        })?
        .ok_or_else(|| err(format!("`{}` contains no private key", path.display())))
}

/// Client config verifying the server against the OS trust store plus every
/// certificate in `ca_file`. A `client_cert`/`client_key` pair enables mTLS.
/// Verification cannot be disabled.
pub fn client_tls_config(
    ca_file: Option<&Path>,
    client_cert: Option<&Path>,
    client_key: Option<&Path>,
) -> Result<Arc<ClientConfig>, ConfigError> {
    let mut roots = RootCertStore::empty();
    // Individual unparsable or unreadable native certs are skipped.
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    if let Some(ca) = ca_file {
        let certs = read_certs(ca)?;
        if certs.is_empty() {
            return Err(err(format!("`{}` contains no certificates", ca.display())));
        }
        for c in certs {
            roots.add(c).map_err(|_| {
                err(format!(
                    "`{}` holds an invalid CA certificate",
                    ca.display()
                ))
            })?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| err(format!("tls setup failed: {e}")))?
        .with_root_certificates(roots);
    let config = match (client_cert, client_key) {
        (Some(cert), Some(key)) => builder
            .with_client_auth_cert(read_certs(cert)?, read_key(key)?)
            .map_err(|_| err("client certificate and key do not match"))?,
        (None, None) => builder.with_no_client_auth(),
        _ => return Err(err("client_cert and client_key must be set together")),
    };
    Ok(Arc::new(config))
}
