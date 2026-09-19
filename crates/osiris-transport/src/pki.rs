//! Minimal private PKI for enrolling Agents: a CA, a server certificate and
//! per-host Agent certificates (ECDSA P-256).

use std::net::IpAddr;
use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    Ia5String, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use uuid::Uuid;

use crate::HOST_URI_PREFIX;

#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("i/o error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid subject alternative name: {0}")]
    San(String),
}

/// PEM material for one certificate and its private key.
pub struct Issued {
    pub cert_pem: String,
    pub key_pem: String,
}

const CA_DAYS: i64 = 3650;
const LEAF_DAYS: i64 = 365;

fn validity(params: &mut CertificateParams, days: i64) {
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(days);
}

fn dn(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn
}

/// A self-signed CA valid for ten years.
pub fn generate_ca(common_name: &str) -> Result<Issued, PkiError> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = dn(common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    validity(&mut params, CA_DAYS);
    let cert = params.self_signed(&key)?;
    Ok(Issued {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

fn load_ca(
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> Result<(rcgen::Certificate, KeyPair), PkiError> {
    let key = KeyPair::from_pem(ca_key_pem)?;
    let params = CertificateParams::from_ca_cert_pem(ca_cert_pem)?;
    let cert = params.self_signed(&key)?;
    Ok((cert, key))
}

fn ia5(s: &str) -> Result<Ia5String, PkiError> {
    Ia5String::try_from(s.to_string()).map_err(|e| PkiError::San(format!("{s}: {e}")))
}

/// A server certificate for `names`, each a DNS name or an IP address literal.
pub fn issue_server(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    names: &[String],
) -> Result<Issued, PkiError> {
    let (ca, ca_key) = load_ca(ca_cert_pem, ca_key_pem)?;
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = dn("osiris-server");
    params.subject_alt_names = names
        .iter()
        .map(|n| match n.parse::<IpAddr>() {
            Ok(ip) => Ok(SanType::IpAddress(ip)),
            Err(_) => Ok(SanType::DnsName(ia5(n)?)),
        })
        .collect::<Result<_, PkiError>>()?;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    validity(&mut params, LEAF_DAYS);
    let cert = params.signed_by(&key, &ca, &ca_key)?;
    Ok(Issued {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// An Agent certificate bound to exactly one host id (SAN URI).
pub fn issue_agent(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    host_id: Uuid,
) -> Result<Issued, PkiError> {
    let (ca, ca_key) = load_ca(ca_cert_pem, ca_key_pem)?;
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = dn(&format!("osiris-agent-{host_id}"));
    params.subject_alt_names = vec![SanType::URI(ia5(&format!("{HOST_URI_PREFIX}{host_id}"))?)];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    validity(&mut params, LEAF_DAYS);
    let cert = params.signed_by(&key, &ca, &ca_key)?;
    Ok(Issued {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// Writes `<dir>/<name>.pem` and `<dir>/<name>.key` (key mode 0600 on unix).
pub fn write_issued(dir: &Path, name: &str, issued: &Issued) -> Result<(), PkiError> {
    let io = |path: &Path, source| PkiError::Io {
        path: path.display().to_string(),
        source,
    };
    std::fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
    let cert_path = dir.join(format!("{name}.pem"));
    std::fs::write(&cert_path, &issued.cert_pem).map_err(|e| io(&cert_path, e))?;
    let key_path = dir.join(format!("{name}.key"));
    std::fs::write(&key_path, &issued.key_pem).map_err(|e| io(&key_path, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| io(&key_path, e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_agent_certificate_is_issued_from_a_generated_ca() {
        let ca = generate_ca("test-ca").unwrap();
        let agent = issue_agent(&ca.cert_pem, &ca.key_pem, Uuid::new_v4()).unwrap();
        assert!(agent.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(agent.key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn a_server_certificate_accepts_dns_names_and_ip_literals() {
        let ca = generate_ca("test-ca").unwrap();
        let names = ["localhost".to_string(), "127.0.0.1".to_string()];
        let server = issue_server(&ca.cert_pem, &ca.key_pem, &names).unwrap();
        assert!(server.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn write_issued_creates_both_files() {
        let dir = tempfile::tempdir().unwrap();
        let ca = generate_ca("test-ca").unwrap();
        write_issued(dir.path(), "ca", &ca).unwrap();
        assert!(dir.path().join("ca.pem").exists());
        assert!(dir.path().join("ca.key").exists());
    }
}
