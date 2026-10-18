//! BPF object integrity: the object must match the SHA-256 in its sidecar.

use sha2::{Digest, Sha256};

/// Why an object failed its integrity check.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntegrityError {
    /// The sidecar has no usable digest (empty, or not 64 hex characters).
    #[error("malformed sha256 sidecar")]
    Malformed,
    /// The sidecar digest differs from the object's actual digest.
    #[error("bpf object digest mismatch (expected {expected}, actual {actual})")]
    Mismatch { expected: String, actual: String },
}

/// Verify `object` against the sidecar text (`<hex>  <filename>\n` form; only
/// the first whitespace-separated token is used, hex case-insensitive).
pub fn verify_object(object: &[u8], sidecar_text: &str) -> Result<(), IntegrityError> {
    let token = sidecar_text
        .split_whitespace()
        .next()
        .ok_or(IntegrityError::Malformed)?;
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(IntegrityError::Malformed);
    }
    let expected = token.to_ascii_lowercase();
    let actual = hex::encode(Sha256::digest(object));
    if expected == actual {
        Ok(())
    } else {
        Err(IntegrityError::Mismatch { expected, actual })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_digest_parsing() {
        let obj = b"object bytes";
        let h = hex::encode(Sha256::digest(obj));
        assert_eq!(verify_object(obj, &format!("{h}  process.bpf.o\n")), Ok(()));
        assert_eq!(verify_object(obj, &h.to_uppercase()), Ok(()));
        let other = hex::encode(Sha256::digest(b"other"));
        assert!(matches!(
            verify_object(obj, &format!("{other}  process.bpf.o\n")),
            Err(IntegrityError::Mismatch { .. })
        ));
        assert_eq!(verify_object(obj, ""), Err(IntegrityError::Malformed));
        assert_eq!(verify_object(obj, "  \n"), Err(IntegrityError::Malformed));
        assert_eq!(verify_object(obj, "abc123"), Err(IntegrityError::Malformed));
    }
}
