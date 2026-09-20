use crate::envelope::CommandError;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::io::Write;
use std::path::Path;

pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

fn write_new(path: &Path, content: &str, secret: bool) -> Result<(), CommandError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut f = opts
        .open(path)
        .map_err(|e| CommandError::Io(format!("{}: {e}", path.display())))?;
    f.write_all(content.as_bytes())
        .map_err(|e| CommandError::Io(e.to_string()))
}

pub fn write_signing_key(dir: &Path, name: &str) -> Result<(), CommandError> {
    let key = generate_signing_key();
    write_new(
        &dir.join(format!("{name}.key")),
        &hex::encode(key.to_bytes()),
        true,
    )?;
    write_new(
        &dir.join(format!("{name}.pub")),
        &hex::encode(key.verifying_key().to_bytes()),
        false,
    )
}

fn read_key32(path: &Path) -> Result<[u8; 32], CommandError> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| CommandError::Io(format!("{}: {e}", path.display())))?;
    let v = hex::decode(s.trim()).map_err(|e| CommandError::BadKey(e.to_string()))?;
    v.try_into()
        .map_err(|_| CommandError::BadKey("expected 32 bytes".into()))
}

pub fn load_signing_key(path: &Path) -> Result<SigningKey, CommandError> {
    Ok(SigningKey::from_bytes(&read_key32(path)?))
}

pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey, CommandError> {
    VerifyingKey::from_bytes(&read_key32(path)?).map_err(|e| CommandError::BadKey(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn write_load_roundtrip_and_no_overwrite() {
        let d = tempfile::tempdir().unwrap();
        write_signing_key(d.path(), "cmd").unwrap();
        let sk = load_signing_key(&d.path().join("cmd.key")).unwrap();
        let vk = load_verifying_key(&d.path().join("cmd.pub")).unwrap();
        assert_eq!(sk.verifying_key(), vk);
        assert!(write_signing_key(d.path(), "cmd").is_err());
    }
}
