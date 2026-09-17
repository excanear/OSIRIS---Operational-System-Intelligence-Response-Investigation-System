use std::path::PathBuf;

fn token_path() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|home| PathBuf::from(home).join(".osiris").join("token"))
}

/// Reads the cached session token: `OSIRIS_TOKEN` env var takes priority
/// (useful for scripts/CI), falling back to `~/.osiris/token`.
pub fn read_token() -> Option<String> {
    if let Ok(t) = std::env::var("OSIRIS_TOKEN") {
        if !t.is_empty() {
            return Some(t);
        }
    }
    let path = token_path()?;
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

pub fn write_token(token: &str) -> std::io::Result<()> {
    let path = token_path()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "HOME is not set"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn delete_token() {
    if let Some(path) = token_path() {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // HOME/OSIRIS_TOKEN are process-global env vars — serialize these tests
    // so they don't race each other under `cargo test`'s default parallelism.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn write_then_read_round_trips_through_home() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::env::remove_var("OSIRIS_TOKEN");
        std::env::set_var("HOME", dir.path());

        write_token("abc123").unwrap();
        assert_eq!(read_token(), Some("abc123".to_string()));

        delete_token();
        assert_eq!(read_token(), None);

        std::env::remove_var("HOME");
    }

    #[test]
    fn osiris_token_env_var_takes_priority_over_the_file() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", dir.path());
        write_token("from-file").unwrap();
        std::env::set_var("OSIRIS_TOKEN", "from-env");

        assert_eq!(read_token(), Some("from-env".to_string()));

        std::env::remove_var("OSIRIS_TOKEN");
        std::env::remove_var("HOME");
    }
}
