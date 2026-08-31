use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Composite process identity: hash(host_id, boot_id, pid, start_time_monotonic).
/// Solves PID reuse — two processes reusing the same PID within the same boot
/// get different keys because start_time_monotonic differs (ARCHITECTURE.md §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessKey([u8; 16]);

impl ProcessKey {
    pub fn new(host_id: Uuid, boot_id: &str, pid: u32, start_time_mono: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(host_id.as_bytes());
        hasher.update(boot_id.as_bytes());
        hasher.update(pid.to_le_bytes());
        hasher.update(start_time_mono.to_le_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        ProcessKey(bytes)
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for ProcessKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_hex())
    }
}

impl Serialize for ProcessKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_hex())
    }
}

impl<'de> Deserialize<'de> for ProcessKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 16 {
            return Err(serde::de::Error::custom("process_key must decode to 16 bytes"));
        }
        let mut array = [0u8; 16];
        array.copy_from_slice(&bytes);
        Ok(ProcessKey(array))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_start_time_yields_different_key_for_same_pid() {
        let host_id = Uuid::new_v4();
        let key_a = ProcessKey::new(host_id, "boot-1", 1234, 1_000_000);
        let key_b = ProcessKey::new(host_id, "boot-1", 1234, 2_000_000);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn same_inputs_yield_same_key() {
        let host_id = Uuid::new_v4();
        let key_a = ProcessKey::new(host_id, "boot-1", 1234, 1_000_000);
        let key_b = ProcessKey::new(host_id, "boot-1", 1234, 1_000_000);
        assert_eq!(key_a, key_b);
    }

    #[test]
    fn hex_round_trip_via_json() {
        let key = ProcessKey::new(Uuid::new_v4(), "boot-1", 42, 99);
        let json = serde_json::to_string(&key).unwrap();
        let back: ProcessKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, back);
    }
}
