use std::collections::{HashMap, HashSet};

/// Everything the Enrich stage needs to reconstruct a §9.2 `SessionRef`
/// (plus the session owner's uid) for any process that belongs to a
/// session, learned once from that session's `SESSION_LOGIN`/
/// `SESSION_CREATE` event.
#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub session_id: String,
    /// The uid reported by the login record itself — the authenticating
    /// process's uid (typically 0 for sshd), retained for completeness. It
    /// is deliberately NOT used to overwrite a descendant event's own
    /// `user`, which is that process's real uid.
    pub uid: u32,
    pub username: Option<String>,
    pub tty: Option<String>,
    pub remote_addr: Option<String>,
    pub auth_method: Option<String>,
}

/// In-memory pid→session resolver (ARCHITECTURE.md §4.2/§7.1 step 3, and
/// §26 step 3's "attach session_id from the Identity Sensor's earlier
/// SESSION_LOGIN … populated at login/exec time"). Sensors never
/// cross-reference each other; this single resolver in the Enrich stage is
/// where the identity↔process linkage is made, exactly as `ProcessResolver`
/// is where the pid↔process_key linkage is made.
///
/// Growth is bounded by per-pid eviction: `forget_pid` drops a pid when its
/// `PROCESS_EXIT` is observed (eBPF backend), and `forget` drops a whole
/// session on logout. Hosts whose process sensor has no exit source (the
/// audit backend) still only prune on logout.
#[derive(Default)]
pub struct SessionResolver {
    by_pid: HashMap<u32, String>,
    sessions: HashMap<String, SessionRecord>,
    /// Reverse index so `forget` is O(members) rather than a full scan of
    /// `by_pid` — the map can hold many thousands of pids across many
    /// sessions, and logouts are common.
    members: HashMap<String, HashSet<u32>>,
}

impl SessionResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `pid` (the process that performed the login — sshd,
    /// login, su) is the root of `record`'s session. A repeated login for
    /// the same session id replaces the record and re-roots it at the new
    /// pid, without discarding members already attached to that session.
    pub fn record_login(&mut self, pid: u32, record: SessionRecord) {
        let session_id = record.session_id.clone();
        self.sessions.insert(session_id.clone(), record);
        self.by_pid.insert(pid, session_id.clone());
        self.members.entry(session_id).or_default().insert(pid);
    }

    /// Resolves `pid`'s session, adopting its parent's session if `pid` is
    /// not itself known. Returns `None` — never a guess — when neither the
    /// pid nor its parent belongs to a known session (plan Global
    /// Constraint #5). A `ppid` of `0` never matches: `0` is the
    /// "no parent reported" convention used by `event_data`'s `ppid`
    /// fallback and by `PrivilegeEventRaw.ppid` for `USER_CMD` records.
    pub fn attach(&mut self, pid: u32, ppid: u32) -> Option<String> {
        if let Some(session_id) = self.by_pid.get(&pid) {
            return Some(session_id.clone());
        }
        if ppid == 0 {
            return None;
        }
        let session_id = self.by_pid.get(&ppid)?.clone();
        self.by_pid.insert(pid, session_id.clone());
        self.members
            .entry(session_id.clone())
            .or_default()
            .insert(pid);
        Some(session_id)
    }

    pub fn record_for(&self, session_id: &str) -> Option<&SessionRecord> {
        self.sessions.get(session_id)
    }

    /// Per-pid eviction on `PROCESS_EXIT`: drops `pid`'s mapping and its
    /// membership entry, leaving the session and its other members intact.
    /// Called by Enrich after the exit event itself has been attributed.
    pub fn forget_pid(&mut self, pid: u32) {
        if let Some(session_id) = self.by_pid.remove(&pid) {
            if let Some(pids) = self.members.get_mut(&session_id) {
                pids.remove(&pid);
            }
        }
    }

    /// Drops a session and every pid mapped to it (called on
    /// `SESSION_LOGOUT`/`SESSION_TERMINATE`). A pid that outlives its
    /// session — a daemon deliberately detached from the login — stops
    /// being attributed to it, which is the correct answer: the session is
    /// over.
    pub fn forget(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
        if let Some(pids) = self.members.remove(session_id) {
            for pid in pids {
                // Only remove the mapping if it still points at this
                // session — a pid re-attached to a newer session must not
                // be dropped by an older session's logout.
                if self.by_pid.get(&pid).map(String::as_str) == Some(session_id) {
                    self.by_pid.remove(&pid);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssh_session() -> SessionRecord {
        SessionRecord {
            session_id: "3".to_string(),
            uid: 0,
            username: Some("alice".to_string()),
            tty: Some("/dev/pts/0".to_string()),
            remote_addr: Some("198.51.100.10".to_string()),
            auth_method: Some("sshd".to_string()),
        }
    }

    #[test]
    fn a_logins_own_pid_resolves_to_its_session() {
        let mut sessions = SessionResolver::new();
        sessions.record_login(100, ssh_session());
        assert_eq!(sessions.attach(100, 1), Some("3".to_string()));
    }

    #[test]
    fn a_child_inherits_its_parents_session() {
        let mut sessions = SessionResolver::new();
        sessions.record_login(100, ssh_session());
        assert_eq!(sessions.attach(200, 100), Some("3".to_string()));
        // ...and a grandchild inherits it transitively, because attaching
        // pid 200 registered it as a session member.
        assert_eq!(sessions.attach(300, 200), Some("3".to_string()));
    }

    #[test]
    fn an_unrelated_pid_gets_no_session_rather_than_a_guess() {
        let mut sessions = SessionResolver::new();
        sessions.record_login(100, ssh_session());
        assert_eq!(sessions.attach(999, 998), None);
        // A ppid of 0 (no parent reported) must never match anything.
        assert_eq!(sessions.attach(777, 0), None);
    }

    #[test]
    fn the_full_session_record_is_retrievable_by_id() {
        let mut sessions = SessionResolver::new();
        sessions.record_login(100, ssh_session());
        let record = sessions.record_for("3").expect("session must be known");
        assert_eq!(record.remote_addr.as_deref(), Some("198.51.100.10"));
        assert_eq!(record.auth_method.as_deref(), Some("sshd"));
        assert_eq!(record.tty.as_deref(), Some("/dev/pts/0"));
        assert!(sessions.record_for("nope").is_none());
    }

    /// Logout is this phase's only bound on the pid map's growth (plan
    /// Global Constraint #5): forgetting a session must drop the record
    /// *and* every pid that mapped to it, or the map leaks for the life of
    /// the process.
    #[test]
    fn forgetting_a_session_drops_the_record_and_every_pid_mapped_to_it() {
        let mut sessions = SessionResolver::new();
        sessions.record_login(100, ssh_session());
        assert_eq!(sessions.attach(200, 100), Some("3".to_string()));
        assert_eq!(sessions.attach(300, 200), Some("3".to_string()));

        sessions.forget("3");

        assert!(sessions.record_for("3").is_none());
        assert_eq!(sessions.attach(100, 1), None);
        assert_eq!(sessions.attach(200, 100), None);
        assert_eq!(sessions.attach(300, 200), None);
    }

    /// Two concurrent sessions must not bleed into each other.
    #[test]
    fn two_sessions_stay_independent() {
        let mut sessions = SessionResolver::new();
        sessions.record_login(100, ssh_session());
        sessions.record_login(
            500,
            SessionRecord {
                session_id: "4".to_string(),
                uid: 0,
                username: Some("bob".to_string()),
                tty: Some("tty1".to_string()),
                remote_addr: None,
                auth_method: Some("login".to_string()),
            },
        );
        assert_eq!(sessions.attach(200, 100), Some("3".to_string()));
        assert_eq!(sessions.attach(600, 500), Some("4".to_string()));
        sessions.forget("3");
        assert_eq!(sessions.attach(600, 500), Some("4".to_string()));
    }

    /// A real audit stream emits both `USER_LOGIN` and `USER_START` for one
    /// session, and `enrich.rs`'s `attach_session` calls `record_login` for
    /// both — `members` must not accumulate the same pid twice from that,
    /// or `forget`'s iteration does needless repeated work per session.
    #[test]
    fn record_login_called_twice_for_the_same_pid_does_not_duplicate_membership() {
        let mut sessions = SessionResolver::new();
        sessions.record_login(100, ssh_session());
        sessions.record_login(100, ssh_session());
        sessions.forget("3");
        // If pid 100 had been double-counted, this would still resolve
        // (the first `forget` pass would only remove one of two identical
        // entries) — asserting `None` here is the actual proof.
        assert_eq!(sessions.attach(100, 1), None);
    }

    #[test]
    fn forget_pid_drops_only_that_pid() {
        let mut sessions = SessionResolver::new();
        sessions.record_login(100, ssh_session());
        assert_eq!(sessions.attach(200, 100), Some("3".to_string()));
        assert_eq!(sessions.attach(300, 100), Some("3".to_string()));
        sessions.forget_pid(200);
        // 200 no longer resolves on its own (ppid 1 is not a member)...
        assert_eq!(sessions.attach(200, 1), None);
        // ...while the root and the sibling keep the session.
        assert_eq!(sessions.attach(100, 1), Some("3".to_string()));
        assert_eq!(sessions.attach(300, 1), Some("3".to_string()));
        assert!(sessions.record_for("3").is_some());
        // Logout still cleans up cleanly after a pid was evicted.
        sessions.forget("3");
        assert_eq!(sessions.attach(300, 1), None);
    }
}
