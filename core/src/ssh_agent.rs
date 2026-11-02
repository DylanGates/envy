//! Envy SSH signing agent (M1).
//!
//! A minimal ssh-agent served by the trusted core. It answers identity and
//! signature requests for a fixed, explicitly scoped set of vault identities.
//! Private key bytes are decrypted only inside this process, only for the
//! duration of one signature, and are zeroized afterwards. The agent never
//! accepts keys from clients.
//!
//! Protocol subset (draft-miller-ssh-agent / OpenSSH `PROTOCOL.agent`). Each
//! message is a 4-byte big-endian length, then a type byte, then the payload.
//!
//! | Request | Response |
//! | --- | --- |
//! | `REQUEST_IDENTITIES` (11) | `IDENTITIES_ANSWER` (12) |
//! | `SIGN_REQUEST` (13) | `SIGN_RESPONSE` (14) or `FAILURE` (5) |
//! | `EXTENSION` (27) `session-bind@openssh.com` | `SUCCESS` (6) or `FAILURE` (5) |
//! | anything else (add/remove/lock/…) | `FAILURE` (5) |
//!
//! M1 supports Ed25519 identities only.

use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

use signature::Signer;
use ssh_key::{Algorithm, PublicKey};
use zeroize::Zeroizing;

use crate::audit::AuditEvent;
use crate::error::CoreError;
use crate::vault::Vault;

/// Maximum accepted message size (256 KiB).
pub const MAX_MESSAGE_LEN: usize = 256 * 1024;

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH2_AGENTC_ADD_IDENTITY: u8 = 17;
pub const SSH_AGENTC_EXTENSION: u8 = 27;

const SESSION_BIND: &[u8] = b"session-bind@openssh.com";

/// One identity this agent instance is scoped to. Holds public data only.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    /// Vault secret name.
    pub name: String,
    pub public_key: PublicKey,
    blob: Vec<u8>,
}

impl AgentIdentity {
    /// The SSH wire-format public key blob.
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }
}

/// Static configuration for one agent instance.
#[derive(Debug, Clone, Default)]
pub struct AgentConfig {
    /// Audit subject (`agent:<id>` or `human`).
    pub subject: String,
    /// Audit project field.
    pub project: String,
    /// Host profile name recorded as `endpoint_host` on sign events.
    pub host_profile: Option<String>,
    /// If set, a `session-bind` naming any other server host key poisons the
    /// connection and every later SIGN on it is refused (defence in depth on
    /// top of `StrictHostKeyChecking=yes` with a pinned `known_hosts`).
    pub expected_host_key_blob: Option<Vec<u8>>,
}

/// Per-connection state.
#[derive(Debug, Default)]
pub struct ConnectionState {
    pub bound_host_key: Option<Vec<u8>>,
    /// Set when the connection was bound to an unexpected host or forwarded.
    pub poisoned: bool,
}

/// The agent. Cheap to share across connection threads via `Arc`.
pub struct SshAgent {
    vault: Arc<Mutex<Vault>>,
    identities: Vec<AgentIdentity>,
    config: AgentConfig,
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    put_u32(out, s.len() as u32);
    out.extend_from_slice(s);
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let (&b, rest) = self.buf.split_first()?;
        self.buf = rest;
        Some(b)
    }
    fn u32(&mut self) -> Option<u32> {
        if self.buf.len() < 4 {
            return None;
        }
        let (head, rest) = self.buf.split_at(4);
        self.buf = rest;
        Some(u32::from_be_bytes([head[0], head[1], head[2], head[3]]))
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        if self.buf.len() < len {
            return None;
        }
        let (s, rest) = self.buf.split_at(len);
        self.buf = rest;
        Some(s)
    }
}

impl SshAgent {
    /// Builds an agent scoped to `identity_names`. Each identity is decrypted
    /// once here to derive its public key, then zeroized; only public keys
    /// are retained. Non-Ed25519 identities are rejected (M1 scope).
    pub fn new(
        vault: Arc<Mutex<Vault>>,
        identity_names: &[String],
        config: AgentConfig,
    ) -> Result<Self, CoreError> {
        let mut identities = Vec::new();
        {
            let v = vault
                .lock()
                .map_err(|_| CoreError::InvalidRequest("vault lock poisoned".into()))?;
            for name in identity_names {
                let public_key = crate::ssh::load_public_key(&v, name)?;
                if public_key.algorithm() != Algorithm::Ed25519 {
                    return Err(CoreError::InvalidRequest(format!(
                        "identity '{name}' is {}; the envy agent supports Ed25519 only",
                        public_key.algorithm().as_str()
                    )));
                }
                let blob = public_key.to_bytes().map_err(|e| {
                    CoreError::InvalidRequest(format!("failed to encode public key: {e}"))
                })?;
                identities.push(AgentIdentity {
                    name: name.clone(),
                    public_key,
                    blob,
                });
            }
        }
        Ok(Self {
            vault,
            identities,
            config,
        })
    }

    pub fn identities(&self) -> &[AgentIdentity] {
        &self.identities
    }

    fn failure() -> Vec<u8> {
        vec![SSH_AGENT_FAILURE]
    }

    /// Handles one decoded message body (type byte + payload) and returns the
    /// response body. Never panics on malformed input.
    pub fn handle_message(&self, state: &mut ConnectionState, msg: &[u8]) -> Vec<u8> {
        let mut r = Reader { buf: msg };
        let Some(kind) = r.u8() else {
            return Self::failure();
        };
        match kind {
            SSH2_AGENTC_REQUEST_IDENTITIES => self.identities_answer(),
            SSH2_AGENTC_SIGN_REQUEST => self.sign(state, &mut r),
            SSH_AGENTC_EXTENSION => self.extension(state, &mut r),
            // ADD_IDENTITY (17), ADD_ID_CONSTRAINED (25), REMOVE_*, LOCK, … :
            // keys enter only through `envy ssh import/generate`.
            _ => Self::failure(),
        }
    }

    fn identities_answer(&self) -> Vec<u8> {
        let mut out = vec![SSH2_AGENT_IDENTITIES_ANSWER];
        put_u32(&mut out, self.identities.len() as u32);
        for id in &self.identities {
            put_string(&mut out, &id.blob);
            let comment = if id.public_key.comment().is_empty() {
                id.name.as_str()
            } else {
                id.public_key.comment()
            };
            put_string(&mut out, comment.as_bytes());
        }
        out
    }

    fn extension(&self, state: &mut ConnectionState, r: &mut Reader) -> Vec<u8> {
        let Some(name) = r.string() else {
            return Self::failure();
        };
        if name != SESSION_BIND {
            return Self::failure();
        }
        let (Some(host_key), Some(_session_id), Some(_sig), Some(is_forwarding)) =
            (r.string(), r.string(), r.string(), r.u8())
        else {
            return Self::failure();
        };
        state.bound_host_key = Some(host_key.to_vec());
        if is_forwarding != 0 {
            // Envy keys are never usable through a forwarded agent.
            state.poisoned = true;
            self.audit(
                "ssh_agent_bind",
                None,
                "denied:forwarded",
                "forwarded agent use refused",
            );
            return Self::failure();
        }
        if let Some(expected) = &self.config.expected_host_key_blob
            && expected.as_slice() != host_key
        {
            state.poisoned = true;
            self.audit(
                "ssh_agent_bind",
                None,
                "denied:host_key_mismatch",
                "session bound to a host key that does not match the pinned key",
            );
            return Self::failure();
        }
        vec![SSH_AGENT_SUCCESS]
    }

    fn sign(&self, state: &ConnectionState, r: &mut Reader) -> Vec<u8> {
        let (Some(key_blob), Some(data), Some(_flags)) = (r.string(), r.string(), r.u32()) else {
            return Self::failure();
        };
        let Some(identity) = self.identities.iter().find(|i| i.blob == key_blob) else {
            return Self::failure();
        };
        if state.poisoned {
            self.audit(
                "ssh_agent_sign",
                Some(&identity.name),
                "denied",
                "connection bound to an unexpected or forwarded host",
            );
            return Self::failure();
        }
        match self.sign_with(identity, data) {
            Ok(sig_blob) => {
                self.audit(
                    "ssh_agent_sign",
                    Some(&identity.name),
                    "success",
                    &format!(
                        "signed with {}",
                        crate::ssh::fingerprint(&identity.public_key)
                    ),
                );
                let mut out = vec![SSH2_AGENT_SIGN_RESPONSE];
                put_string(&mut out, &sig_blob);
                out
            }
            Err(_) => {
                self.audit(
                    "ssh_agent_sign",
                    Some(&identity.name),
                    "failed",
                    "signing failed",
                );
                Self::failure()
            }
        }
    }

    /// Decrypt → sign → zeroize. Returns the SSH signature blob
    /// (`string algorithm, string signature`).
    fn sign_with(&self, identity: &AgentIdentity, data: &[u8]) -> Result<Vec<u8>, CoreError> {
        let raw = {
            let v = self
                .vault
                .lock()
                .map_err(|_| CoreError::InvalidRequest("vault lock poisoned".into()))?;
            Zeroizing::new(v.get_secret(&identity.name)?)
        };
        // `PrivateKey` zeroizes its Ed25519 secret on drop.
        let private = crate::ssh::parse_private_key(&raw)?;
        drop(raw);
        if private.public_key().key_data() != identity.public_key.key_data() {
            return Err(CoreError::InvalidRequest(
                "stored key no longer matches the agent identity".into(),
            ));
        }
        let signature: ssh_key::Signature = private
            .try_sign(data)
            .map_err(|e| CoreError::InvalidRequest(format!("signing failed: {e}")))?;
        drop(private);
        let mut blob = Vec::new();
        put_string(&mut blob, signature.algorithm().as_str().as_bytes());
        put_string(&mut blob, signature.as_bytes());
        Ok(blob)
    }

    /// Audit never includes signed data or key material.
    fn audit(&self, operation: &str, identity: Option<&str>, outcome: &str, summary: &str) {
        if let Ok(v) = self.vault.lock() {
            let _ = v.log_event(&AuditEvent {
                subject: Some(&self.config.subject),
                project: Some(&self.config.project),
                provider: identity,
                operation,
                endpoint_host: self.config.host_profile.as_deref(),
                outcome,
                redaction_summary: Some(summary),
            });
        }
    }

    /// Serves one client connection: loops over framed messages until EOF.
    /// A zero-length or oversized frame gets `FAILURE` and closes the
    /// connection (the stream cannot be resynchronised).
    pub fn serve_stream<S: Read + Write>(&self, mut stream: S) -> io::Result<()> {
        let mut state = ConnectionState::default();
        loop {
            let mut len_buf = [0u8; 4];
            match stream.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            if len == 0 || len > MAX_MESSAGE_LEN {
                write_frame(&mut stream, &Self::failure())?;
                return Ok(());
            }
            let mut msg = vec![0u8; len];
            stream.read_exact(&mut msg)?;
            let response = self.handle_message(&mut state, &msg);
            write_frame(&mut stream, &response)?;
        }
    }
}

fn write_frame<W: Write>(w: &mut W, body: &[u8]) -> io::Result<()> {
    let mut frame = Vec::with_capacity(body.len() + 4);
    put_string(&mut frame, body);
    w.write_all(&frame)?;
    w.flush()
}

// ---------------------------------------------------------------------------
// Unix socket server
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub use unix::*;

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};

    fn io_err(path: &Path, source: io::Error) -> CoreError {
        CoreError::Io {
            path: path.to_path_buf(),
            source,
        }
    }

    /// UID of the process on the other end of `stream`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
        use std::os::fd::AsRawFd;
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: valid fd, correctly sized out-pointer.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut libc::ucred as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cred.uid)
    }

    /// UID of the process on the other end of `stream`.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
        use std::os::fd::AsRawFd;
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: valid fd and out-pointers.
        let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }

    fn own_uid() -> u32 {
        // SAFETY: getuid has no preconditions.
        unsafe { libc::getuid() }
    }

    /// Binds the agent socket with `0600` permissions. A stale socket at
    /// `path` is removed; any other kind of file is left alone (error).
    pub fn bind_agent_socket(path: &Path) -> Result<UnixListener, CoreError> {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_socket() {
                std::fs::remove_file(path).map_err(|e| io_err(path, e))?;
            } else {
                return Err(io_err(
                    path,
                    io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "path exists and is not a socket",
                    ),
                ));
            }
        }
        let listener = UnixListener::bind(path).map_err(|e| io_err(path, e))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| io_err(path, e))?;
        Ok(listener)
    }

    /// Accept loop: same-UID peers only, one thread per connection. Returns
    /// when `stop` is set (checked after each accept).
    pub fn serve_listener(
        agent: Arc<SshAgent>,
        listener: UnixListener,
        stop: Option<Arc<AtomicBool>>,
    ) -> io::Result<()> {
        let me = own_uid();
        for conn in listener.incoming() {
            if stop.as_ref().is_some_and(|s| s.load(Ordering::SeqCst)) {
                return Ok(());
            }
            let Ok(stream) = conn else { continue };
            match peer_uid(&stream) {
                Ok(uid) if uid == me => {}
                _ => continue, // drop the connection
            }
            let agent = Arc::clone(&agent);
            std::thread::spawn(move || {
                let _ = agent.serve_stream(stream);
            });
        }
        Ok(())
    }

    /// A short-lived agent for one `ssh` invocation (M1 / G2 fix).
    ///
    /// Lives in a fresh `0700` temp dir holding only: the agent socket, the
    /// identity's **public** key (for `IdentityFile` + `IdentitiesOnly`), and
    /// the pinned `known_hosts` line. Torn down on drop.
    pub struct EphemeralAgent {
        dir: tempfile::TempDir,
        pub socket_path: PathBuf,
        pub public_key_path: PathBuf,
        pub known_hosts_path: Option<PathBuf>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl EphemeralAgent {
        pub fn start(agent: SshAgent, known_hosts_line: Option<&str>) -> Result<Self, CoreError> {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::Builder::new()
                .prefix("envy-ssh-")
                .tempdir()
                .map_err(|e| io_err(Path::new("/tmp"), e))?;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
                .map_err(|e| io_err(dir.path(), e))?;

            let identity = agent.identities().first().cloned().ok_or_else(|| {
                CoreError::InvalidRequest("ephemeral agent needs one identity".into())
            })?;
            let public_key_path = dir.path().join("identity.pub");
            let pub_line = identity
                .public_key
                .to_openssh()
                .map_err(|e| CoreError::InvalidRequest(format!("encode public key: {e}")))?;
            write_private_file(&public_key_path, format!("{pub_line}\n").as_bytes())?;

            let known_hosts_path = match known_hosts_line {
                Some(line) => {
                    let p = dir.path().join("known_hosts");
                    write_private_file(&p, format!("{line}\n").as_bytes())?;
                    Some(p)
                }
                None => None,
            };

            let socket_path = dir.path().join("agent.sock");
            let listener = bind_agent_socket(&socket_path)?;
            let stop = Arc::new(AtomicBool::new(false));
            let agent = Arc::new(agent);
            let stop_thread = Arc::clone(&stop);
            let thread = std::thread::spawn(move || {
                let _ = serve_listener(agent, listener, Some(stop_thread));
            });
            Ok(Self {
                dir,
                socket_path,
                public_key_path,
                known_hosts_path,
                stop,
                thread: Some(thread),
            })
        }

        /// The session directory (for tests / diagnostics).
        pub fn dir(&self) -> &Path {
            self.dir.path()
        }

        /// `ssh` options that route authentication through this agent and pin
        /// the host key. Contains paths only — never key material.
        pub fn ssh_options(&self) -> Vec<String> {
            let mut opts = vec![
                "-o".into(),
                format!("IdentityAgent={}", self.socket_path.display()),
                "-o".into(),
                "IdentitiesOnly=yes".into(),
                "-o".into(),
                format!("IdentityFile={}", self.public_key_path.display()),
                "-o".into(),
                "ForwardAgent=no".into(),
                "-o".into(),
                "StrictHostKeyChecking=yes".into(),
            ];
            if let Some(kh) = &self.known_hosts_path {
                opts.extend([
                    "-o".into(),
                    format!("UserKnownHostsFile={}", kh.display()),
                    "-o".into(),
                    "GlobalKnownHostsFile=/dev/null".into(),
                ]);
            }
            opts
        }
    }

    impl Drop for EphemeralAgent {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            // Wake the blocking accept so the thread can observe `stop`.
            let _ = UnixStream::connect(&self.socket_path);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    fn write_private_file(path: &Path, data: &[u8]) -> Result<(), CoreError> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| io_err(path, e))?;
        f.write_all(data).map_err(|e| io_err(path, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::InMemoryKeyStore;
    use crate::ssh::tests::{FIXTURE_ED25519, FIXTURE_FINGERPRINT};
    use crate::vault::init_with_keystore;
    use signature::Verifier;

    fn agent_with(names: &[&str], extra: &[(&str, &[u8])]) -> (tempfile::TempDir, SshAgent) {
        let dir = tempfile::tempdir().unwrap();
        let store = InMemoryKeyStore::new();
        let vault = init_with_keystore(dir.path(), &store).unwrap();
        for (name, value) in extra {
            vault.add_secret(name, value).unwrap();
        }
        let vault = Arc::new(Mutex::new(vault));
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let agent = SshAgent::new(
            vault,
            &names,
            AgentConfig {
                subject: "human".into(),
                project: "test".into(),
                host_profile: Some("prod".into()),
                expected_host_key_blob: None,
            },
        )
        .unwrap();
        (dir, agent)
    }

    fn parse_identities(resp: &[u8]) -> Vec<(Vec<u8>, String)> {
        let mut r = Reader { buf: resp };
        assert_eq!(r.u8(), Some(SSH2_AGENT_IDENTITIES_ANSWER));
        let n = r.u32().unwrap();
        (0..n)
            .map(|_| {
                let blob = r.string().unwrap().to_vec();
                let comment = String::from_utf8(r.string().unwrap().to_vec()).unwrap();
                (blob, comment)
            })
            .collect()
    }

    fn sign_request(blob: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = vec![SSH2_AGENTC_SIGN_REQUEST];
        put_string(&mut m, blob);
        put_string(&mut m, data);
        put_u32(&mut m, 0);
        m
    }

    fn session_bind(host_key_blob: &[u8], forwarding: bool) -> Vec<u8> {
        let mut m = vec![SSH_AGENTC_EXTENSION];
        put_string(&mut m, SESSION_BIND);
        put_string(&mut m, host_key_blob);
        put_string(&mut m, b"session-id");
        put_string(&mut m, b"sig");
        m.push(forwarding as u8);
        m
    }

    #[test]
    fn identities_answer_for_zero_and_one_keys() {
        let (_d, empty) = agent_with(&[], &[]);
        let resp = empty.handle_message(&mut ConnectionState::default(), &[11]);
        assert!(parse_identities(&resp).is_empty());

        let (_d, agent) = agent_with(&["deploy"], &[("deploy", FIXTURE_ED25519.as_bytes())]);
        let resp = agent.handle_message(&mut ConnectionState::default(), &[11]);
        let ids = parse_identities(&resp);
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].1, "envy-fixture");
        let pk = PublicKey::from_bytes(&ids[0].0).unwrap();
        assert_eq!(crate::ssh::fingerprint(&pk), FIXTURE_FINGERPRINT);
    }

    #[test]
    fn list_then_sign_round_trip_verifies_with_public_key() {
        let (_d, agent) = agent_with(&["deploy"], &[("deploy", FIXTURE_ED25519.as_bytes())]);
        let mut state = ConnectionState::default();
        let ids = parse_identities(&agent.handle_message(&mut state, &[11]));
        let (blob, _) = &ids[0];

        let data = b"session-id-and-userauth-request";
        let resp = agent.handle_message(&mut state, &sign_request(blob, data));
        let mut r = Reader { buf: &resp };
        assert_eq!(r.u8(), Some(SSH2_AGENT_SIGN_RESPONSE));
        let sig_blob = r.string().unwrap();
        let mut sr = Reader { buf: sig_blob };
        assert_eq!(sr.string().unwrap(), b"ssh-ed25519");
        let raw_sig = sr.string().unwrap();
        assert_eq!(raw_sig.len(), 64);

        let public = PublicKey::from_bytes(blob).unwrap();
        let sig = ssh_key::Signature::new(Algorithm::Ed25519, raw_sig.to_vec()).unwrap();
        Verifier::verify(&public, data, &sig).expect("signature verifies");
        assert!(Verifier::verify(&public, b"tampered", &sig).is_err());

        // Signing writes an audit event without the signed data.
        let v = agent.vault.lock().unwrap();
        let events = v.list_events(None).unwrap();
        let ev = events
            .iter()
            .find(|e| e.operation == "ssh_agent_sign")
            .unwrap();
        assert_eq!(ev.outcome, "success");
        assert_eq!(ev.subject.as_deref(), Some("human"));
        let summary = ev.redaction_summary.clone().unwrap();
        assert!(!summary.contains("session-id-and-userauth-request"));
    }

    #[test]
    fn unknown_key_malformed_and_add_identity_are_refused() {
        let (_d, agent) = agent_with(&["deploy"], &[("deploy", FIXTURE_ED25519.as_bytes())]);
        let mut st = ConnectionState::default();
        assert_eq!(
            agent.handle_message(&mut st, &sign_request(b"not-a-key", b"x")),
            vec![SSH_AGENT_FAILURE]
        );
        assert_eq!(
            agent.handle_message(&mut st, &[13, 0, 0]),
            vec![SSH_AGENT_FAILURE]
        );
        assert_eq!(agent.handle_message(&mut st, &[]), vec![SSH_AGENT_FAILURE]);
        let mut add = vec![SSH2_AGENTC_ADD_IDENTITY];
        put_string(&mut add, b"ssh-ed25519");
        assert_eq!(agent.handle_message(&mut st, &add), vec![SSH_AGENT_FAILURE]);
        assert_eq!(
            agent.handle_message(&mut st, &[99]),
            vec![SSH_AGENT_FAILURE]
        );
        assert_eq!(agent.identities().len(), 1);
    }

    #[test]
    fn non_ed25519_or_non_ssh_identity_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = InMemoryKeyStore::new();
        let vault = init_with_keystore(dir.path(), &store).unwrap();
        vault.add_secret("api", b"sk_test_123").unwrap();
        let vault = Arc::new(Mutex::new(vault));
        assert!(SshAgent::new(vault, &["api".to_string()], AgentConfig::default()).is_err());
    }

    #[test]
    fn session_bind_to_unpinned_host_key_blocks_signing() {
        let pinned = crate::ssh::host_key_blob(crate::ssh::tests::FIXTURE_ED25519_PUB).unwrap();
        let (_d, mut agent) = agent_with(&["deploy"], &[("deploy", FIXTURE_ED25519.as_bytes())]);
        agent.config.expected_host_key_blob = Some(pinned.clone());
        let blob = agent.identities()[0].blob().to_vec();

        // Matching host key: bind succeeds, signing works.
        let mut ok = ConnectionState::default();
        assert_eq!(
            agent.handle_message(&mut ok, &session_bind(&pinned, false)),
            vec![6]
        );
        assert_eq!(
            agent.handle_message(&mut ok, &sign_request(&blob, b"d"))[0],
            14
        );

        // Swapped host key: bind refused and the connection can't sign.
        let other = {
            let mut rng = rand::rngs::OsRng;
            ssh_key::PrivateKey::random(&mut rng, Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .to_bytes()
                .unwrap()
        };
        let mut bad = ConnectionState::default();
        assert_eq!(
            agent.handle_message(&mut bad, &session_bind(&other, false)),
            vec![SSH_AGENT_FAILURE]
        );
        assert!(bad.poisoned);
        assert_eq!(
            agent.handle_message(&mut bad, &sign_request(&blob, b"d")),
            vec![SSH_AGENT_FAILURE]
        );

        // Forwarded use is refused.
        let mut fwd = ConnectionState::default();
        assert_eq!(
            agent.handle_message(&mut fwd, &session_bind(&pinned, true)),
            vec![SSH_AGENT_FAILURE]
        );
        assert_eq!(
            agent.handle_message(&mut fwd, &sign_request(&blob, b"d")),
            vec![SSH_AGENT_FAILURE]
        );
    }

    /// In-memory duplex stream for driving `serve_stream`.
    struct Duplex {
        input: io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }
    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        put_string(&mut f, body);
        f
    }

    #[test]
    fn serve_stream_handles_multiple_messages_and_oversize() {
        let (_d, agent) = agent_with(&["deploy"], &[("deploy", FIXTURE_ED25519.as_bytes())]);
        let mut input = frame(&[11]);
        input.extend(frame(&[11]));
        let mut d = Duplex {
            input: io::Cursor::new(input),
            output: Vec::new(),
        };
        agent.serve_stream(&mut d).unwrap();
        let mut r = Reader { buf: &d.output };
        let first = r.string().unwrap();
        let second = r.string().unwrap();
        assert_eq!(first[0], 12);
        assert_eq!(first, second);

        let mut big = Vec::new();
        put_u32(&mut big, (MAX_MESSAGE_LEN + 1) as u32);
        let mut d = Duplex {
            input: io::Cursor::new(big),
            output: Vec::new(),
        };
        agent.serve_stream(&mut d).unwrap();
        assert_eq!(d.output, frame(&[SSH_AGENT_FAILURE]));
    }

    #[cfg(unix)]
    #[test]
    fn unix_socket_serves_two_requests_on_one_connection() {
        use std::os::unix::net::UnixStream;
        let (_d, agent) = agent_with(&["deploy"], &[("deploy", FIXTURE_ED25519.as_bytes())]);
        let sock_dir = tempfile::tempdir().unwrap();
        let path = sock_dir.path().join("a.sock");
        let listener = bind_agent_socket(&path).unwrap();
        let agent = Arc::new(agent);
        std::thread::spawn(move || {
            let _ = serve_listener(agent, listener, None);
        });
        let mut c = UnixStream::connect(&path).unwrap();
        for _ in 0..2 {
            c.write_all(&frame(&[11])).unwrap();
            let mut len = [0u8; 4];
            c.read_exact(&mut len).unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            c.read_exact(&mut body).unwrap();
            assert_eq!(parse_identities(&body).len(), 1);
        }
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn ephemeral_agent_writes_no_private_key_to_disk() {
        let (_d, agent) = agent_with(&["deploy"], &[("deploy", FIXTURE_ED25519.as_bytes())]);
        let eph = EphemeralAgent::start(
            agent,
            Some("[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB6cgv5HKKUsq6udElcTQog97Q7H+5pnlC9DqXyH2wuI"),
        )
        .unwrap();
        let dir = eph.dir().to_path_buf();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p == eph.socket_path {
                continue;
            }
            let text = std::fs::read_to_string(&p).unwrap();
            assert!(
                !text.contains("PRIVATE KEY"),
                "{} holds private key",
                p.display()
            );
        }
        let opts = eph.ssh_options().join(" ");
        assert!(opts.contains("StrictHostKeyChecking=yes"));
        assert!(opts.contains("ForwardAgent=no"));
        assert!(opts.contains("GlobalKnownHostsFile=/dev/null"));
        assert!(!opts.contains("PRIVATE"));
        drop(eph);
        assert!(!dir.exists());
    }
}
