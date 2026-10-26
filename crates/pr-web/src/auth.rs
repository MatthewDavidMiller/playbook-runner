//! Operator authentication: the admin password, sessions, CSRF tokens, and
//! login throttling.
//!
//! The admin password is stored as `pbkdf2:sha256:<iterations>$<salt>$<hex>`
//! in `<data>/admin.password` (mode 0600), sealed with the master key like
//! every other file in the data directory. Sessions are random 256-bit
//! identifiers held only in memory, keyed by HMAC(web key, id), so a restart
//! signs everyone out and nothing on disk yields a usable cookie. CSRF tokens
//! are HMAC(web key, "csrf", session id) and are compared in constant time.
//!
//! Until an admin password exists the server prints a one-time setup token
//! to its log, and `/setup` requires it: whoever reaches the page first
//! cannot claim the instance without also reading the container's log.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use pr_common::{Error, Result, fsio, rand};
use pr_crypto::{SubKey, cleanse, ct_equal, hex, hmac_sha256, pbkdf2_sha256};
use pr_store::Sealer;

use crate::html::Tone;

pub const MINIMUM_PASSWORD_BYTES: usize = 12;
pub const MAXIMUM_PASSWORD_BYTES: usize = 128;
pub const SESSION_COOKIE: &str = "pr_session";
pub const LOGIN_COOKIE: &str = "pr_login";

const PBKDF2_ITERATIONS: u32 = 600_000;
const PASSWORD_FILE_LIMIT: usize = 512 + pr_store::sealed::OVERHEAD;
/// The authenticated label of the sealed password file.
const PASSWORD_LABEL: &str = "admin/password";
const MAXIMUM_SESSIONS: usize = 64;
const MAXIMUM_FLASHES: usize = 8;
/// Failed logins a client may make inside the window before it is locked
/// out until the oldest failure ages out.
const FAILURE_LIMIT: usize = 5;
const FAILURE_WINDOW: Duration = Duration::from_mins(15);
const MAXIMUM_TRACKED_CLIENTS: usize = 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn validate_new_password(password: &str) -> Result<()> {
    if !(MINIMUM_PASSWORD_BYTES..=MAXIMUM_PASSWORD_BYTES).contains(&password.len()) {
        return Err(Error::new(format!(
            "The password must be {MINIMUM_PASSWORD_BYTES}-{MAXIMUM_PASSWORD_BYTES} bytes long"
        )));
    }
    if password.chars().any(char::is_control) {
        return Err(Error::new("The password must not contain control characters"));
    }
    Ok(())
}

/// Seals `hash_line` (a [`hash_password`] result and a newline) and writes it
/// as `<data_dir>/admin.password`.
pub fn store_password_hash(data_dir: &Path, sealer: &Sealer, hash_line: &str) -> Result<()> {
    let sealed = sealer.seal(PASSWORD_LABEL, hash_line.as_bytes())?;
    fsio::atomic_replace(data_dir.join("admin.password"), &sealed, PASSWORD_FILE_LIMIT)
}

/// `pbkdf2:sha256:600000$SALT$DIGEST` for a new password.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = rand::random_hex(16)?;
    let mut digest = [0_u8; 32];
    pbkdf2_sha256(password.as_bytes(), salt.as_bytes(), PBKDF2_ITERATIONS, &mut digest)
        .map_err(|_| Error::new("unable to derive the password hash"))?;
    let out = format!("pbkdf2:sha256:{PBKDF2_ITERATIONS}${salt}${}", hex(&digest));
    cleanse(&mut digest);
    Ok(out)
}

/// Checks `supplied` against a stored hash. A malformed hash never matches.
pub fn verify_password(stored: &str, supplied: &str) -> bool {
    let Some(rest) = stored.trim().strip_prefix("pbkdf2:sha256:") else { return false };
    let mut parts = rest.splitn(3, '$');
    let (Some(iterations), Some(salt), Some(expected)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Ok(iterations) = iterations.parse::<u32>() else { return false };
    if iterations == 0 || iterations > 10_000_000 || expected.len() != 64 {
        return false;
    }
    let mut digest = [0_u8; 32];
    let ok = pbkdf2_sha256(supplied.as_bytes(), salt.as_bytes(), iterations, &mut digest).is_ok()
        && ct_equal(hex(&digest).as_bytes(), expected.as_bytes());
    cleanse(&mut digest);
    ok
}

#[derive(Debug)]
struct Session {
    expires: Instant,
    flashes: Vec<(Tone, String)>,
}

#[derive(Debug)]
pub struct Auth {
    password_file: PathBuf,
    sealer: Arc<Sealer>,
    web_key: SubKey,
    lifetime: Duration,
    sessions: Mutex<HashMap<String, Session>>,
    failures: Mutex<HashMap<String, VecDeque<Instant>>>,
    /// Present only while no admin password exists.
    setup_token: Mutex<Option<String>>,
}

impl Auth {
    /// Loads the password file, seeding it from `seed` when it is missing,
    /// and creates a setup token when there is still no password.
    pub fn new(
        data_dir: &Path,
        web_key: SubKey,
        lifetime_s: u64,
        seed: Option<&Path>,
        sealer: Arc<Sealer>,
    ) -> Result<Self> {
        let auth = Self {
            password_file: data_dir.join("admin.password"),
            sealer,
            web_key,
            lifetime: Duration::from_secs(lifetime_s),
            sessions: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            setup_token: Mutex::new(None),
        };
        // A hash written before sealing existed is sealed now.
        if let Some(raw) = fsio::read_bounded(&auth.password_file, PASSWORD_FILE_LIMIT)?
            && !Sealer::is_sealed(&raw)
        {
            let line = String::from_utf8_lossy(&raw).trim().to_owned();
            store_password_hash(data_dir, &auth.sealer, &format!("{line}\n"))?;
        }
        if auth.stored_hash()?.is_none() {
            if let Some(seed) = seed {
                let mut text = fsio::read_text(seed, PASSWORD_FILE_LIMIT)?
                    .ok_or_else(|| Error::new("PR_ADMIN_PASSWORD_FILE does not exist"))?;
                let result = auth.set_password(text.trim_end_matches(['\r', '\n']));
                pr_common::buf::wipe_string(&mut text);
                result?;
            } else {
                *lock(&auth.setup_token) = Some(rand::random_hex(16)?);
            }
        }
        Ok(auth)
    }

    fn stored_hash(&self) -> Result<Option<String>> {
        let Some(raw) = fsio::read_bounded(&self.password_file, PASSWORD_FILE_LIMIT)? else {
            return Ok(None);
        };
        let (plain, _) = self.sealer.open_any(PASSWORD_LABEL, raw)?;
        Ok(Some(String::from_utf8_lossy(plain.expose()).trim().to_owned())
            .filter(|t| !t.is_empty()))
    }

    pub fn needs_setup(&self) -> bool {
        lock(&self.setup_token).is_some()
    }

    /// The one-time token for `/setup`, for the startup log.
    pub fn setup_token(&self) -> Option<String> {
        lock(&self.setup_token).clone()
    }

    pub fn check_setup_token(&self, supplied: &str) -> bool {
        lock(&self.setup_token)
            .as_deref()
            .is_some_and(|t| ct_equal(t.as_bytes(), supplied.as_bytes()))
    }

    /// Replaces the admin password and ends every session.
    pub fn set_password(&self, password: &str) -> Result<()> {
        validate_new_password(password)?;
        let mut line = hash_password(password)?;
        line.push('\n');
        let dir = self.password_file.parent().unwrap_or_else(|| Path::new("."));
        store_password_hash(dir, &self.sealer, &line)?;
        lock(&self.sessions).clear();
        *lock(&self.setup_token) = None;
        Ok(())
    }

    pub fn password_matches(&self, supplied: &str) -> bool {
        matches!(self.stored_hash(), Ok(Some(h)) if verify_password(&h, supplied))
    }

    fn keyed(&self, label: &[u8], data: &str) -> String {
        let mut msg = Vec::with_capacity(label.len() + 1 + data.len());
        msg.extend_from_slice(label);
        msg.push(0);
        msg.extend_from_slice(data.as_bytes());
        // HMAC over a few hundred bytes cannot fail short of libcrypto
        // itself being broken; an empty key then matches nothing.
        hmac_sha256(self.web_key.bytes(), &msg).map(|d| hex(&d)).unwrap_or_default()
    }

    fn session_key(&self, id: &str) -> Option<String> {
        (id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| self.keyed(b"session", id))
            .filter(|k| !k.is_empty())
    }

    /// Starts a session and returns its identifier.
    pub fn create_session(&self) -> Result<String> {
        let id = rand::random_hex(32)?;
        let key =
            self.session_key(&id).ok_or_else(|| Error::new("unable to derive a session key"))?;
        let now = Instant::now();
        let mut sessions = lock(&self.sessions);
        sessions.retain(|_, s| s.expires > now);
        while sessions.len() >= MAXIMUM_SESSIONS {
            let oldest = sessions.iter().min_by_key(|(_, s)| s.expires).map(|(k, _)| k.clone());
            match oldest {
                Some(k) => sessions.remove(&k),
                None => break,
            };
        }
        sessions.insert(key, Session { expires: now + self.lifetime, flashes: Vec::new() });
        Ok(id)
    }

    pub fn is_valid(&self, id: &str) -> bool {
        let Some(key) = self.session_key(id) else { return false };
        lock(&self.sessions).get(&key).is_some_and(|s| s.expires > Instant::now())
    }

    pub fn end_session(&self, id: &str) {
        if let Some(key) = self.session_key(id) {
            lock(&self.sessions).remove(&key);
        }
    }

    pub fn flash(&self, id: &str, tone: Tone, message: impl Into<String>) {
        let Some(key) = self.session_key(id) else { return };
        if let Some(s) = lock(&self.sessions).get_mut(&key)
            && s.flashes.len() < MAXIMUM_FLASHES
        {
            s.flashes.push((tone, message.into()));
        }
    }

    pub fn take_flashes(&self, id: &str) -> Vec<(Tone, String)> {
        let Some(key) = self.session_key(id) else { return Vec::new() };
        lock(&self.sessions)
            .get_mut(&key)
            .map(|s| std::mem::take(&mut s.flashes))
            .unwrap_or_default()
    }

    pub fn csrf_token(&self, session_id: &str) -> String {
        self.keyed(b"csrf", session_id)
    }

    pub fn verify_csrf(&self, session_id: &str, token: &str) -> bool {
        let expected = self.csrf_token(session_id);
        !expected.is_empty() && ct_equal(expected.as_bytes(), token.as_bytes())
    }

    /// The token the login form carries, bound to its pre-session cookie.
    pub fn login_token(&self, nonce: &str) -> String {
        self.keyed(b"login", nonce)
    }

    pub fn verify_login_token(&self, nonce: &str, token: &str) -> bool {
        nonce.len() == 32 && ct_equal(self.login_token(nonce).as_bytes(), token.as_bytes())
    }

    /// Seconds until `client` may try again, or `None` when it may now.
    pub fn locked_out(&self, client: &str) -> Option<u64> {
        let now = Instant::now();
        let mut failures = lock(&self.failures);
        let entry = failures.get_mut(client)?;
        while entry.front().is_some_and(|t| now.duration_since(*t) > FAILURE_WINDOW) {
            entry.pop_front();
        }
        if entry.len() < FAILURE_LIMIT {
            return None;
        }
        let oldest = *entry.front()?;
        Some((FAILURE_WINDOW.saturating_sub(now.duration_since(oldest))).as_secs().max(1))
    }

    pub fn record_failure(&self, client: &str) {
        let mut failures = lock(&self.failures);
        if failures.len() >= MAXIMUM_TRACKED_CLIENTS && !failures.contains_key(client) {
            // Forget the clients whose failures are all stale, then, if
            // still full, refuse to track more rather than grow.
            let now = Instant::now();
            failures
                .retain(|_, v| v.back().is_some_and(|t| now.duration_since(*t) <= FAILURE_WINDOW));
            if failures.len() >= MAXIMUM_TRACKED_CLIENTS {
                return;
            }
        }
        let entry = failures.entry(client.to_owned()).or_default();
        entry.push_back(Instant::now());
        while entry.len() > FAILURE_LIMIT {
            entry.pop_front();
        }
    }

    pub fn clear_failures(&self, client: &str) {
        lock(&self.failures).remove(client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pr_crypto::MasterKey;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pr-auth-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sealer() -> Arc<Sealer> {
        Arc::new(Sealer::new(&MasterKey::from_hex(&[b'a'; 64]).unwrap()).unwrap())
    }

    fn key() -> SubKey {
        MasterKey::from_hex(&[b'a'; 64]).unwrap().derive("web").unwrap()
    }

    #[test]
    fn password_hashes_verify_and_reject() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("pbkdf2:sha256:600000$"));
        assert!(verify_password(&h, "correct horse battery"));
        assert!(!verify_password(&h, "correct horse batterz"));
        assert!(!verify_password("plain", "plain"));
        assert!(!verify_password("pbkdf2:sha256:0$s$00", ""));
        assert!(validate_new_password("short").is_err());
        assert!(validate_new_password("has a\ttab in it").is_err());
    }

    #[test]
    fn setup_token_until_a_password_exists() {
        let dir = scratch("setup");
        let auth = Auth::new(&dir, key(), 3600, None, sealer()).unwrap();
        assert!(auth.needs_setup());
        let token = auth.setup_token().unwrap();
        assert!(auth.check_setup_token(&token));
        assert!(!auth.check_setup_token("wrong"));
        auth.set_password("a long enough password").unwrap();
        assert!(!auth.needs_setup());
        assert!(!auth.check_setup_token(&token));
        assert!(auth.password_matches("a long enough password"));
        // A restart finds the stored password and offers no setup.
        assert!(!Auth::new(&dir, key(), 3600, None, sealer()).unwrap().needs_setup());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_hash_is_sealed_on_disk_and_a_plain_one_is_upgraded() {
        let dir = scratch("sealed");
        let auth = Auth::new(&dir, key(), 3600, None, sealer()).unwrap();
        auth.set_password("a long enough password").unwrap();
        let raw = std::fs::read(dir.join("admin.password")).unwrap();
        assert!(Sealer::is_sealed(&raw));
        assert!(!raw.windows(6).any(|w| w == b"pbkdf2"));
        // An install from before sealing has a plain hash file.
        let hash = hash_password("an older password!").unwrap();
        std::fs::write(dir.join("admin.password"), format!("{hash}\n")).unwrap();
        let auth = Auth::new(&dir, key(), 3600, None, sealer()).unwrap();
        assert!(auth.password_matches("an older password!"));
        assert!(Sealer::is_sealed(&std::fs::read(dir.join("admin.password")).unwrap()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn seed_file_sets_the_first_password() {
        let dir = scratch("seed");
        let seed = dir.join("seed");
        std::fs::write(&seed, "seeded password value\n").unwrap();
        let auth = Auth::new(&dir, key(), 3600, Some(&seed), sealer()).unwrap();
        assert!(!auth.needs_setup());
        assert!(auth.password_matches("seeded password value"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sessions_csrf_and_password_change() {
        let dir = scratch("sessions");
        let auth = Auth::new(&dir, key(), 3600, None, sealer()).unwrap();
        let id = auth.create_session().unwrap();
        assert!(auth.is_valid(&id));
        assert!(!auth.is_valid("nothex"));
        let token = auth.csrf_token(&id);
        assert!(auth.verify_csrf(&id, &token));
        assert!(!auth.verify_csrf(&id, "00"));
        let other = auth.create_session().unwrap();
        assert!(!auth.verify_csrf(&other, &token));
        auth.flash(&id, Tone::Success, "saved");
        assert_eq!(auth.take_flashes(&id).len(), 1);
        assert!(auth.take_flashes(&id).is_empty());
        auth.set_password("a brand new password").unwrap();
        assert!(!auth.is_valid(&id) && !auth.is_valid(&other));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn throttling_locks_after_repeated_failures() {
        let dir = scratch("throttle");
        let auth = Auth::new(&dir, key(), 3600, None, sealer()).unwrap();
        for _ in 0..FAILURE_LIMIT - 1 {
            auth.record_failure("10.0.0.1");
        }
        assert_eq!(auth.locked_out("10.0.0.1"), None);
        auth.record_failure("10.0.0.1");
        assert!(auth.locked_out("10.0.0.1").is_some());
        assert_eq!(auth.locked_out("10.0.0.2"), None);
        auth.clear_failures("10.0.0.1");
        assert_eq!(auth.locked_out("10.0.0.1"), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
