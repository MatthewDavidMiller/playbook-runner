//! End-to-end tests of the web interface: a real listener on loopback, real
//! HTTP over TCP, and the setup, login, CSRF, and throttling flows a browser
//! would go through.

// Test helpers outside #[test] functions: a failed step should panic loudly.
#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::format_push_string
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use pr_crypto::MasterKey;
use pr_web::app::App;
use pr_web::auth::Auth;
use pr_web::config::Config;

#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// `name=value` of the Set-Cookie for `name`.
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie")).find_map(
            |(_, v)| {
                let pair = v.split(';').next()?;
                pair.starts_with(&format!("{name}=")).then(|| pair.to_owned())
            },
        )
    }

    /// The value of the first hidden csrf_token input.
    pub fn csrf(&self) -> String {
        let marker = "name=\"csrf_token\" value=\"";
        let start = self.body.find(marker).expect("no csrf field") + marker.len();
        self.body[start..].split('"').next().unwrap().to_owned()
    }
}

#[derive(Debug)]
pub struct Server {
    pub addr: std::net::SocketAddr,
    pub dir: PathBuf,
    pub token: Option<String>,
}

impl Server {
    pub fn start(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("pr-web-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = Config {
            listen: addr,
            data_dir: dir.clone(),
            work_dir: dir.join("work"),
            master_key_file: dir.join("key"),
            admin_password_file: None,
            trusted_proxies: Vec::new(),
            secure_cookies: false,
            session_seconds: 3600,
            timezone: "UTC".into(),
        };
        let key = MasterKey::from_hex(&[b'7'; 64]).unwrap();
        let auth = Auth::new(&dir, key.derive("web").unwrap(), 3600, None).unwrap();
        let token = auth.setup_token();
        let store = pr_store::Store::open(&dir, &key).unwrap();
        let app = Arc::new(App::new(config, auth, store));
        thread::spawn(move || pr_web::http::serve(&listener, &app));
        Self { addr, dir, token }
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        cookies: &[&str],
        form: Option<&str>,
        extra: &[(&str, &str)],
    ) -> Reply {
        let mut stream = TcpStream::connect(self.addr).unwrap();
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\n", self.addr);
        if !cookies.is_empty() {
            req.push_str(&format!("Cookie: {}\r\n", cookies.join("; ")));
        }
        for (k, v) in extra {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        let body = form.unwrap_or("");
        if form.is_some() {
            req.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        req.push_str("\r\n");
        req.push_str(body);
        stream.write_all(req.as_bytes()).unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).unwrap();
        let text = String::from_utf8(raw).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        let mut lines = head.split("\r\n");
        let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
        let headers = lines
            .map(|l| {
                let (k, v) = l.split_once(':').unwrap();
                (k.to_owned(), v.trim().to_owned())
            })
            .collect();
        Reply { status, headers, body: body.to_owned() }
    }

    pub fn get(&self, path: &str, cookies: &[&str]) -> Reply {
        self.request("GET", path, cookies, None, &[])
    }

    pub fn post(&self, path: &str, cookies: &[&str], form: &str) -> Reply {
        self.request("POST", path, cookies, Some(form), &[])
    }

    /// Completes setup with `password` and signs in; returns the session
    /// cookie and its CSRF token.
    pub fn sign_in(&self, password: &str) -> (String, String) {
        if let Some(token) = &self.token {
            let r = self.post(
                "/setup",
                &[],
                &format!("token={token}&password={password}&confirm={password}"),
            );
            assert_eq!(r.status, 303, "{}", r.body);
        }
        let form = self.get("/login", &[]);
        let nonce = form.cookie("pr_login").unwrap();
        let r = self.post(
            "/login",
            &[&nonce],
            &format!("csrf_token={}&password={password}", form.csrf()),
        );
        assert_eq!(r.status, 303, "{}", r.body);
        let session = r.cookie("pr_session").unwrap();
        let dash = self.get("/", &[&session]);
        assert_eq!(dash.status, 200);
        (session, dash.csrf())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const PASSWORD: &str = "integration+test+password";

#[test]
fn health_and_static_need_no_session() {
    let s = Server::start("static");
    assert_eq!(s.get("/healthz", &[]).body, "ok");
    let css = s.get("/static/style.css", &[]);
    assert_eq!(css.status, 200);
    assert_eq!(css.header("content-type"), Some("text/css; charset=utf-8"));
    let head = s.request("HEAD", "/healthz", &[], None, &[]);
    assert_eq!((head.status, head.body.as_str()), (200, ""));
}

#[test]
fn every_response_carries_the_security_headers() {
    let s = Server::start("headers");
    let r = s.get("/setup", &[]);
    let csp = r.header("content-security-policy").unwrap();
    assert!(csp.contains("default-src 'none'") && csp.contains("frame-ancestors 'none'"));
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(r.header("cache-control"), Some("no-store"));
}

#[test]
fn setup_requires_the_token_then_closes() {
    let s = Server::start("setup");
    assert_eq!(s.get("/", &[]).header("location"), Some("/setup"));
    let wrong =
        s.post("/setup", &[], &format!("token=nope&password={PASSWORD}&confirm={PASSWORD}"));
    assert_eq!(wrong.status, 400);
    assert!(wrong.body.contains("setup token is incorrect"));
    let token = s.token.clone().unwrap();
    let short = s.post("/setup", &[], &format!("token={token}&password=short&confirm=short"));
    assert!(short.body.contains("12-128"));
    let ok =
        s.post("/setup", &[], &format!("token={token}&password={PASSWORD}&confirm={PASSWORD}"));
    assert_eq!(ok.header("location"), Some("/login"));
    // Once a password exists the setup page is gone.
    assert_eq!(s.get("/setup", &[]).header("location"), Some("/login"));
    let again = s.post("/setup", &[], &format!("token={token}&password=x&confirm=x"));
    assert_eq!(again.header("location"), Some("/login"));
}

#[test]
fn login_requires_its_form_token_and_the_password() {
    let s = Server::start("login");
    let (session, _) = s.sign_in(PASSWORD);
    assert!(session.starts_with("pr_session="));
    // A login post without the form's cookie-bound token is refused.
    let r = s.post("/login", &[], &format!("csrf_token=00&password={PASSWORD}"));
    assert!(r.body.contains("expired"));
    assert!(r.cookie("pr_session").is_none());
    // Wrong password.
    let form = s.get("/login", &[]);
    let nonce = form.cookie("pr_login").unwrap();
    let r = s.post("/login", &[&nonce], &format!("csrf_token={}&password=wrong", form.csrf()));
    assert_eq!(r.status, 401);
    assert!(r.cookie("pr_session").is_none());
}

#[test]
fn posts_require_csrf_and_same_origin() {
    let s = Server::start("csrf");
    let (session, csrf) = s.sign_in(PASSWORD);
    let r = s.post("/logout", &[&session], "csrf_token=bad");
    assert_eq!(r.status, 403);
    let r = s.request(
        "POST",
        "/logout",
        &[&session],
        Some(&format!("csrf_token={csrf}")),
        &[("Origin", "https://evil.example")],
    );
    assert_eq!(r.status, 403);
    let r = s.request(
        "POST",
        "/logout",
        &[&session],
        Some(&format!("csrf_token={csrf}")),
        &[("Sec-Fetch-Site", "cross-site")],
    );
    assert_eq!(r.status, 403);
    // Without a session a POST is refused outright.
    assert_eq!(s.post("/logout", &[], &format!("csrf_token={csrf}")).status, 403);
    // The genuine logout works and ends the session.
    let origin = format!("http://{}", s.addr);
    let r = s.request(
        "POST",
        "/logout",
        &[&session],
        Some(&format!("csrf_token={csrf}")),
        &[("Origin", &origin)],
    );
    assert_eq!(r.header("location"), Some("/login"));
    assert_eq!(s.get("/", &[&session]).header("location"), Some("/login"));
}

#[test]
fn repeated_failures_are_throttled() {
    let s = Server::start("throttle");
    s.sign_in(PASSWORD);
    let mut last = 0;
    for _ in 0..6 {
        let form = s.get("/login", &[]);
        let nonce = form.cookie("pr_login").unwrap();
        last = s
            .post("/login", &[&nonce], &format!("csrf_token={}&password=wrong", form.csrf()))
            .status;
    }
    assert_eq!(last, 429);
    // Even the right password is refused while locked out.
    let form = s.get("/login", &[]);
    let nonce = form.cookie("pr_login").unwrap();
    let r = s.post("/login", &[&nonce], &format!("csrf_token={}&password={PASSWORD}", form.csrf()));
    assert_eq!(r.status, 429);
}

#[test]
fn password_change_signs_everyone_out() {
    let s = Server::start("password");
    let (session, csrf) = s.sign_in(PASSWORD);
    let wrong = s.post(
        "/settings/password",
        &[&session],
        &format!(
            "csrf_token={csrf}&current=nope&password=another+long+pass&confirm=another+long+pass"
        ),
    );
    assert_eq!(wrong.header("location"), Some("/settings"));
    let r = s.post(
        "/settings/password",
        &[&session],
        &format!("csrf_token={csrf}&current={PASSWORD}&password=another+long+pass&confirm=another+long+pass"),
    );
    assert_eq!(r.header("location"), Some("/login"));
    assert_eq!(s.get("/", &[&session]).header("location"), Some("/login"));
}

#[test]
fn malformed_requests_get_clean_errors() {
    let s = Server::start("malformed");
    let mut stream = TcpStream::connect(s.addr).unwrap();
    stream.write_all(b"BREW /pot HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut out = String::new();
    stream.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 501"));
    let mut stream = TcpStream::connect(s.addr).unwrap();
    stream
        .write_all(b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999\r\n\r\n")
        .unwrap();
    let mut out = String::new();
    stream.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 413"));
    let mut stream = TcpStream::connect(s.addr).unwrap();
    stream
        .write_all(b"POST /login HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
        .unwrap();
    let mut out = String::new();
    stream.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 501"));
}

/// Percent-encodes a form value.
pub fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Every file under `dir`, recursively, as bytes.
fn all_files(dir: &std::path::Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(all_files(&path));
        } else {
            out.push((path.clone(), std::fs::read(&path).unwrap()));
        }
    }
    out
}

/// The id in the first `href="/<section>/<id>"` link of a page.
fn first_id(page: &Reply, section: &str) -> String {
    let marker = format!("href=\"/{section}/");
    let start = page.body.find(&marker).expect("no record link") + marker.len();
    page.body[start..].split('"').next().unwrap().to_owned()
}

#[test]
fn secrets_are_write_only_and_never_on_disk_in_plaintext() {
    let s = Server::start("secrets");
    let (session, csrf) = s.sign_in(PASSWORD);
    let password = "vault-password-canary-3141";
    let r = s.post(
        "/secrets",
        &[&session],
        &format!("csrf_token={csrf}&name=Homelab+vault&kind=vault_password&vault_id=default&value={password}"),
    );
    assert_eq!(r.header("location"), Some("/secrets"));
    let key = pr_common::sshkey::TEST_ONLY_KEY;
    s.post(
        "/secrets",
        &[&session],
        &format!("csrf_token={csrf}&name=Deploy+key&kind=ssh_key&value={}", enc(key)),
    );
    let list = s.get("/secrets", &[&session]);
    assert!(
        list.body.contains("Homelab vault") && list.body.contains("Deploy key"),
        "{}",
        list.body
    );
    assert!(list.body.contains(pr_common::sshkey::TEST_ONLY_KEY_FINGERPRINT));
    let id = first_id(&list, "secrets");
    let detail = s.get(&format!("/secrets/{id}"), &[&session]);
    for page in [&list, &detail] {
        assert!(!page.body.contains(password));
        assert!(!page.body.contains("b3BlbnNzaC1rZXktdjE"), "the key body was rendered");
    }
    for (path, bytes) in all_files(&s.dir) {
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains(password), "{} holds the vault password", path.display());
        assert!(!text.contains("b3BlbnNzaC1rZXktdjE"), "{} holds the SSH key", path.display());
    }
    // A passphrase-protected or malformed key is refused with a message.
    let r = s.post(
        "/secrets",
        &[&session],
        &format!("csrf_token={csrf}&name=Bad&kind=ssh_key&value=nope"),
    );
    assert_eq!(r.header("location"), Some("/secrets"));
    assert!(s.get("/secrets", &[&session]).body.contains("not an OpenSSH private key"));
}

#[test]
fn records_in_use_cannot_be_deleted() {
    let s = Server::start("in-use");
    let (session, csrf) = s.sign_in(PASSWORD);
    let key = pr_common::sshkey::TEST_ONLY_KEY;
    s.post(
        "/secrets",
        &[&session],
        &format!("csrf_token={csrf}&name=Deploy&kind=ssh_key&value={}", enc(key)),
    );
    let key_id = first_id(&s.get("/secrets", &[&session]), "secrets");
    let r = s.post(
        "/repositories",
        &[&session],
        &format!(
            "csrf_token={csrf}&name=Playbooks&url={}&branch=main&deploy_key={key_id}",
            enc("git@github.com:owner/ansible_playbooks.git")
        ),
    );
    assert_eq!(r.header("location"), Some("/repositories"));
    assert!(
        s.get("/repositories", &[&session])
            .body
            .contains("git@github.com:owner/ansible_playbooks.git")
    );
    s.post(&format!("/secrets/{key_id}/delete"), &[&session], &format!("csrf_token={csrf}"));
    let page = s.get("/secrets", &[&session]);
    assert!(page.body.contains("is used by repository"));
    assert!(page.body.contains(&format!("/secrets/{key_id}")));
    // Invalid URLs are refused.
    s.post(
        "/repositories",
        &[&session],
        &format!("csrf_token={csrf}&name=Bad&url={}&branch=main", enc("-upload-pack=touch /tmp/x")),
    );
    assert!(s.get("/repositories", &[&session]).body.contains("git URL"));
}

#[test]
fn inventories_round_trip_encrypted() {
    let s = Server::start("inventories");
    let (session, csrf) = s.sign_in(PASSWORD);
    let content = "all:\n  vars:\n    canary_var: inventory-canary-2718\n";
    s.post(
        "/inventories",
        &[&session],
        &format!("csrf_token={csrf}&name=Homelab&content={}", enc(content)),
    );
    let list = s.get("/inventories", &[&session]);
    let id = first_id(&list, "inventories");
    let page = s.get(&format!("/inventories/{id}"), &[&session]);
    assert!(page.body.contains("inventory-canary-2718"));
    for (path, bytes) in all_files(&s.dir) {
        assert!(
            !String::from_utf8_lossy(&bytes).contains("inventory-canary"),
            "{}",
            path.display()
        );
    }
    let updated = content.replace("2718", "1618");
    s.post(
        &format!("/inventories/{id}"),
        &[&session],
        &format!("csrf_token={csrf}&name=Homelab&content={}", enc(&updated)),
    );
    assert!(
        s.get(&format!("/inventories/{id}"), &[&session]).body.contains("inventory-canary-1618")
    );
    s.post(&format!("/inventories/{id}/delete"), &[&session], &format!("csrf_token={csrf}"));
    assert_eq!(s.get(&format!("/inventories/{id}"), &[&session]).status, 404);
}

#[test]
fn known_hosts_are_validated() {
    let s = Server::start("known-hosts");
    let (session, csrf) = s.sign_in(PASSWORD);
    let good = "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    s.post("/known-hosts", &[&session], &format!("csrf_token={csrf}&content={}", enc(good)));
    assert!(s.get("/known-hosts", &[&session]).body.contains("github.com ssh-ed25519"));
    s.post("/known-hosts", &[&session], &format!("csrf_token={csrf}&content=garbage"));
    let page = s.get("/known-hosts", &[&session]);
    assert!(page.body.contains("line 1 is incomplete"));
    assert!(page.body.contains("github.com ssh-ed25519"), "a rejected save keeps the old file");
}
