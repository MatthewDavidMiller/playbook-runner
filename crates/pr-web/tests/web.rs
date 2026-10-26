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
            keep_runs: 50,
            zoneinfo_dir: "/usr/share/zoneinfo".into(),
        };
        let key = MasterKey::from_hex(&[b'7'; 64]).unwrap();
        let store = Arc::new(pr_store::Store::open(&dir, &key).unwrap());
        let auth = Auth::new(&dir, key.derive("web").unwrap(), 3600, None, store.sealer()).unwrap();
        let token = auth.setup_token();
        let exec = pr_runner::ExecConfig {
            work_dir: dir.join("work"),
            path: std::env::var("PATH").unwrap(),
            timezone: "UTC".into(),
        };
        let runner = pr_runner::Runner::new(Arc::clone(&store), &dir, exec, 50).unwrap();
        runner.start().unwrap();
        let app = Arc::new(App::new(config, auth, store, runner));
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
    let generated = pr_common::testkey::generate("").unwrap();
    let key = generated.private.as_str();
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
    assert!(list.body.contains(&generated.fingerprint));
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
    let generated = pr_common::testkey::generate("").unwrap();
    let key = generated.private.as_str();
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

fn git(dir: &std::path::Path, args: &[&str]) {
    let ok = std::process::Command::new("git")
        .args(["-c", "user.name=test", "-c", "user.email=test@example.invalid"])
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap()
        .success();
    assert!(ok);
}

#[test]
fn a_template_runs_from_the_interface() {
    let s = Server::start("run");
    let (session, csrf) = s.sign_in(PASSWORD);
    let repo = s.dir.join("playbooks.git");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    std::fs::write(
        repo.join("hello.yml"),
        "- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.debug:\n        msg: hello-from-the-runner\n",
    )
    .unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "hello"]);
    let python = String::from_utf8(
        std::process::Command::new("sh")
            .args(["-c", "command -v python3"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let inventory = format!(
        "all:\n  hosts:\n    localhost:\n      ansible_connection: local\n      ansible_python_interpreter: {}\n",
        python.trim()
    );
    s.post(
        "/repositories",
        &[&session],
        &format!(
            "csrf_token={csrf}&name=Local&url={}&branch=main&deploy_key=",
            enc(&repo.to_string_lossy())
        ),
    );
    let repo_id = first_id(&s.get("/repositories", &[&session]), "repositories");
    s.post(
        "/inventories",
        &[&session],
        &format!("csrf_token={csrf}&name=Local&content={}", enc(&inventory)),
    );
    let inv_id = first_id(&s.get("/inventories", &[&session]), "inventories");
    // An unparseable inventory is refused by ansible-inventory.
    s.post(
        "/inventories",
        &[&session],
        &format!("csrf_token={csrf}&name=Broken&content={}", enc("all: [x\n")),
    );
    assert!(s.get("/inventories", &[&session]).body.contains("could not parse"));
    let r = s.post(
        "/templates",
        &[&session],
        &format!(
            "csrf_token={csrf}&name=Hello&repository={repo_id}&playbook=hello.yml&inventory={inv_id}\
             &ssh_key=&limit=&tags=&skip_tags=&verbosity=0&timeout_minutes=5"
        ),
    );
    assert_eq!(r.header("location"), Some("/templates"));
    let templates = s.get("/templates", &[&session]);
    assert!(templates.body.contains("hello.yml"), "{}", templates.body);
    let tpl_id = first_id(&templates, "templates");
    let r = s.post(&format!("/templates/{tpl_id}/run"), &[&session], &format!("csrf_token={csrf}"));
    let location = r.header("location").unwrap().to_owned();
    assert!(location.starts_with("/runs/"));
    let start = std::time::Instant::now();
    let page = loop {
        let page = s.get(&location, &[&session]);
        if !page.body.contains("status-heading\">running<")
            && !page.body.contains("status-heading\">queued<")
        {
            break page;
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(120));
        std::thread::sleep(std::time::Duration::from_millis(250));
    };
    assert!(page.body.contains("<h2 id=\"status-heading\">succeeded</h2>"), "{}", page.body);
    assert!(page.body.contains("hello-from-the-runner"));
    assert!(!page.body.contains("http-equiv=\"refresh\""), "a finished run stops refreshing");
    let log = s.get(&format!("{location}/log"), &[&session]);
    assert_eq!(log.header("content-type"), Some("text/plain; charset=utf-8"));
    assert!(log.body.contains("hello-from-the-runner"));
    // The inventory is in use now and cannot be deleted.
    s.post(&format!("/inventories/{inv_id}/delete"), &[&session], &format!("csrf_token={csrf}"));
    assert!(s.get("/inventories", &[&session]).body.contains("is used by template"));
    assert!(s.get("/", &[&session]).body.contains("Hello"));
}

#[test]
fn schedules_validate_cron_and_protect_their_template() {
    let s = Server::start("schedules");
    let (session, csrf) = s.sign_in(PASSWORD);
    // A template needs a repository and an inventory.
    s.post(
        "/repositories",
        &[&session],
        &format!("csrf_token={csrf}&name=R&url={}&branch=main", enc("git@github.com:o/r.git")),
    );
    let repo_id = first_id(&s.get("/repositories", &[&session]), "repositories");
    s.post(
        "/inventories",
        &[&session],
        &format!("csrf_token={csrf}&name=I&content={}", enc("all:\n  hosts: {}\n")),
    );
    let inv_id = first_id(&s.get("/inventories", &[&session]), "inventories");
    s.post(
        "/templates",
        &[&session],
        &format!("csrf_token={csrf}&name=Weekly&repository={repo_id}&playbook=site.yml&inventory={inv_id}&verbosity=0&timeout_minutes=60"),
    );
    let tpl_id = first_id(&s.get("/templates", &[&session]), "templates");
    s.post(
        "/schedules",
        &[&session],
        &format!(
            "csrf_token={csrf}&name=Bad&template={tpl_id}&cron={}&enabled=1",
            enc("61 * * * *")
        ),
    );
    assert!(s.get("/schedules", &[&session]).body.contains("is not a five-field cron expression"));
    s.post(
        "/schedules",
        &[&session],
        &format!(
            "csrf_token={csrf}&name=Never&template={tpl_id}&cron={}&enabled=1",
            enc("0 0 31 2 *")
        ),
    );
    assert!(s.get("/schedules", &[&session]).body.contains("never fires"));
    s.post(
        "/schedules",
        &[&session],
        &format!(
            "csrf_token={csrf}&name=Sunday+patching&template={tpl_id}&cron={}&enabled=1",
            enc("0 4 * * sun")
        ),
    );
    let page = s.get("/schedules", &[&session]);
    assert!(page.body.contains("Sunday patching"));
    assert!(page.body.contains(" 04:00 UTC"), "the next run is shown");
    assert!(s.get("/", &[&session]).body.contains("Sunday patching"), "the dashboard lists it");
    // The schedule's template cannot be deleted out from under it.
    s.post(&format!("/templates/{tpl_id}/delete"), &[&session], &format!("csrf_token={csrf}"));
    assert!(
        s.get(&format!("/templates/{tpl_id}"), &[&session]).body.contains("is used by schedule")
    );
}

/// A local repository with playbooks, a task file, and a failing playbook,
/// added to the server; returns (repository id, inventory id).
fn playbook_fixture(s: &Server, session: &str, csrf: &str) -> (String, String) {
    let repo = s.dir.join("fixture.git");
    for (path, text) in [
        (
            "site.yml",
            "- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.debug:\n        msg: site-ran\n",
        ),
        (
            "plays/broken.yml",
            "- hosts: all\n  gather_facts: false\n  tasks:\n    - name: Break on purpose\n      ansible.builtin.fail:\n        msg: deliberate-failure\n",
        ),
        ("tasks/helper.yml", "- name: not a playbook\n  ansible.builtin.debug: {}\n"),
    ] {
        let p = repo.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-q", "-m", "fixture"]);
    s.post(
        "/repositories",
        &[session],
        &format!("csrf_token={csrf}&name=Fixture&url={}&branch=main", enc(&repo.to_string_lossy())),
    );
    let repo_id = first_id(&s.get("/repositories", &[session]), "repositories");
    let python = String::from_utf8(
        std::process::Command::new("sh")
            .args(["-c", "command -v python3"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let inventory = format!(
        "all:\n  hosts:\n    localhost:\n      ansible_connection: local\n      ansible_python_interpreter: {}\n",
        python.trim()
    );
    s.post(
        "/inventories",
        &[session],
        &format!("csrf_token={csrf}&name=Local&content={}", enc(&inventory)),
    );
    let inv_id = first_id(&s.get("/inventories", &[session]), "inventories");
    (repo_id, inv_id)
}

/// Waits for a run page to leave queued/running.
fn finished_run(s: &Server, session: &str, location: &str) -> Reply {
    let start = std::time::Instant::now();
    loop {
        let page = s.get(location, &[session]);
        if !page.body.contains("status-heading\">running<")
            && !page.body.contains("status-heading\">queued<")
        {
            return page;
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(120));
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

#[test]
fn syncing_a_repository_fills_the_playbook_dropdown() {
    let s = Server::start("sync");
    let (session, csrf) = s.sign_in(PASSWORD);
    let (repo_id, inv_id) = playbook_fixture(&s, &session, &csrf);
    // Step one offers repositories; step two is the form for one of them.
    assert!(s.get("/templates", &[&session]).body.contains("Next: choose a playbook"));
    let new = format!("/templates/new?repository={repo_id}");
    assert!(s.get(&new, &[&session]).body.contains("has not been synced yet"));
    let r = s.post(
        &format!("/repositories/{repo_id}/sync"),
        &[&session],
        &format!("csrf_token={csrf}&back={}", enc(&new)),
    );
    assert_eq!(r.header("location"), Some(new.as_str()));
    let page = s.get(&new, &[&session]);
    assert!(page.body.contains("Synced Fixture: 2 playbook(s)"), "{}", page.body);
    assert!(page.body.contains("<option value=\"site.yml\">site.yml</option>"));
    assert!(page.body.contains("<option value=\"plays/broken.yml\">plays/broken.yml</option>"));
    assert!(!page.body.contains("tasks/helper.yml"), "task files are not offered");
    // Saving with the dropdown, and with a typed path.
    s.post(
        "/templates",
        &[&session],
        &format!("csrf_token={csrf}&name=Site&repository={repo_id}&playbook=site.yml&playbook_other=&inventory={inv_id}&verbosity=0&timeout_minutes=5"),
    );
    s.post(
        "/templates",
        &[&session],
        &format!("csrf_token={csrf}&name=Typed&repository={repo_id}&playbook=&playbook_other=tasks%2Fhelper.yml&inventory={inv_id}&verbosity=0&timeout_minutes=5"),
    );
    let list = s.get("/templates", &[&session]);
    assert!(
        list.body.contains("<code>site.yml</code>")
            && list.body.contains("<code>tasks/helper.yml</code>"),
        "{}",
        list.body
    );
    // Neither chosen nor typed: refused, back on the form.
    let r = s.post(
        "/templates",
        &[&session],
        &format!("csrf_token={csrf}&name=None&repository={repo_id}&playbook=&playbook_other=&inventory={inv_id}&verbosity=0&timeout_minutes=5"),
    );
    assert_eq!(r.header("location"), Some(new.as_str()));
    assert!(s.get(&new, &[&session]).body.contains("Choose a playbook"));
    // The repository page lists what the sync found.
    assert!(
        s.get(&format!("/repositories/{repo_id}"), &[&session])
            .body
            .contains("<code>plays/broken.yml</code>")
    );
}

#[test]
fn a_failed_sync_says_why() {
    let s = Server::start("sync-fail");
    let (session, csrf) = s.sign_in(PASSWORD);
    s.post(
        "/repositories",
        &[&session],
        &format!("csrf_token={csrf}&name=Gone&url={}&branch=main", enc("/nonexistent/repo.git")),
    );
    let repo_id = first_id(&s.get("/repositories", &[&session]), "repositories");
    s.post(
        &format!("/repositories/{repo_id}/sync"),
        &[&session],
        &format!("csrf_token={csrf}&back=%2Frepositories"),
    );
    let page = s.get("/repositories", &[&session]);
    assert!(page.body.contains("Sync failed: git clone failed"), "{}", page.body);
    assert!(
        page.body.contains("does not exist")
            || page.body.contains("not appear to be a git repository"),
        "git's reason is shown"
    );
}

#[test]
fn the_schedule_builder_writes_cron_and_reads_it_back() {
    let s = Server::start("builder");
    let (session, csrf) = s.sign_in(PASSWORD);
    let (repo_id, inv_id) = playbook_fixture(&s, &session, &csrf);
    s.post(
        "/templates",
        &[&session],
        &format!("csrf_token={csrf}&name=Site&repository={repo_id}&playbook=site.yml&inventory={inv_id}&verbosity=0&timeout_minutes=5"),
    );
    let tpl_id = first_id(&s.get("/templates", &[&session]), "templates");
    s.post(
        "/schedules",
        &[&session],
        &format!("csrf_token={csrf}&name=Weekly&template={tpl_id}&frequency=weekly&time=17%3A00&weekdays=1&weekdays=4&enabled=1"),
    );
    let list = s.get("/schedules", &[&session]);
    assert!(list.body.contains("Every Monday and Thursday at 5:00 PM"), "{}", list.body);
    let id = first_id(&list, "schedules");
    let page = s.get(&format!("/schedules/{id}"), &[&session]);
    assert!(page.body.contains("<code>0 17 * * 1,4</code>"));
    assert_eq!(page.body.matches(" 17:00 UTC").count(), 3, "the next three runs are listed");
    // The edit form comes back prefilled with the builder's choices.
    assert!(page.body.contains("<option value=\"weekly\" selected>"));
    assert!(page.body.contains("name=\"weekdays\" value=\"1\" checked"));
    assert!(page.body.contains("value=\"17:00\""));
    // A weekly schedule with no day is refused.
    s.post(
        &format!("/schedules/{id}"),
        &[&session],
        &format!("csrf_token={csrf}&name=Weekly&template={tpl_id}&frequency=weekly&time=17%3A00&enabled=1"),
    );
    assert!(
        s.get(&format!("/schedules/{id}"), &[&session])
            .body
            .contains("Choose at least one day of the week")
    );
}

#[test]
fn a_failed_run_explains_where_it_failed() {
    let s = Server::start("run-detail");
    let (session, csrf) = s.sign_in(PASSWORD);
    let (repo_id, inv_id) = playbook_fixture(&s, &session, &csrf);
    s.post(
        "/templates",
        &[&session],
        &format!("csrf_token={csrf}&name=Broken&repository={repo_id}&playbook=plays%2Fbroken.yml&inventory={inv_id}&verbosity=0&timeout_minutes=5"),
    );
    let tpl_id = first_id(&s.get("/templates", &[&session]), "templates");
    let r = s.post(&format!("/templates/{tpl_id}/run"), &[&session], &format!("csrf_token={csrf}"));
    let page = finished_run(&s, &session, r.header("location").unwrap());
    assert!(page.body.contains("status-heading\">failed<"), "{}", page.body);
    assert!(page.body.contains("Stopped at: <strong>Running the playbook</strong>"));
    assert!(
        page.body.contains(
            "<td>localhost <span class=\"state-token status-failed\">problems</span></td>"
        )
    );
    assert!(page.body.contains("task <strong>Break on purpose</strong> on <strong>localhost</strong></a>: deliberate-failure"), "{}", page.body);
    // The summary links to the highlighted line in the log.
    let anchor =
        page.body.split("<a href=\"#log-").nth(1).unwrap().split('"').next().unwrap().to_owned();
    let marked = format!("<span class=\"log-failure\" id=\"log-{anchor}\">");
    let line =
        page.body.split(&marked).nth(1).map(|rest| rest.split("</span>").next().unwrap_or(""));
    assert!(line.is_some_and(|l| l.contains("FAILED!")), "anchor {anchor} marks {line:?}");
    // The log sits in a scrolling frame that opens on its end, and a run that
    // has finished no longer refreshes or offers the live controls.
    assert!(page.body.contains("<div class=\"run-log-frame follow\""), "{}", page.body);
    assert!(!page.body.contains("http-equiv=\"refresh\""));
    assert!(!page.body.contains("Pause updates"));
    let off = s.get(&format!("{}?follow=0", r.header("location").unwrap()), &[&session]);
    assert!(off.body.contains("<div class=\"run-log-frame\""));
}

#[test]
fn the_about_page_reports_the_toolchain_and_licenses() {
    let s = Server::start("about");
    let (session, _) = s.sign_in(PASSWORD);
    let page = s.get("/about", &[&session]);
    assert_eq!(page.status, 200);
    assert!(page.body.contains(&format!("<dt>Version</dt><dd>{}</dd>", pr_common::VERSION)));
    assert!(page.body.contains("<dt>ansible-core</dt><dd>2."), "{}", page.body);
    assert!(page.body.contains("Permission is hereby granted"), "the MIT license text");
    assert!(
        page.body.contains("ansible-core") && page.body.contains("GNU General Public License v3.0")
    );
    assert!(page.body.contains("<a href=\"/about\" aria-current=\"page\">About</a>"));
}

/// The files the application itself keeps: the data directory's own files,
/// its blobs, and the run records and logs (not the test fixtures beside them).
fn data_files(dir: &std::path::Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    for sub in [dir.to_path_buf(), dir.join("blobs"), dir.join("runs")] {
        for entry in std::fs::read_dir(&sub).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                out.push((path.clone(), std::fs::read(&path).unwrap()));
            }
        }
    }
    out
}

#[test]
fn everything_the_application_stores_is_sealed() {
    let s = Server::start("sealed");
    let (session, csrf) = s.sign_in(PASSWORD);
    let (repo_id, inv_id) = playbook_fixture(&s, &session, &csrf);
    s.post(
        "/templates",
        &[&session],
        &format!("csrf_token={csrf}&name=Broken+canary&repository={repo_id}&playbook=plays%2Fbroken.yml&inventory={inv_id}&verbosity=0&timeout_minutes=5"),
    );
    let tpl_id = first_id(&s.get("/templates", &[&session]), "templates");
    let r = s.post(&format!("/templates/{tpl_id}/run"), &[&session], &format!("csrf_token={csrf}"));
    let location = r.header("location").unwrap().to_owned();
    let page = finished_run(&s, &session, &location);
    // The page still shows the run: the log is sealed on disk, not unreadable.
    assert!(page.body.contains("deliberate-failure"), "{}", page.body);

    let files = data_files(&s.dir);
    assert!(files.len() >= 8, "{:?}", files.iter().map(|f| &f.0).collect::<Vec<_>>());
    for (path, bytes) in &files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = String::from_utf8_lossy(bytes);
        for canary in ["Broken canary", "Fixture", "deliberate-failure", "pbkdf2", "localhost"] {
            assert!(!text.contains(canary), "{} holds {canary:?}", path.display());
        }
        match path.extension().and_then(|e| e.to_str()) {
            Some("json") | None if name == "admin.password" => {
                assert!(bytes.starts_with(b"PRF1"), "{name} is not sealed");
            }
            Some("json") => assert!(bytes.starts_with(b"PRF1"), "{name} is not sealed"),
            Some("log") => assert!(bytes.starts_with(b"PRL1"), "{name} is not sealed"),
            _ => {}
        }
    }
}

#[test]
fn a_git_url_with_a_credential_is_refused() {
    let s = Server::start("url-credential");
    let (session, csrf) = s.sign_in(PASSWORD);
    for url in ["https://ghp_exampletoken@github.com/o/r.git", "https://u:p@host/o/r.git"] {
        let r = s.post(
            "/repositories",
            &[&session],
            &format!("csrf_token={csrf}&name=Leaky&url={}&branch=main", enc(url)),
        );
        assert_eq!(r.header("location"), Some("/repositories"));
        let page = s.get("/repositories", &[&session]);
        assert!(page.body.contains("Do not put a token or password in the URL"), "{}", page.body);
        assert!(!page.body.contains("Leaky"), "no record was created");
    }
    for (_, bytes) in data_files(&s.dir) {
        assert!(!String::from_utf8_lossy(&bytes).contains("ghp_exampletoken"));
    }
}
