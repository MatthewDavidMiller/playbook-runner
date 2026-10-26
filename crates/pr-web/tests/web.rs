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
        let app = Arc::new(App::new(config, auth));
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
