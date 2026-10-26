//! The application: routing, the per-request security checks, and the
//! pages that are not specific to one kind of record.
//!
//! Every page except `/login`, `/setup`, `/healthz`, and `/static/*`
//! requires a session. Every POST additionally requires the session's CSRF
//! token and, when the browser sends them, `Origin` matching `Host` and a
//! `Sec-Fetch-Site` that is not cross-site.

use std::fmt::Write as _;
use std::net::IpAddr;

use pr_common::rand;

use crate::auth::{Auth, LOGIN_COOKIE, SESSION_COOKIE};
use crate::config::Config;
use crate::html::{self, Page, Tone, esc};
use crate::http::{Form, Handler, Method, Request, Response};

const STYLE: &str = include_str!("../static/style.css");
const FAVICON: &str = include_str!("../static/favicon.svg");

#[derive(Debug)]
pub struct App {
    pub config: Config,
    pub auth: Auth,
}

/// A signed-in request: the session identifier and its CSRF token.
#[derive(Debug)]
pub struct Session {
    pub id: String,
    pub csrf: String,
}

impl App {
    pub fn new(config: Config, auth: Auth) -> Self {
        Self { config, auth }
    }

    /// The client address used for throttling: the right-most
    /// `X-Forwarded-For` entry when the connection comes from a trusted
    /// proxy (Traefik appends the address it saw), otherwise the peer.
    pub fn client_key(&self, req: &Request) -> String {
        if self.config.trusted_proxies.contains(&req.peer)
            && let Some(ip) = req
                .header("x-forwarded-for")
                .and_then(|v| v.rsplit(',').next())
                .and_then(|v| v.trim().parse::<IpAddr>().ok())
        {
            return ip.to_string();
        }
        req.peer.to_string()
    }

    fn cookie(&self, name: &str, value: &str, max_age: u64) -> String {
        let secure = if self.config.secure_cookies { "; Secure" } else { "" };
        format!("{name}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Strict{secure}")
    }

    pub fn session(&self, req: &Request) -> Option<Session> {
        let id = req.cookie(SESSION_COOKIE)?;
        self.auth
            .is_valid(id)
            .then(|| Session { id: id.to_owned(), csrf: self.auth.csrf_token(id) })
    }

    /// Renders a signed-in page, consuming the session's pending flashes.
    pub fn page(&self, s: &Session, title: &str, nav: &'static str, body: String) -> Response {
        self.page_with(s, Page { title: title.to_owned(), nav, body, ..Page::default() })
    }

    pub fn page_with(&self, s: &Session, mut page: Page) -> Response {
        page.csrf = Some(s.csrf.clone());
        let mut flashes = self.auth.take_flashes(&s.id);
        flashes.append(&mut page.flashes);
        page.flashes = flashes;
        Response::html(200, html::render(&page))
    }

    pub fn flash_redirect(
        &self,
        s: &Session,
        tone: Tone,
        message: impl Into<String>,
        to: &str,
    ) -> Response {
        self.auth.flash(&s.id, tone, message);
        Response::redirect(to)
    }

    fn not_found(&self, s: Option<&Session>) -> Response {
        let body =
            "<h1>Not found</h1>\n<p class=\"page-intro\">There is no page at this address.</p>"
                .to_owned();
        let page = Page { title: "Not found".into(), body, ..Page::default() };
        let mut r = match s {
            Some(s) => self.page_with(s, page),
            None => Response::html(404, html::render(&page)),
        };
        r.status = 404;
        r
    }

    /// The browser-supplied origin checks every POST must pass.
    fn same_origin(req: &Request) -> bool {
        if req.header("sec-fetch-site").is_some_and(|v| v == "cross-site" || v == "same-site") {
            return false;
        }
        match (req.header("origin"), req.header("host")) {
            (Some(origin), Some(host)) => {
                let authority = origin
                    .strip_prefix("https://")
                    .or_else(|| origin.strip_prefix("http://"))
                    .unwrap_or("");
                authority.eq_ignore_ascii_case(host)
            }
            (Some(_), None) => false,
            (None, _) => true,
        }
    }

    /// The form of a POST from a signed-in session with a valid CSRF token,
    /// or the response that refuses it.
    pub fn checked_form(&self, req: &Request, s: &Session) -> Result<Form, Response> {
        if !Self::same_origin(req) {
            return Err(Response::text(403, "cross-origin request refused"));
        }
        let form = req.form();
        if !self.auth.verify_csrf(&s.id, form.get("csrf_token").unwrap_or("")) {
            return Err(Response::text(403, "invalid or missing CSRF token"));
        }
        Ok(form)
    }

    fn route(&self, req: &Request) -> Response {
        let path = req.path.as_str();
        let post = req.method == Method::Post;
        match (post, path) {
            (false, "/static/style.css") => {
                return Response::new(200, "text/css; charset=utf-8", STYLE)
                    .with_header("Cache-Control", "max-age=3600".to_owned());
            }
            (false, "/static/favicon.svg") => {
                return Response::new(200, "image/svg+xml", FAVICON)
                    .with_header("Cache-Control", "max-age=3600".to_owned());
            }
            (false, "/healthz") => return Response::text(200, "ok"),
            (false, "/setup") => return self.setup_form(None),
            (true, "/setup") => return self.setup_submit(req),
            (false, "/login") => return self.login_form(None),
            (true, "/login") => return self.login_submit(req),
            _ => {}
        }
        if self.auth.needs_setup() {
            return Response::redirect("/setup");
        }
        let Some(s) = self.session(req) else {
            return if post {
                Response::text(403, "not signed in")
            } else {
                Response::redirect("/login")
            };
        };
        let segments: Vec<&str> =
            path.trim_matches('/').split('/').filter(|p| !p.is_empty()).collect();
        let response = if post {
            match self.checked_form(req, &s) {
                Ok(form) => self.route_post(req, &s, &segments, &form),
                Err(r) => Some(r),
            }
        } else {
            self.route_get(req, &s, &segments)
        };
        response.unwrap_or_else(|| self.not_found(Some(&s)))
    }

    fn route_get(&self, _req: &Request, s: &Session, segments: &[&str]) -> Option<Response> {
        Some(match segments {
            [] => self.dashboard(s),
            ["settings"] => self.settings(s),
            [section] if html::NAV.iter().any(|(_, _, key)| key == section) => {
                self.placeholder(s, section)
            }
            _ => return None,
        })
    }

    fn route_post(
        &self,
        _req: &Request,
        s: &Session,
        segments: &[&str],
        form: &Form,
    ) -> Option<Response> {
        Some(match segments {
            ["logout"] => self.logout(s),
            ["settings", "password"] => self.change_password(s, form),
            _ => return None,
        })
    }

    // ------------------------------------------------------------- pages

    fn placeholder(&self, s: &Session, section: &str) -> Response {
        let (_, label, key) =
            html::NAV.iter().find(|(_, _, k)| *k == section).copied().unwrap_or(("", "", ""));
        let body = format!(
            "<h1>{}</h1>\n<p class=\"page-intro\">This section is not available yet.</p>",
            esc(label)
        );
        let nav = html::NAV.iter().find(|(_, _, k)| *k == key).map_or("", |(_, _, k)| *k);
        self.page(s, label, nav, body)
    }

    fn dashboard(&self, s: &Session) -> Response {
        let mut body = String::from("<h1>Dashboard</h1>\n");
        body.push_str(
            "<section class=\"card\" aria-labelledby=\"about-heading\">\n\
             <h2 id=\"about-heading\">This instance</h2>\n<dl class=\"details-list\">\n",
        );
        let _ = write!(
            body,
            "<dt>Version</dt><dd>{}</dd>\n<dt>Data directory</dt><dd><code>{}</code></dd>\n\
             <dt>Schedule time zone</dt><dd>{}</dd>\n</dl>\n</section>\n",
            esc(pr_common::VERSION),
            esc(&self.config.data_dir.display().to_string()),
            esc(&self.config.timezone),
        );
        self.page(s, "Dashboard", "dashboard", body)
    }

    fn settings(&self, s: &Session) -> Response {
        let mut body = String::from("<h1>Settings</h1>\n");
        body.push_str(
            "<section class=\"card\" aria-labelledby=\"password-heading\">\n\
             <h2 id=\"password-heading\">Admin password</h2>\n\
             <p class=\"field-help\">Changing the password signs out every session, including this one.</p>\n\
             <form method=\"POST\" action=\"/settings/password\">\n",
        );
        body.push_str(&html::csrf_field(&s.csrf));
        body.push_str(&html::field("current", "Current password", "password", "", "", true));
        body.push_str(&html::field(
            "password",
            "New password",
            "password",
            "",
            "12-128 characters.",
            true,
        ));
        body.push_str(&html::field("confirm", "Confirm new password", "password", "", "", true));
        body.push_str("<button type=\"submit\" class=\"button\">Change password</button>\n</form>\n</section>\n");
        self.page(s, "Settings", "settings", body)
    }

    fn change_password(&self, s: &Session, form: &Form) -> Response {
        if !self.auth.password_matches(form.get("current").unwrap_or("")) {
            return self.flash_redirect(
                s,
                Tone::Danger,
                "The current password is incorrect.",
                "/settings",
            );
        }
        let new = form.get("password").unwrap_or("");
        if new != form.get("confirm").unwrap_or("") {
            return self.flash_redirect(
                s,
                Tone::Danger,
                "The new passwords do not match.",
                "/settings",
            );
        }
        match self.auth.set_password(new) {
            Ok(()) => Response::redirect("/login"),
            Err(e) => self.flash_redirect(s, Tone::Danger, e.message(), "/settings"),
        }
    }

    fn logout(&self, s: &Session) -> Response {
        self.auth.end_session(&s.id);
        Response::redirect("/login").with_header("Set-Cookie", self.cookie(SESSION_COOKIE, "", 0))
    }

    // -------------------------------------------------- login and setup

    fn login_form(&self, error: Option<&str>) -> Response {
        if self.auth.needs_setup() {
            return Response::redirect("/setup");
        }
        let Ok(nonce) = rand::random_hex(16) else {
            return Response::text(500, "randomness unavailable");
        };
        let mut body = String::from(
            "<h1>Log in</h1>\n<section class=\"card login-card\" aria-labelledby=\"login-heading\">\n\
             <h2 id=\"login-heading\">Operator access</h2>\n",
        );
        if let Some(e) = error {
            let _ =
                writeln!(body, "<p class=\"notice notice-danger\" role=\"alert\">{}</p>", esc(e));
        }
        body.push_str("<form method=\"POST\" action=\"/login\">\n");
        body.push_str(&html::csrf_field(&self.auth.login_token(&nonce)));
        body.push_str(
            "<div class=\"field\">\n<label for=\"password\">Password</label>\n\
             <input type=\"password\" id=\"password\" name=\"password\" autocomplete=\"current-password\" required autofocus>\n\
             </div>\n<button type=\"submit\" class=\"button\">Log in</button>\n</form>\n</section>",
        );
        let page =
            Page { title: "Log in".into(), page_class: " page-center", body, ..Page::default() };
        let status = if error.is_some() { 401 } else { 200 };
        Response::html(status, html::render(&page))
            .with_header("Set-Cookie", self.cookie(LOGIN_COOKIE, &nonce, 3600))
    }

    fn login_submit(&self, req: &Request) -> Response {
        if self.auth.needs_setup() {
            return Response::redirect("/setup");
        }
        let form = req.form();
        let nonce = req.cookie(LOGIN_COOKIE).unwrap_or("");
        if !Self::same_origin(req)
            || !self.auth.verify_login_token(nonce, form.get("csrf_token").unwrap_or(""))
        {
            return self.login_form(Some("The login form expired. Please try again."));
        }
        let client = self.client_key(req);
        if let Some(wait) = self.auth.locked_out(&client) {
            let mut r = self.login_form(Some(&format!(
                "Too many failed attempts. Try again in {} minute(s).",
                wait.div_ceil(60)
            )));
            r.status = 429;
            return r;
        }
        if !self.auth.password_matches(form.get("password").unwrap_or("")) {
            self.auth.record_failure(&client);
            eprintln!("playbook-runner: failed login from {client}");
            return self.login_form(Some("Incorrect password."));
        }
        self.auth.clear_failures(&client);
        match self.auth.create_session() {
            Ok(id) => Response::redirect("/")
                .with_header(
                    "Set-Cookie",
                    self.cookie(SESSION_COOKIE, &id, self.config.session_seconds),
                )
                .with_header("Set-Cookie", self.cookie(LOGIN_COOKIE, "", 0)),
            Err(_) => Response::text(500, "unable to start a session"),
        }
    }

    fn setup_form(&self, error: Option<&str>) -> Response {
        if !self.auth.needs_setup() {
            return Response::redirect("/login");
        }
        let mut body = String::from(
            "<h1>Set up playbook-runner</h1>\n<section class=\"card login-card\" aria-labelledby=\"setup-heading\">\n\
             <h2 id=\"setup-heading\">Create the admin password</h2>\n\
             <p class=\"field-help\">The setup token is printed in the server log at startup \
             (<code>podman logs playbook-runner</code>).</p>\n",
        );
        if let Some(e) = error {
            let _ =
                writeln!(body, "<p class=\"notice notice-danger\" role=\"alert\">{}</p>", esc(e));
        }
        body.push_str("<form method=\"POST\" action=\"/setup\">\n");
        body.push_str(&html::field("token", "Setup token", "text", "", "", true));
        body.push_str(&html::field(
            "password",
            "Admin password",
            "password",
            "",
            "12-128 characters.",
            true,
        ));
        body.push_str(&html::field("confirm", "Confirm password", "password", "", "", true));
        body.push_str("<button type=\"submit\" class=\"button\">Create password</button>\n</form>\n</section>");
        let page =
            Page { title: "Set up".into(), page_class: " page-center", body, ..Page::default() };
        Response::html(if error.is_some() { 400 } else { 200 }, html::render(&page))
    }

    fn setup_submit(&self, req: &Request) -> Response {
        if !self.auth.needs_setup() {
            return Response::redirect("/login");
        }
        if !Self::same_origin(req) {
            return Response::text(403, "cross-origin request refused");
        }
        let client = self.client_key(req);
        if self.auth.locked_out(&client).is_some() {
            return self.setup_form(Some("Too many failed attempts. Try again later."));
        }
        let form = req.form();
        if !self.auth.check_setup_token(form.text("token")) {
            self.auth.record_failure(&client);
            return self.setup_form(Some("The setup token is incorrect."));
        }
        let password = form.get("password").unwrap_or("");
        if password != form.get("confirm").unwrap_or("") {
            return self.setup_form(Some("The passwords do not match."));
        }
        match self.auth.set_password(password) {
            Ok(()) => Response::redirect("/login"),
            Err(e) => self.setup_form(Some(e.message())),
        }
    }
}

impl Handler for App {
    fn handle(&self, request: &Request) -> Response {
        self.route(request)
    }

    fn hsts(&self) -> bool {
        self.config.secure_cookies
    }
}
