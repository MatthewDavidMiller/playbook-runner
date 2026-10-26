//! A small HTTP/1.1 server: a thread per connection under a fixed ceiling,
//! one request per connection, and every read bounded in size and time.
//!
//! TLS is not here. In production Traefik terminates HTTPS and forwards to
//! this listener on an internal Podman network; in development it listens on
//! loopback.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

pub const MAX_CONNECTIONS: usize = 64;
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_HEADERS: usize = 64;
/// The largest body any route accepts: an inventory file with headroom.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(15);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const THREAD_STACK: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
}

#[derive(Debug)]
pub struct Request {
    pub method: Method,
    /// The path without its query string, percent-decoding not applied.
    pub path: String,
    pub query: Vec<(String, String)>,
    /// Header names lowercased; a repeated header keeps its first value.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub peer: IpAddr,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    pub fn query_value(&self, name: &str) -> Option<&str> {
        self.query.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.header("cookie")?.split(';').find_map(|pair| {
            let (k, v) = pair.trim().split_once('=')?;
            (k == name).then_some(v)
        })
    }

    /// The body as an `application/x-www-form-urlencoded` form. A body of any
    /// other type reads as an empty form.
    pub fn form(&self) -> Form {
        let is_form = self.header("content-type").is_some_and(|t| {
            t.split(';')
                .next()
                .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/x-www-form-urlencoded"))
        });
        if !is_form {
            return Form(Vec::new());
        }
        Form(parse_urlencoded(&self.body))
    }
}

/// Decoded form fields, in order. Values may hold secrets, so the Debug
/// output shows only the field names.
pub struct Form(Vec<(String, String)>);

impl Form {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn all(&self, name: &str) -> impl Iterator<Item = &str> {
        self.0.iter().filter(move |(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// The trimmed value, or "" when absent.
    pub fn text(&self, name: &str) -> &str {
        self.get(name).unwrap_or("").trim()
    }

    pub fn checked(&self, name: &str) -> bool {
        self.get(name).is_some_and(|v| v == "on" || v == "1" || v == "true")
    }
}

impl std::fmt::Debug for Form {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.iter().map(|(k, _)| k)).finish()
    }
}

impl Drop for Form {
    fn drop(&mut self) {
        for (_, v) in &mut self.0 {
            pr_common::buf::wipe_string(v);
        }
    }
}

fn hex_value(c: u8) -> Option<u8> {
    char::from(c).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// Percent-decodes `s`, with `+` as a space when `plus` is set. Invalid
/// escapes are kept literally; invalid UTF-8 is replaced.
pub fn percent_decode(s: &[u8], plus: bool) -> String {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'+' if plus => out.push(b' '),
            b'%' if i + 2 < s.len() => {
                if let (Some(hi), Some(lo)) = (hex_value(s[i + 1]), hex_value(s[i + 2])) {
                    out.push(hi << 4 | lo);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    match String::from_utf8(out) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

pub fn parse_urlencoded(body: &[u8]) -> Vec<(String, String)> {
    body.split(|&b| b == b'&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = match pair.iter().position(|&b| b == b'=') {
                Some(i) => (&pair[..i], &pair[i + 1..]),
                None => (pair, &[][..]),
            };
            (percent_decode(k, true), percent_decode(v, true))
        })
        .collect()
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".to_owned(), content_type.to_owned())],
            body: body.into(),
        }
    }

    pub fn html(status: u16, body: String) -> Self {
        Self::new(status, "text/html; charset=utf-8", body)
    }

    pub fn text(status: u16, body: &str) -> Self {
        Self::new(status, "text/plain; charset=utf-8", body)
    }

    /// A 303 to a same-site path; anything else becomes "/".
    pub fn redirect(location: &str) -> Self {
        let safe = location.starts_with('/')
            && !location.starts_with("//")
            && !location.contains(['\\', '\r', '\n']);
        let mut r = Self::new(303, "text/plain; charset=utf-8", "See Other");
        r.headers.push(("Location".to_owned(), if safe { location } else { "/" }.to_owned()));
        r
    }

    #[must_use]
    pub fn with_header(mut self, name: &str, value: String) -> Self {
        self.headers.push((name.to_owned(), value));
        self
    }
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        303 => "See Other",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    }
}

/// Headers every response carries. The pages use no JavaScript, no inline
/// styles, and no third-party origins, so the policy can refuse all of them.
const SECURITY_HEADERS: &[(&str, &str)] = &[
    (
        "Content-Security-Policy",
        "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; \
         frame-ancestors 'none'; base-uri 'none'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()"),
    ("Cache-Control", "no-store"),
];

fn write_response(
    stream: &mut TcpStream,
    mut r: Response,
    head_only: bool,
    hsts: bool,
) -> io::Result<()> {
    let mut out = String::with_capacity(1024);
    let _ = write!(out, "HTTP/1.1 {} {}\r\n", r.status, reason(r.status));
    for (k, v) in SECURITY_HEADERS {
        if !r.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(k)) {
            let _ = write!(out, "{k}: {v}\r\n");
        }
    }
    if hsts {
        out.push_str("Strict-Transport-Security: max-age=31536000\r\n");
    }
    for (k, v) in &r.headers {
        // Header values are built by this program, but a stray newline must
        // never split a response.
        if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
            continue;
        }
        let _ = write!(out, "{k}: {v}\r\n");
    }
    let _ = write!(out, "Content-Length: {}\r\nConnection: close\r\n\r\n", r.body.len());
    stream.write_all(out.as_bytes())?;
    if !head_only {
        stream.write_all(&r.body)?;
    }
    pr_common::buf::wipe_vec(&mut r.body);
    stream.flush()
}

#[derive(Debug)]
enum ReadError {
    Status(u16),
    Io,
}

/// Finds the end of the header block: the index just past "\r\n\r\n",
/// looking only at `buf[from..]` (a caller that already searched the start
/// passes how far back a terminator could still begin).
fn header_end(buf: &[u8], from: usize) -> Option<usize> {
    let tail = buf.get(from..)?;
    tail.windows(4).position(|w| w == b"\r\n\r\n").map(|i| from + i + 4)
}

fn read_request(stream: &mut TcpStream, peer: IpAddr) -> Result<Request, ReadError> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    let mut searched = 0;
    let end = loop {
        if let Some(end) = header_end(&buf, searched) {
            break end;
        }
        // A terminator can straddle the previous read by up to three bytes.
        searched = buf.len().saturating_sub(3);
        if buf.len() > MAX_HEADER_BYTES {
            return Err(ReadError::Status(431));
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err(ReadError::Io),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(ReadError::Status(408));
            }
            Err(_) => return Err(ReadError::Io),
        }
    };
    if end > MAX_HEADER_BYTES {
        return Err(ReadError::Status(431));
    }
    let head = std::str::from_utf8(&buf[..end - 4]).map_err(|_| ReadError::Status(400))?.to_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(ReadError::Status(400))?;
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ReadError::Status(400));
    };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(ReadError::Status(400));
    }
    let method = match method {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        "POST" => Method::Post,
        _ => return Err(ReadError::Status(501)),
    };
    if !target.starts_with('/') || target.len() > 2048 {
        return Err(ReadError::Status(400));
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, parse_urlencoded(q.as_bytes())),
        None => (target, Vec::new()),
    };
    let mut headers = HashMap::new();
    for (count, line) in lines.enumerate() {
        if count >= MAX_HEADERS {
            return Err(ReadError::Status(431));
        }
        let (name, value) = line.split_once(':').ok_or(ReadError::Status(400))?;
        if name.is_empty() || name.contains(|c: char| !c.is_ascii_graphic()) {
            return Err(ReadError::Status(400));
        }
        headers.entry(name.to_ascii_lowercase()).or_insert_with(|| value.trim().to_owned());
    }
    if headers.contains_key("transfer-encoding") {
        return Err(ReadError::Status(501));
    }
    let length = match headers.get("content-length") {
        Some(v) => pr_common::buf::parse_u64(v.as_bytes(), MAX_BODY_BYTES as u64)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or(ReadError::Status(413))?,
        None if method == Method::Post => return Err(ReadError::Status(411)),
        None => 0,
    };
    let mut body = buf.split_off(end);
    if body.len() > length {
        return Err(ReadError::Status(400));
    }
    body.reserve_exact(length - body.len());
    while body.len() < length {
        let want = (length - body.len()).min(chunk.len());
        match stream.read(&mut chunk[..want]) {
            Ok(0) => return Err(ReadError::Io),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(ReadError::Status(408));
            }
            Err(_) => return Err(ReadError::Io),
        }
    }
    pr_common::buf::wipe_vec(&mut buf);
    Ok(Request { method, path: path.to_owned(), query, headers, body, peer })
}

pub trait Handler: Send + Sync + 'static {
    fn handle(&self, request: &Request) -> Response;
    /// Whether responses advertise HSTS (only when served behind HTTPS).
    fn hsts(&self) -> bool;
}

fn serve_connection<H: Handler>(handler: &H, mut stream: TcpStream, peer: SocketAddr) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let hsts = handler.hsts();
    match read_request(&mut stream, peer.ip()) {
        Ok(mut request) => {
            let head = request.method == Method::Head;
            let response = handler.handle(&request);
            pr_common::buf::wipe_vec(&mut request.body);
            let _ = write_response(&mut stream, response, head, hsts);
        }
        Err(ReadError::Status(code)) => {
            let _ = write_response(&mut stream, Response::text(code, reason(code)), false, hsts);
        }
        Err(ReadError::Io) => {}
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// Accepts connections forever, serving each on its own thread. Past
/// [`MAX_CONNECTIONS`] concurrent connections a client gets a 503.
pub fn serve<H: Handler>(listener: &TcpListener, handler: &Arc<H>) {
    let active = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let Ok(mut stream) = incoming else { continue };
        let Ok(peer) = stream.peer_addr() else { continue };
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            let _ = write_response(&mut stream, Response::text(503, "busy"), false, false);
            continue;
        }
        let handler = Arc::clone(handler);
        let counter = Arc::clone(&active);
        let spawned = thread::Builder::new()
            .name("http".to_owned())
            .stack_size(THREAD_STACK)
            .spawn(move || {
                serve_connection(handler.as_ref(), stream, peer);
                counter.fetch_sub(1, Ordering::AcqRel);
            });
        if spawned.is_err() {
            active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoded_forms_decode() {
        let pairs = parse_urlencoded(b"a=1&b=hello+world&c=%2Fx%3D&d&e=%zz&f=%e2%9c%93");
        let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("a"), Some("1"));
        assert_eq!(get("b"), Some("hello world"));
        assert_eq!(get("c"), Some("/x="));
        assert_eq!(get("d"), Some(""));
        assert_eq!(get("e"), Some("%zz"));
        assert_eq!(get("f"), Some("\u{2713}"));
        assert_eq!(percent_decode(b"%4", false), "%4");
        assert_eq!(percent_decode(b"%41", false), "A");
        assert_eq!(percent_decode(b"a+b", false), "a+b");
    }

    #[test]
    fn redirects_stay_on_site() {
        let loc = |r: Response| r.headers.iter().find(|(k, _)| k == "Location").unwrap().1.clone();
        assert_eq!(loc(Response::redirect("/runs/3")), "/runs/3");
        assert_eq!(loc(Response::redirect("//evil.example")), "/");
        assert_eq!(loc(Response::redirect("https://evil.example")), "/");
        assert_eq!(loc(Response::redirect("/a\r\nSet-Cookie: x")), "/");
    }

    #[test]
    fn form_debug_hides_values() {
        let f = Form(vec![("password".to_owned(), "hunter2".to_owned())]);
        assert_eq!(format!("{f:?}"), "[\"password\"]");
    }
}
