//! The playbook-runner entry point.
//!
//! ```text
//! playbook-runner [serve]   Run the web interface (the container's command)
//! playbook-runner gen-key   Print a new 256-bit master key as 64 hex digits
//! playbook-runner passwd    Set the admin password from one line on stdin
//! playbook-runner rekey     Re-encrypt the data directory from the key in
//!                           PR_OLD_MASTER_KEY_FILE to PR_MASTER_KEY_FILE
//! playbook-runner healthcheck  Exit 0 when the local server answers /healthz
//! playbook-runner version   Print the version
//! ```
//!
//! Configuration comes from the environment; see `pr_web::config`.

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;

use pr_common::{Error, Result, fsio};
use pr_crypto::MasterKey;
use pr_runner::{ExecConfig, Runner};
use pr_store::Store;
use pr_web::app::App;
use pr_web::auth::Auth;
use pr_web::config::Config;

fn load_master_key(config: &Config) -> Result<MasterKey> {
    MasterKey::load(&config.master_key_file).map_err(|_| {
        Error::new(format!(
            "cannot read a 64-hex-digit master key from {} (set PR_MASTER_KEY_FILE)",
            config.master_key_file.display()
        ))
    })
}

fn serve() -> Result<()> {
    let config = Config::from_env()?;
    fsio::mkdir_all(&config.data_dir, 0o700)?;
    let master = load_master_key(&config)?;
    let web_key = master.derive("web").map_err(|_| Error::new("key derivation failed"))?;
    let store = Arc::new(Store::open(&config.data_dir, &master)?);
    let exec = ExecConfig {
        work_dir: config.work_dir.clone(),
        path: std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_owned()),
        timezone: config.timezone.clone(),
    };
    let runner = Runner::new(Arc::clone(&store), &config.data_dir, exec, config.keep_runs)?;
    runner.start()?;
    let zone = pr_sched::Zone::load(&config.zoneinfo_dir, &config.timezone)?;
    pr_web::pages::set_zone(zone.clone());
    pr_runner::scheduler::start(Arc::clone(&runner), Arc::clone(&store), zone)?;
    let auth = Auth::new(
        &config.data_dir,
        web_key,
        config.session_seconds,
        config.admin_password_file.as_deref(),
    )?;
    if let Some(token) = auth.setup_token() {
        eprintln!(
            "playbook-runner: no admin password is set; open /setup with setup token {token}"
        );
    }
    let listener = TcpListener::bind(config.listen)
        .map_err(|e| Error::new(format!("cannot listen on {}: {e}", config.listen)))?;
    eprintln!("playbook-runner {} listening on {}", pr_common::VERSION, config.listen);
    let app = Arc::new(App::new(config, auth, store, runner));
    pr_web::http::serve(&listener, &app);
    Ok(())
}

fn gen_key() -> Result<()> {
    let key = MasterKey::generate_hex().map_err(|_| Error::new("randomness unavailable"))?;
    let mut out = io::stdout().lock();
    out.write_all(key.expose())?;
    out.write_all(b"\n")?;
    Ok(())
}

fn passwd() -> Result<()> {
    let config = Config::from_env()?;
    fsio::mkdir_all(&config.data_dir, 0o700)?;
    let mut buf = [0_u8; 512];
    let mut len = 0;
    let mut stdin = io::stdin().lock();
    loop {
        match stdin.read(&mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => {
                len += n;
                if len == buf.len() || buf[..len].contains(&b'\n') {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    let line = buf[..len].split(|&b| b == b'\n').next().unwrap_or_default();
    let result = std::str::from_utf8(line)
        .map_err(|_| Error::new("the password must be UTF-8"))
        .and_then(|p| {
            pr_web::auth::validate_new_password(p.trim_end_matches('\r'))?;
            let mut hash = pr_web::auth::hash_password(p.trim_end_matches('\r'))?;
            hash.push('\n');
            fsio::atomic_replace(config.data_dir.join("admin.password"), hash.as_bytes(), 512)
        });
    pr_crypto::cleanse(&mut buf);
    result?;
    eprintln!("Admin password updated. Restart the server to end existing sessions.");
    Ok(())
}

fn rekey() -> Result<()> {
    let config = Config::from_env()?;
    let old_path = std::env::var_os("PR_OLD_MASTER_KEY_FILE")
        .ok_or_else(|| Error::new("set PR_OLD_MASTER_KEY_FILE to the current key"))?;
    let old = MasterKey::load(std::path::Path::new(&old_path))
        .map_err(|_| Error::new("cannot read the key in PR_OLD_MASTER_KEY_FILE"))?;
    let new = load_master_key(&config)?;
    let converted = pr_store::rekey(&config.data_dir, &old, &new)?;
    eprintln!("Re-encrypted {converted} stored value(s); the data directory now uses the new key.");
    Ok(())
}

/// GET /healthz on the configured listener (loopback for a wildcard).
fn healthcheck() -> Result<()> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    use std::time::Duration;
    let config = Config::from_env()?;
    let mut addr = config.listen;
    if addr.ip().is_unspecified() {
        addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port());
    }
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
    let mut head = [0_u8; 12];
    stream.read_exact(&mut head)?;
    if &head == b"HTTP/1.1 200" { Ok(()) } else { Err(Error::new("unhealthy")) }
}

fn main() -> ExitCode {
    let command = std::env::args().nth(1).unwrap_or_else(|| "serve".to_owned());
    let result = match command.as_str() {
        "serve" => serve(),
        "gen-key" => gen_key(),
        "passwd" => passwd(),
        "rekey" => rekey(),
        "healthcheck" => healthcheck(),
        "version" | "--version" => {
            println!("playbook-runner {}", pr_common::VERSION);
            Ok(())
        }
        _ => Err(Error::new(
            "usage: playbook-runner [serve|gen-key|passwd|rekey|healthcheck|version]",
        )),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("playbook-runner: {e}");
            ExitCode::FAILURE
        }
    }
}
