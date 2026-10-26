//! Runtime configuration, read once from the environment at startup.
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `PR_LISTEN` | `127.0.0.1:8080` | Address the HTTP listener binds |
//! | `PR_DATA_DIR` | `/var/lib/playbook-runner` | Persistent state (mode 0700) |
//! | `PR_WORK_DIR` | `/run/playbook-runner` | Per-run scratch space; must be tmpfs in production |
//! | `PR_MASTER_KEY_FILE` | `/run/secrets/playbook_runner_master_key` | 64 hex digits |
//! | `PR_ADMIN_PASSWORD_FILE` | unset | Seeds the admin password on first start |
//! | `PR_TRUSTED_PROXIES` | unset | Comma-separated proxy IPs whose `X-Forwarded-For` is believed |
//! | `PR_SECURE_COOKIES` | `true` | `false` only for plain-HTTP development |
//! | `PR_SESSION_HOURS` | `12` | Session lifetime |
//! | `PR_TIMEZONE` | `UTC` | Zone schedules are written in, e.g. `America/New_York` |

use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use pr_common::{Error, Result};

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub work_dir: PathBuf,
    pub master_key_file: PathBuf,
    pub admin_password_file: Option<PathBuf>,
    pub trusted_proxies: Vec<IpAddr>,
    pub secure_cookies: bool,
    pub session_seconds: u64,
    pub timezone: String,
}

fn var(name: &str) -> Option<String> {
    env::var(name).ok().map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let listen = var("PR_LISTEN")
            .unwrap_or_else(|| "127.0.0.1:8080".to_owned())
            .parse()
            .map_err(|_| Error::new("PR_LISTEN must be an address such as 0.0.0.0:8080"))?;
        let trusted_proxies = match var("PR_TRUSTED_PROXIES") {
            None => Vec::new(),
            Some(list) => list
                .split(',')
                .map(|ip| ip.trim().parse())
                .collect::<std::result::Result<_, _>>()
                .map_err(|_| Error::new("PR_TRUSTED_PROXIES must list IP addresses"))?,
        };
        let secure_cookies = match var("PR_SECURE_COOKIES").as_deref() {
            None | Some("true" | "1") => true,
            Some("false" | "0") => false,
            Some(_) => return Err(Error::new("PR_SECURE_COOKIES must be true or false")),
        };
        let hours = match var("PR_SESSION_HOURS") {
            None => 12,
            Some(h) => pr_common::buf::parse_u64(h.as_bytes(), 24 * 30)
                .filter(|&h| h > 0)
                .ok_or_else(|| Error::new("PR_SESSION_HOURS must be 1-720"))?,
        };
        let timezone = var("PR_TIMEZONE").unwrap_or_else(|| "UTC".to_owned());
        Ok(Self {
            listen,
            data_dir: var("PR_DATA_DIR")
                .unwrap_or_else(|| "/var/lib/playbook-runner".into())
                .into(),
            work_dir: var("PR_WORK_DIR").unwrap_or_else(|| "/run/playbook-runner".into()).into(),
            master_key_file: var("PR_MASTER_KEY_FILE")
                .unwrap_or_else(|| "/run/secrets/playbook_runner_master_key".into())
                .into(),
            admin_password_file: var("PR_ADMIN_PASSWORD_FILE").map(PathBuf::from),
            trusted_proxies,
            secure_cookies,
            session_seconds: hours * 3600,
            timezone,
        })
    }
}
