//! What the image runs playbooks with, read from the tools themselves for
//! the About page: ansible-core and its Python, the built-in collections,
//! git, and OpenSSH. Asking the tools means the page cannot drift from what
//! is actually installed.

use std::process::{Command, Stdio};

use pr_common::json::{self, Value};
use pr_common::{Result, fsio, rand};

use crate::exec::{ExecConfig, Scratch};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Toolchain {
    pub ansible_core: String,
    pub python: String,
    /// (name, version), sorted by name.
    pub collections: Vec<(String, String)>,
    pub git: String,
    pub openssh: String,
}

/// stdout, or stderr when stdout is empty (ssh -V prints to stderr); ""
/// when the program is missing or fails.
fn output(cfg: &ExecConfig, home: &std::path::Path, program: &str, args: &[&str]) -> String {
    let result = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", &cfg.path)
        .env("HOME", home)
        .env("ANSIBLE_LOCAL_TEMP", home)
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .output();
    match result {
        Ok(out) if out.status.success() => {
            let text = if out.stdout.is_empty() { out.stderr } else { out.stdout };
            String::from_utf8_lossy(&text).into_owned()
        }
        _ => String::new(),
    }
}

/// "2.21.3" from `ansible-playbook [core 2.21.3]`.
fn ansible_core_version(text: &str) -> String {
    text.lines()
        .next()
        .and_then(|l| l.split("[core ").nth(1))
        .and_then(|l| l.split(']').next())
        .unwrap_or_default()
        .to_owned()
}

/// "3.12.15" from the `python version = 3.12.15 (...)` line.
fn python_version(text: &str) -> String {
    text.lines()
        .find_map(|l| l.trim().strip_prefix("python version = "))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_default()
        .to_owned()
}

/// Collections from `ansible-galaxy collection list --format json`.
fn collections(text: &str) -> Vec<(String, String)> {
    let Ok(root) = json::parse(text.trim().as_bytes()) else { return Vec::new() };
    let mut out = Vec::new();
    for (_, path) in root.as_object().unwrap_or_default() {
        for (name, info) in path.as_object().unwrap_or_default() {
            let version = info.get("version").and_then(Value::as_str).unwrap_or("?");
            out.push((name.clone(), version.to_owned()));
        }
    }
    out.sort();
    out.dedup();
    out
}

pub fn toolchain(cfg: &ExecConfig) -> Result<Toolchain> {
    fsio::mkdir_all(&cfg.work_dir, 0o700)?;
    let dir = cfg.work_dir.join(format!("about-{}", rand::random_hex(8)?));
    fsio::mkdir_all(&dir, 0o700)?;
    let scratch = Scratch(dir.clone());
    let ansible = output(cfg, &dir, "ansible-playbook", &["--version"]);
    let list = output(cfg, &dir, "ansible-galaxy", &["collection", "list", "--format", "json"]);
    let git = output(cfg, &dir, "git", &["--version"]);
    let ssh = output(cfg, &dir, "ssh", &["-V"]);
    drop(scratch);
    Ok(Toolchain {
        ansible_core: ansible_core_version(&ansible),
        python: python_version(&ansible),
        collections: collections(&list),
        git: git.trim().trim_start_matches("git version ").to_owned(),
        openssh: ssh.split(',').next().unwrap_or_default().trim().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_read_from_tool_output() {
        let ansible = "ansible-playbook [core 2.21.3]\n  config file = None\n  python version = 3.12.15 (main, Oct  1 2026) [GCC] (/opt/venv/bin/python3)\n";
        assert_eq!(ansible_core_version(ansible), "2.21.3");
        assert_eq!(python_version(ansible), "3.12.15");
        let list = r#"{"/usr/share/ansible/collections/ansible_collections": {"community.general": {"version": "13.5.0"}, "ansible.posix": {"version": "2.2.2"}}}"#;
        assert_eq!(
            collections(list),
            [
                ("ansible.posix".to_owned(), "2.2.2".to_owned()),
                ("community.general".to_owned(), "13.5.0".to_owned())
            ]
        );
        assert!(collections("not json").is_empty());
        assert_eq!(ansible_core_version(""), "");
    }
}
