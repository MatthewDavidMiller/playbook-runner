//! Fresh SSH keys for tests, so no private key is ever committed.
//!
//! Each call runs `ssh-keygen` (present in the toolbox and the runtime image)
//! in a private temporary directory, reads the key back, asks `ssh-keygen -l`
//! for its fingerprint, and removes the directory. Tests compare against that
//! fingerprint rather than one computed by the code under test.

#![doc(hidden)]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::{Error, Result, fsio, rand};

#[derive(Debug, Clone)]
pub struct TestKey {
    /// The OpenSSH private key file's text.
    pub private: String,
    /// `SHA256:...` exactly as `ssh-keygen -l` prints it.
    pub fingerprint: String,
}

/// Removes the key directory however the generation ends.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn ssh_keygen(args: &[&str]) -> Result<String> {
    let out = Command::new("ssh-keygen")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| Error::new(format!("cannot run ssh-keygen: {e}")))?;
    if !out.status.success() {
        return Err(Error::new(format!(
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A new ed25519 key, protected by `passphrase` unless it is empty.
pub fn generate(passphrase: &str) -> Result<TestKey> {
    let dir = std::env::temp_dir().join(format!("pr-testkey-{}", rand::random_hex(8)?));
    fsio::mkdir_all(&dir, 0o700)?;
    let scratch = Scratch(dir);
    let key = scratch.0.join("key");
    let key_arg = key.to_str().ok_or_else(|| Error::new("temporary path is not UTF-8"))?;
    ssh_keygen(&["-q", "-t", "ed25519", "-N", passphrase, "-C", "test", "-f", key_arg])?;
    let private =
        fsio::read_text(&key, 16 * 1024)?.ok_or_else(|| Error::new("ssh-keygen wrote no key"))?;
    let listing = ssh_keygen(&["-l", "-f", &format!("{key_arg}.pub")])?;
    let fingerprint = listing
        .split_ascii_whitespace()
        .nth(1)
        .filter(|f| f.starts_with("SHA256:"))
        .ok_or_else(|| Error::new("unexpected ssh-keygen -l output"))?
        .to_owned();
    Ok(TestKey { private, fingerprint })
}
