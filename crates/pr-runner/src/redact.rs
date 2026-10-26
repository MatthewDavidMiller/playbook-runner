//! Copies a child's output into the run log line by line, masking every
//! known secret value and stopping at a size ceiling.
//!
//! ansible does not print vault passwords, but a playbook can print anything
//! it decrypts, and git or ssh can echo a URL. Masking the values the run
//! was given is the last line of defence, not the first.

use std::fs::File;
use std::io::{ErrorKind, Read, Write};

/// The most a run log grows to; past it the log ends with a notice.
pub const LOG_LIMIT: u64 = 16 * 1024 * 1024;
/// Lines longer than this are written in pieces.
const LINE_LIMIT: usize = 64 * 1024;
/// Values shorter than this are not masked: masking "a" would shred the log
/// and protect nothing.
const MIN_SECRET_LEN: usize = 4;
pub const MASK: &str = "********";

#[derive(Debug)]
pub struct Redactor {
    secrets: Vec<Vec<u8>>,
}

impl Redactor {
    pub fn new(secrets: impl IntoIterator<Item = Vec<u8>>) -> Self {
        let mut secrets: Vec<Vec<u8>> =
            secrets.into_iter().filter(|s| s.len() >= MIN_SECRET_LEN).collect();
        // Longest first, so a secret containing another is masked whole.
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        Self { secrets }
    }

    pub fn redact(&self, line: &[u8]) -> Vec<u8> {
        let mut out = line.to_vec();
        for secret in &self.secrets {
            let mut i = 0;
            let mut replaced = Vec::with_capacity(out.len());
            while i < out.len() {
                if out[i..].starts_with(secret) {
                    replaced.extend_from_slice(MASK.as_bytes());
                    i += secret.len();
                } else {
                    replaced.push(out[i]);
                    i += 1;
                }
            }
            out = replaced;
        }
        out
    }
}

impl Drop for Redactor {
    fn drop(&mut self) {
        for s in &mut self.secrets {
            pr_crypto::cleanse(s);
        }
    }
}

/// Copies `input` to `log` until EOF. Returns the bytes written.
pub fn pump(mut input: impl Read, log: &mut File, redactor: &Redactor, mut written: u64) -> u64 {
    let mut pending: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 8192];
    let mut truncated = false;
    let mut emit = |line: &[u8], written: &mut u64, truncated: &mut bool| {
        if *truncated {
            return;
        }
        let clean = redactor.redact(line);
        if *written + clean.len() as u64 > LOG_LIMIT {
            let _ = log
                .write_all(b"\n[playbook-runner: log limit reached; further output discarded]\n");
            *truncated = true;
            return;
        }
        if log.write_all(&clean).is_ok() {
            *written += clean.len() as u64;
        }
    };
    loop {
        match input.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                pending.extend_from_slice(&chunk[..n]);
                while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = pending.drain(..=pos).collect();
                    emit(&line, &mut written, &mut truncated);
                }
                if pending.len() > LINE_LIMIT {
                    let line = std::mem::take(&mut pending);
                    emit(&line, &mut written, &mut truncated);
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    if !pending.is_empty() {
        emit(&pending, &mut written, &mut truncated);
    }
    let _ = log.flush();
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_every_occurrence_longest_first() {
        let r = Redactor::new([b"hunter2".to_vec(), b"hunter22".to_vec(), b"ab".to_vec()]);
        assert_eq!(r.redact(b"pw=hunter22 and hunter2, ab\n"), b"pw=******** and ********, ab\n");
    }

    #[test]
    fn pump_masks_across_chunk_boundaries_and_caps_lines() {
        let dir = std::env::temp_dir().join(format!("pr-redact-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log");
        let mut log = File::create(&path).unwrap();
        let mut input = b"first line\nsecret: topsecretvalue\n".to_vec();
        input.extend(std::iter::repeat_n(b'x', LINE_LIMIT + 10));
        input.extend_from_slice(b"\ntail topsecretvalue");
        let r = Redactor::new([b"topsecretvalue".to_vec()]);
        let n = pump(input.as_slice(), &mut log, &r, 0);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(n, text.len() as u64);
        assert!(text.starts_with("first line\nsecret: ********\n"));
        assert!(text.ends_with("tail ********"));
        assert!(!text.contains("topsecret"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
