//! Copies a child's output into the run log line by line, masking every
//! known secret value and stopping at a size ceiling.
//!
//! ansible does not print vault passwords, but a playbook can print anything
//! it decrypts, and git or ssh can echo a URL. Masking the values the run
//! was given is the last line of defence, not the first.

use std::borrow::Cow;
use std::io::{ErrorKind, Read};

use pr_store::seallog::LogSink;

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
    /// Longest first, so a secret containing another is masked whole.
    secrets: Vec<Vec<u8>>,
    /// For each first byte, the secrets that start with it, longest first.
    by_first: Vec<Vec<usize>>,
}

impl Redactor {
    pub fn new(secrets: impl IntoIterator<Item = Vec<u8>>) -> Self {
        let mut secrets: Vec<Vec<u8>> =
            secrets.into_iter().filter(|s| s.len() >= MIN_SECRET_LEN).collect();
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        secrets.dedup();
        let mut by_first = vec![Vec::new(); 256];
        for (i, secret) in secrets.iter().enumerate() {
            if let Some(&first) = secret.first() {
                by_first[usize::from(first)].push(i);
            }
        }
        Self { secrets, by_first }
    }

    /// `line` with every known secret masked. One pass, and no copy at all
    /// for the common line that holds none.
    pub fn redact<'a>(&self, line: &'a [u8]) -> Cow<'a, [u8]> {
        let mut out: Option<Vec<u8>> = None;
        let mut copied = 0;
        let mut i = 0;
        while i < line.len() {
            let hit = self.by_first[usize::from(line[i])]
                .iter()
                .map(|&k| &self.secrets[k])
                .find(|secret| line[i..].starts_with(secret));
            if let Some(secret) = hit {
                let out = out.get_or_insert_with(|| Vec::with_capacity(line.len()));
                out.extend_from_slice(&line[copied..i]);
                out.extend_from_slice(MASK.as_bytes());
                i += secret.len();
                copied = i;
            } else {
                i += 1;
            }
        }
        match out {
            None => Cow::Borrowed(line),
            Some(mut out) => {
                out.extend_from_slice(&line[copied..]);
                Cow::Owned(out)
            }
        }
    }
}

impl Drop for Redactor {
    fn drop(&mut self) {
        for s in &mut self.secrets {
            pr_crypto::cleanse(s);
        }
    }
}

/// The lines of a private key's body, each masked on its own because the
/// log is masked a line at a time. The BEGIN/END lines are not secret.
pub fn ssh_key_secrets(key: &[u8]) -> Vec<Vec<u8>> {
    key.split(|&b| b == b'\n')
        .map(<[u8]>::trim_ascii)
        .filter(|line| line.len() >= 16 && !line.starts_with(b"-----"))
        .map(<[u8]>::to_vec)
        .collect()
}

/// Words that mark an inventory variable as holding a secret.
const SECRET_WORDS: [&str; 8] =
    ["pass", "pwd", "secret", "token", "key", "credential", "auth", "private"];
/// Variables ending like this hold a location, not a secret.
const LOCATION_SUFFIXES: [&str; 3] = ["_file", "_path", "_dir"];

/// Values of inventory variables that look like secrets (`ansible_become_pass`,
/// `api_token`, ...). The inventory is YAML and this project reads no YAML, so
/// this is a line-by-line heuristic and best-effort: it catches the plain
/// `name: value` form and skips vault blocks, templates, collections, and
/// short values. It is a second net under `no_log`, not a replacement.
pub fn inventory_secrets(inventory: &[u8]) -> Vec<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(inventory) else { return Vec::new() };
    let mut found = Vec::new();
    for line in text.lines() {
        let line = line.trim_start();
        let line = line.strip_prefix("- ").unwrap_or(line);
        let Some((name, value)) = line.split_once(':') else { continue };
        let name = name.trim().to_ascii_lowercase();
        if !SECRET_WORDS.iter().any(|w| name.contains(w))
            || LOCATION_SUFFIXES.iter().any(|s| name.ends_with(s))
        {
            continue;
        }
        let value = value.split(" #").next().unwrap_or_default().trim();
        let value = value.trim_matches(['"', '\'']);
        let skipped = value.len() < 8
            || value.starts_with(['!', '|', '>', '[', '{', '&', '*'])
            || value.contains("{{");
        if !skipped {
            found.push(value.as_bytes().to_vec());
        }
    }
    found
}

/// Writes one piece of output, or the notice that the log is full.
fn emit(log: &LogSink, redactor: &Redactor, line: &[u8], written: &mut u64, truncated: &mut bool) {
    if *truncated {
        return;
    }
    let clean = redactor.redact(line);
    if *written + clean.len() as u64 > LOG_LIMIT {
        log.write(b"\n[playbook-runner: log limit reached; further output discarded]\n");
        *truncated = true;
        return;
    }
    log.write(&clean);
    *written += clean.len() as u64;
}

/// Copies `input` to `log` until EOF, masking secrets. Output is sealed
/// after each burst, so a live log is readable as it arrives without a
/// write per line. Returns the bytes written.
pub fn pump(mut input: impl Read, log: &LogSink, redactor: &Redactor, mut written: u64) -> u64 {
    let mut pending: Vec<u8> = Vec::with_capacity(8192);
    let mut chunk = [0_u8; 16384];
    let mut truncated = false;
    loop {
        match input.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                pending.extend_from_slice(&chunk[..n]);
                let mut start = 0;
                while let Some(rel) = pending[start..].iter().position(|&b| b == b'\n') {
                    let end = start + rel + 1;
                    emit(log, redactor, &pending[start..end], &mut written, &mut truncated);
                    start = end;
                }
                pending.drain(..start);
                if pending.len() > LINE_LIMIT {
                    let line = std::mem::take(&mut pending);
                    emit(log, redactor, &line, &mut written, &mut truncated);
                }
                log.flush();
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    if !pending.is_empty() {
        emit(log, redactor, &pending, &mut written, &mut truncated);
    }
    log.flush();
    written
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pr_crypto::MasterKey;
    use pr_store::Sealer;

    use super::*;

    #[test]
    fn masks_every_occurrence_longest_first() {
        let r = Redactor::new([b"hunter2".to_vec(), b"hunter22".to_vec(), b"abcd".to_vec()]);
        assert_eq!(
            r.redact(b"pw=hunter22 and hunter2, abcd\n").as_ref(),
            b"pw=******** and ********, ********\n"
        );
        assert!(matches!(r.redact(b"nothing to hide\n"), Cow::Borrowed(_)));
        assert_eq!(r.redact(b"hunte").as_ref(), b"hunte");
    }

    #[test]
    fn key_bodies_and_inventory_secrets_are_found() {
        let key = b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\nAAAAB3NzaC1lZDI1NTE5AAAAIPlaceholder\n-----END OPENSSH PRIVATE KEY-----\n";
        let found = ssh_key_secrets(key);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|l| !l.starts_with(b"-----")));

        let inventory = b"all:\n  vars:\n    ansible_become_pass: 'sudo-example-pw'\n    api_token: abcdefgh12345 # note\n    \
            vault_pw: !vault |\n      $ANSIBLE_VAULT\n    db_password: \"{{ lookup('x') }}\"\n    short_key: abc\n    \
            ssh_private_key_file: /home/u/.ssh/id_ed25519\n    ansible_host: 192.0.2.1\n";
        let found: Vec<String> = inventory_secrets(inventory)
            .into_iter()
            .map(|v| String::from_utf8(v).unwrap())
            .collect();
        assert_eq!(found, ["sudo-example-pw", "abcdefgh12345"]);
    }

    #[test]
    fn pump_masks_across_chunk_boundaries_and_caps_lines() {
        let dir = std::env::temp_dir().join(format!("pr-redact-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("1.log");
        let sealer = Arc::new(Sealer::new(&MasterKey::from_hex(&[b'3'; 64]).unwrap()).unwrap());
        let log = LogSink::create(Arc::clone(&sealer), &path, 1).unwrap();
        let mut input = b"first line\nsecret: topsecretvalue\n".to_vec();
        input.extend(std::iter::repeat_n(b'x', LINE_LIMIT + 10));
        input.extend_from_slice(b"\ntail topsecretvalue");
        let r = Redactor::new([b"topsecretvalue".to_vec()]);
        let n = pump(input.as_slice(), &log, &r, 0);
        let (bytes, _) = pr_store::seallog::read_tail(&sealer, &path, 1, 1 << 22).unwrap().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(n, text.len() as u64);
        assert!(text.starts_with("first line\nsecret: ********\n"));
        assert!(text.ends_with("tail ********"));
        assert!(!text.contains("topsecret"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
