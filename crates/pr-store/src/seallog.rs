//! Run logs sealed with the master key.
//!
//! A log is written while its run is going, and the run page reads its tail
//! every few seconds, so it cannot be one sealed blob. It is a header and a
//! sequence of records:
//!
//! ```text
//! "PRL1" 00 00 00 00                      8-byte header
//! len(4) || nonce || ciphertext || tag || len(4)      one record, repeated
//! ```
//!
//! Each record holds a few KiB of log text, sealed with AES-256-GCM. Its
//! authenticated data is the run number and the record's byte offset, so a
//! record moved within a log, or a log moved to another run, fails to open.
//! The length is written on both sides, which lets the tail be read by
//! walking backwards from the end without opening the rest.
//!
//! A record is appended with one write, so a crash leaves at worst a partial
//! record at the end, which readers skip. Logs written before sealing existed
//! are plain text; [`read_tail`] reads them and [`migrate`] seals them.

use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use pr_common::{Error, Result, fsio};
use pr_crypto::SecretBytes;

use crate::sealed::Sealer;

const MAGIC: &[u8; 4] = b"PRL1";
const HEADER: u64 = 8;
/// Log text per record: large enough to keep the framing negligible, small
/// enough that a live log appears promptly.
const CHUNK: usize = 32 * 1024;
/// The most a record's sealed body may hold; anything larger is corrupt.
const BODY_MAX: u64 = 1 << 20;
/// Nonce and tag: the least a sealed body can be.
const BODY_MIN: u64 = 12 + 16;
/// The largest log file this module will rewrite or read whole.
const FILE_LIMIT: usize = 24 * 1024 * 1024;

fn aad(run: u64, offset: u64) -> String {
    format!("playbook-runner/v1/log/{run}/{offset}")
}

fn len_bytes(len: usize) -> Result<[u8; 4]> {
    Ok(u32::try_from(len).map_err(|_| Error::new("log record too large"))?.to_be_bytes())
}

/// One framed record for `plain` that starts at `offset`.
fn frame(sealer: &Sealer, run: u64, offset: u64, plain: &[u8]) -> Result<Vec<u8>> {
    let body = pr_crypto::seal(sealer.key(), aad(run, offset).as_bytes(), plain)
        .map_err(|_| Error::new("encryption failed"))?;
    let len = len_bytes(body.len())?;
    let mut out = Vec::with_capacity(body.len() + 8);
    out.extend_from_slice(&len);
    out.extend_from_slice(&body);
    out.extend_from_slice(&len);
    Ok(out)
}

fn header() -> [u8; 8] {
    let mut h = [0_u8; 8];
    h[..4].copy_from_slice(MAGIC);
    h
}

/// A whole log as it would be on disk.
fn seal_all(sealer: &Sealer, run: u64, plain: &[u8]) -> Result<Vec<u8>> {
    let mut out = header().to_vec();
    for chunk in plain.chunks(CHUNK) {
        let offset = out.len() as u64;
        out.extend_from_slice(&frame(sealer, run, offset, chunk)?);
    }
    Ok(out)
}

#[derive(Debug)]
struct Inner {
    file: File,
    sealer: Arc<Sealer>,
    run: u64,
    offset: u64,
    buf: Vec<u8>,
}

impl Inner {
    fn flush(&mut self) -> Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let record = frame(&self.sealer, self.run, self.offset, &self.buf)?;
        self.buf.clear();
        // Appended in one write: a crash leaves a whole record or a partial
        // one at the end, never a gap.
        std::io::Write::write_all(&mut self.file, &record)?;
        self.offset += record.len() as u64;
        Ok(())
    }
}

/// The writing end of a sealed log, shared by the threads that feed one run.
/// Text is buffered and sealed in records; [`LogSink::flush`] makes what has
/// been written so far readable.
#[derive(Clone, Debug)]
pub struct LogSink {
    inner: Arc<Mutex<Inner>>,
}

impl LogSink {
    /// Opens (creating when new) the log at `path` for run `run`.
    pub fn create(sealer: Arc<Sealer>, path: &Path, run: u64) -> Result<Self> {
        let file =
            OpenOptions::new().create(true).append(true).read(true).mode(0o600).open(path)?;
        let mut offset = file.metadata()?.len();
        if offset == 0 {
            std::io::Write::write_all(&mut &file, &header())?;
            offset = HEADER;
        } else {
            let mut magic = [0_u8; 4];
            file.read_exact_at(&mut magic, 0).map_err(|_| Error::new("log is not sealed"))?;
            if &magic != MAGIC {
                return Err(Error::new("log is not sealed"));
            }
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                file,
                sealer,
                run,
                offset,
                buf: Vec::with_capacity(CHUNK + 4096),
            })),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Appends text. Writing is best-effort, like the file it replaces: a
    /// failed write loses output but never fails the run.
    pub fn write(&self, bytes: &[u8]) {
        let mut inner = self.lock();
        inner.buf.extend_from_slice(bytes);
        if inner.buf.len() >= CHUNK {
            let _ = inner.flush();
        }
    }

    /// Seals what is buffered so readers can see it.
    pub fn flush(&self) {
        let _ = self.lock().flush();
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

fn read_at(file: &File, offset: u64, len: u64) -> Result<Vec<u8>> {
    let mut buf = vec![0_u8; usize::try_from(len).map_err(|_| Error::new("log record too large"))?];
    file.read_exact_at(&mut buf, offset).map_err(|_| Error::new("the log is truncated"))?;
    Ok(buf)
}

fn read_len(file: &File, offset: u64) -> Option<u64> {
    let mut four = [0_u8; 4];
    file.read_exact_at(&mut four, offset).ok()?;
    Some(u64::from(u32::from_be_bytes(four)))
}

/// Where the last whole record ends. A healthy file ends at its length; one
/// cut off mid-record (a crash) ends at the last record that is complete.
fn valid_end(file: &File, len: u64) -> u64 {
    if len >= HEADER + 8 + BODY_MIN
        && let Some(body) = read_len(file, len - 4)
        && (BODY_MIN..=BODY_MAX).contains(&body)
        && len >= HEADER + 8 + body
        && read_len(file, len - 8 - body) == Some(body)
    {
        return len;
    }
    let mut pos = HEADER;
    while let Some(body) = read_len(file, pos) {
        if !(BODY_MIN..=BODY_MAX).contains(&body)
            || pos + 8 + body > len
            || read_len(file, pos + 4 + body) != Some(body)
        {
            break;
        }
        pos += 8 + body;
    }
    pos
}

/// The record that ends at `end`: its start offset and plaintext.
fn record_before(file: &File, sealer: &Sealer, run: u64, end: u64) -> Result<(u64, SecretBytes)> {
    let corrupt = || Error::new("the log is corrupt");
    let body = read_len(file, end.checked_sub(4).ok_or_else(corrupt)?).ok_or_else(corrupt)?;
    if !(BODY_MIN..=BODY_MAX).contains(&body) {
        return Err(corrupt());
    }
    let start = end.checked_sub(8 + body).filter(|s| *s >= HEADER).ok_or_else(corrupt)?;
    let raw = read_at(file, start + 4, body)?;
    if read_len(file, start) != Some(body) {
        return Err(corrupt());
    }
    let plain = pr_crypto::open(sealer.key(), aad(run, start).as_bytes(), &raw)
        .map_err(|_| Error::new("the log failed authentication"))?;
    Ok((start, plain))
}

fn is_sealed_file(file: &File, len: u64) -> bool {
    let mut magic = [0_u8; 4];
    len >= HEADER && file.read_exact_at(&mut magic, 0).is_ok() && &magic == MAGIC
}

fn legacy_tail(file: &File, len: u64, max: u64) -> Result<(Vec<u8>, bool)> {
    let start = len.saturating_sub(max);
    Ok((read_at(file, start, len - start)?, start > 0))
}

/// The last `max` bytes of the log at `path` (the whole log if it is
/// shorter) and whether earlier output was left out. `Ok(None)` means there
/// is no such log.
pub fn read_tail(
    sealer: &Sealer,
    path: &Path,
    run: u64,
    max: u64,
) -> Result<Option<(Vec<u8>, bool)>> {
    let file = match fsio::open_nofollow(path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let len = file.metadata()?.len();
    if !is_sealed_file(&file, len) {
        return legacy_tail(&file, len, max).map(Some);
    }
    let mut end = valid_end(&file, len);
    let mut chunks: Vec<SecretBytes> = Vec::new();
    let mut have: u64 = 0;
    while end > HEADER && have < max {
        let (start, plain) = record_before(&file, sealer, run, end)?;
        have += plain.len() as u64;
        chunks.push(plain);
        end = start;
    }
    let mut out = Vec::with_capacity(usize::try_from(have.min(max)).unwrap_or(0));
    for chunk in chunks.iter().rev() {
        out.extend_from_slice(chunk.expose());
    }
    let extra = usize::try_from(have.saturating_sub(max)).unwrap_or(0);
    out.drain(..extra);
    Ok(Some((out, end > HEADER || extra > 0)))
}

/// Seals a log written before sealing existed. Returns whether it changed.
pub fn migrate(sealer: &Sealer, path: &Path, run: u64) -> Result<bool> {
    let Some(raw) = fsio::read_bounded(path, FILE_LIMIT)? else { return Ok(false) };
    if raw.is_empty() || raw.starts_with(MAGIC) {
        return Ok(false);
    }
    fsio::atomic_replace(path, &seal_all(sealer, run, &raw)?, FILE_LIMIT)?;
    Ok(true)
}

/// Moves a log from `old` to `new`. A log that already opens under `new` is
/// left alone, so an interrupted rekey can be repeated. Returns whether it
/// changed.
pub fn reseal(old: &Sealer, new: &Sealer, path: &Path, run: u64) -> Result<bool> {
    let Some(raw) = fsio::read_bounded(path, FILE_LIMIT)? else { return Ok(false) };
    if raw.is_empty() {
        return Ok(false);
    }
    if !raw.starts_with(MAGIC) {
        fsio::atomic_replace(path, &seal_all(new, run, &raw)?, FILE_LIMIT)?;
        return Ok(true);
    }
    let file = fsio::open_nofollow(path)?;
    let len = file.metadata()?.len();
    let end = valid_end(&file, len);
    if end > HEADER && record_before(&file, new, run, end).is_ok() {
        return Ok(false);
    }
    let mut plain = Vec::new();
    let mut pos = HEADER;
    while pos < end {
        let body = read_len(&file, pos).ok_or_else(|| Error::new("the log is corrupt"))?;
        let opened =
            pr_crypto::open(old.key(), aad(run, pos).as_bytes(), &read_at(&file, pos + 4, body)?)
                .map_err(|_| Error::new("the log opens under neither key"))?;
        plain.extend_from_slice(opened.expose());
        pos += 8 + body;
    }
    fsio::atomic_replace(path, &seal_all(new, run, &plain)?, FILE_LIMIT)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pr_crypto::MasterKey;

    fn sealer(c: u8) -> Arc<Sealer> {
        Arc::new(Sealer::new(&MasterKey::from_hex(&[c; 64]).unwrap()).unwrap())
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pr-seallog-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("7.log")
    }

    fn tail(s: &Sealer, path: &Path, max: u64) -> (String, bool) {
        let (bytes, cut) = read_tail(s, path, 7, max).unwrap().unwrap();
        (String::from_utf8(bytes).unwrap(), cut)
    }

    #[test]
    fn a_log_round_trips_and_holds_no_plaintext() {
        let s = sealer(b'1');
        let path = scratch("round");
        let sink = LogSink::create(Arc::clone(&s), &path, 7).unwrap();
        sink.write(b"hello topsecret world\n");
        sink.flush();
        sink.write(b"second line\n");
        sink.flush();
        let on_disk = std::fs::read(&path).unwrap();
        assert!(!on_disk.windows(9).any(|w| w == b"topsecret"));
        assert_eq!(
            tail(&s, &path, 1 << 20),
            ("hello topsecret world\nsecond line\n".into(), false)
        );
        // Only the tail: the first record is left out, and the cut is reported.
        let (text, cut) = tail(&s, &path, 12);
        assert_eq!((text.as_str(), cut), ("second line\n", true));
        // Unflushed text is not readable yet; dropping the sink flushes it.
        sink.write(b"late\n");
        assert!(!tail(&s, &path, 1 << 20).0.contains("late"));
        drop(sink);
        assert!(tail(&s, &path, 1 << 20).0.ends_with("late\n"));
    }

    #[test]
    fn large_logs_span_records_and_still_read_back_whole() {
        let s = sealer(b'1');
        let path = scratch("large");
        let sink = LogSink::create(Arc::clone(&s), &path, 7).unwrap();
        let line = "x".repeat(99) + "\n";
        for _ in 0..2000 {
            sink.write(line.as_bytes());
        }
        drop(sink);
        let (text, cut) = tail(&s, &path, 1 << 20);
        assert_eq!((text.len(), cut), (200_000, false));
        let (text, cut) = tail(&s, &path, 150_000);
        assert_eq!((text.len(), cut), (150_000, true));
    }

    #[test]
    fn tampering_moving_and_the_wrong_key_are_refused() {
        let s = sealer(b'1');
        let path = scratch("tamper");
        let sink = LogSink::create(Arc::clone(&s), &path, 7).unwrap();
        sink.write(b"one\n");
        sink.flush();
        sink.write(b"two\n");
        drop(sink);
        assert!(read_tail(&sealer(b'2'), &path, 7, 100).is_err());
        assert!(read_tail(&s, &path, 8, 100).is_err(), "another run's number");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[8 + 4 + 13] ^= 1; // inside the first record's ciphertext
        std::fs::write(&path, &bytes).unwrap();
        assert!(read_tail(&s, &path, 7, 1 << 20).is_err());
    }

    #[test]
    fn a_crash_mid_record_costs_only_that_record() {
        let s = sealer(b'1');
        let path = scratch("crash");
        let sink = LogSink::create(Arc::clone(&s), &path, 7).unwrap();
        sink.write(b"kept\n");
        sink.flush();
        sink.write(b"lost\n");
        drop(sink);
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() - 9]).unwrap();
        assert_eq!(tail(&s, &path, 1 << 20), ("kept\n".into(), false));
    }

    #[test]
    fn plain_logs_read_migrate_and_rekey() {
        let (s, t) = (sealer(b'1'), sealer(b'2'));
        let path = scratch("legacy");
        std::fs::write(&path, b"old plain log\nsecond\n").unwrap();
        assert_eq!(tail(&s, &path, 1 << 20), ("old plain log\nsecond\n".into(), false));
        assert_eq!(tail(&s, &path, 7), ("second\n".into(), true));
        assert!(migrate(&s, &path, 7).unwrap());
        assert!(!migrate(&s, &path, 7).unwrap());
        assert!(!std::fs::read(&path).unwrap().windows(3).any(|w| w == b"old"));
        assert_eq!(tail(&s, &path, 1 << 20).0, "old plain log\nsecond\n");
        assert!(reseal(&s, &t, &path, 7).unwrap());
        assert!(!reseal(&s, &t, &path, 7).unwrap(), "repeatable");
        assert!(read_tail(&s, &path, 7, 100).is_err());
        assert_eq!(tail(&t, &path, 1 << 20).0, "old plain log\nsecond\n");
    }
}
