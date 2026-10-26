//! The data directory: typed records written atomically as JSON, and the
//! keystore that encrypts secrets and inventories at rest.
//!
//! ```text
//! <data>/keycheck              which master key this data belongs to
//! <data>/<collection>.json     one file per record type (no secret values)
//! <data>/blobs/<kind>-<id>     AES-256-GCM sealed values: "PRB1" || nonce || ct || tag
//! <data>/known_hosts           the managed OpenSSH known_hosts file
//! <data>/runs/                 run records and logs (pr-runner)
//! ```
//!
//! Every write replaces a whole file atomically under one process-wide
//! lock, so a crash leaves each file either old or new. Collections are
//! small (tens of records) and read from disk on every access, which keeps
//! the files the single source of truth.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod jsonw;
pub mod model;
pub mod validate;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use pr_common::json::{self, Value};
use pr_common::{Error, Result, fsio, rand};
use pr_crypto::{MasterKey, SecretBytes, SubKey};

pub use model::{
    Inventory, Record, RepoSnapshot, Repository, Schedule, Secret, SecretKind, Template,
};

/// The largest collection file: generous for a homelab's records.
const COLLECTION_LIMIT: usize = 4 * 1024 * 1024;
/// The largest sealed value: an inventory of 512 KiB plus framing.
const BLOB_LIMIT: usize = 600 * 1024;
pub const KNOWN_HOSTS_LIMIT: usize = 64 * 1024;
const BLOB_MAGIC: &[u8; 4] = b"PRB1";
const KEY_PURPOSE: &str = "store/v1";

#[derive(Debug)]
pub struct Store {
    dir: PathBuf,
    key: SubKey,
    lock: Mutex<()>,
}

fn key_check(master: &MasterKey) -> Result<String> {
    let check = master.derive("key-check").map_err(|_| Error::new("key derivation failed"))?;
    Ok(pr_crypto::hex(&check.bytes()[..16]))
}

/// A fresh record identifier: 16 lowercase hex digits.
pub fn new_id() -> Result<String> {
    rand::random_hex(8)
}

pub fn is_id(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Store {
    /// Opens (creating when new) the data directory. Refuses a master key
    /// other than the one the existing data was written with, so a wrong
    /// key fails at startup instead of mixing two keys' blobs.
    pub fn open(dir: &Path, master: &MasterKey) -> Result<Self> {
        fsio::mkdir_all(dir, 0o700)?;
        fsio::mkdir_all(dir.join("blobs"), 0o700)?;
        let check_path = dir.join("keycheck");
        let check = key_check(master)?;
        match fsio::read_text(&check_path, 256)? {
            Some(stored) if stored.trim() == check => {}
            Some(_) => {
                return Err(Error::new(
                    "the master key does not match the key this data directory was encrypted with",
                ));
            }
            None => fsio::atomic_replace(&check_path, format!("{check}\n").as_bytes(), 256)?,
        }
        let key = master.derive(KEY_PURPOSE).map_err(|_| Error::new("key derivation failed"))?;
        Ok(Self { dir: dir.to_path_buf(), key, lock: Mutex::new(()) })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn guard(&self) -> MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // ------------------------------------------------------- collections

    fn read_collection<T: Record>(&self) -> Result<Vec<T>> {
        let path = self.dir.join(T::FILE);
        let Some(text) = fsio::read_bounded(&path, COLLECTION_LIMIT)? else {
            return Ok(Vec::new());
        };
        let root = json::parse(&text).map_err(|e| Error::new(format!("{}: {e}", T::FILE)))?;
        let items = root
            .get("items")
            .and_then(Value::as_array)
            .filter(|_| {
                root.only_keys(&["version", "items"])
                    && root.get("version").and_then(Value::as_u64) == Some(1)
            })
            .ok_or_else(|| Error::new(format!("{}: unexpected layout", T::FILE)))?;
        items
            .iter()
            .map(|v| {
                T::read_json(v).ok_or_else(|| Error::new(format!("{}: malformed record", T::FILE)))
            })
            .collect()
    }

    fn write_collection<T: Record>(&self, items: &[T]) -> Result<()> {
        let mut out = String::from("{\"version\":1,\"items\":[");
        for (i, item) in items.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("\n  ");
            item.write_json(&mut out);
        }
        out.push_str("\n]}\n");
        fsio::atomic_replace(self.dir.join(T::FILE), out.as_bytes(), COLLECTION_LIMIT)
    }

    /// Every record of a type, sorted by name.
    pub fn list<T: Record>(&self) -> Result<Vec<T>> {
        let _g = self.guard();
        let mut items = self.read_collection::<T>()?;
        items.sort_by_key(|r| r.name().to_lowercase());
        Ok(items)
    }

    pub fn get<T: Record>(&self, id: &str) -> Result<Option<T>> {
        let _g = self.guard();
        Ok(self.read_collection::<T>()?.into_iter().find(|r| r.id() == id))
    }

    /// Inserts or replaces (by id) a record. Names are unique per type.
    pub fn put<T: Record>(&self, record: T) -> Result<()> {
        let _g = self.guard();
        let mut items = self.read_collection::<T>()?;
        if items
            .iter()
            .any(|r| r.id() != record.id() && r.name().eq_ignore_ascii_case(record.name()))
        {
            return Err(Error::new(format!(
                "Another {} is already named \"{}\"",
                T::NOUN,
                record.name()
            )));
        }
        match items.iter_mut().find(|r| r.id() == record.id()) {
            Some(slot) => *slot = record,
            None => items.push(record),
        }
        self.write_collection(&items)
    }

    /// Removes a record and its sealed value, if any.
    pub fn delete<T: Record>(&self, id: &str) -> Result<()> {
        let _g = self.guard();
        let mut items = self.read_collection::<T>()?;
        items.retain(|r| r.id() != id);
        self.write_collection(&items)?;
        if let Some(kind) = T::BLOB_KIND {
            fsio::remove_file_durable(self.blob_path(kind, id)?)?;
        }
        Ok(())
    }

    // ------------------------------------------------------------- blobs

    fn blob_path(&self, kind: &str, id: &str) -> Result<PathBuf> {
        if !is_id(id) || !kind.bytes().all(|b| b.is_ascii_lowercase()) {
            return Err(Error::new("invalid blob reference"));
        }
        Ok(self.dir.join("blobs").join(format!("{kind}-{id}")))
    }

    fn aad(kind: &str, id: &str) -> String {
        format!("playbook-runner/v1/{kind}/{id}")
    }

    /// Seals `plaintext` and stores it as the value of record `kind/id`.
    pub fn put_blob(&self, kind: &str, id: &str, plaintext: &[u8]) -> Result<()> {
        let path = self.blob_path(kind, id)?;
        let sealed = pr_crypto::seal(self.key.bytes(), Self::aad(kind, id).as_bytes(), plaintext)
            .map_err(|_| Error::new("encryption failed"))?;
        let mut out = Vec::with_capacity(BLOB_MAGIC.len() + sealed.len());
        out.extend_from_slice(BLOB_MAGIC);
        out.extend_from_slice(&sealed);
        let _g = self.guard();
        fsio::atomic_replace(path, &out, BLOB_LIMIT)
    }

    /// The decrypted value of record `kind/id`. A blob moved to another
    /// record, altered, or sealed under another key fails.
    pub fn get_blob(&self, kind: &str, id: &str) -> Result<SecretBytes> {
        let path = self.blob_path(kind, id)?;
        let raw = {
            let _g = self.guard();
            fsio::read_bounded(path, BLOB_LIMIT)?
                .ok_or_else(|| Error::new("the stored value is missing"))?
        };
        let sealed = raw
            .strip_prefix(BLOB_MAGIC.as_slice())
            .ok_or_else(|| Error::new("the stored value is corrupt"))?;
        pr_crypto::open(self.key.bytes(), Self::aad(kind, id).as_bytes(), sealed)
            .map_err(|_| Error::new("the stored value failed authentication"))
    }

    // ------------------------------------------------------- known_hosts

    pub fn known_hosts_path(&self) -> PathBuf {
        self.dir.join("known_hosts")
    }

    pub fn known_hosts(&self) -> Result<String> {
        let _g = self.guard();
        Ok(fsio::read_text(self.known_hosts_path(), KNOWN_HOSTS_LIMIT)?.unwrap_or_default())
    }

    pub fn set_known_hosts(&self, text: &str) -> Result<()> {
        let normalized = validate::known_hosts(text)?;
        let _g = self.guard();
        fsio::atomic_replace(self.known_hosts_path(), normalized.as_bytes(), KNOWN_HOSTS_LIMIT)
    }
}

/// Re-encrypts every blob from `old` to `new` and moves the key check to
/// `new`. Run it with the server stopped. It is safe to repeat after an
/// interruption: a blob that already opens under `new` is left alone.
pub fn rekey(dir: &Path, old: &MasterKey, new: &MasterKey) -> Result<usize> {
    let stored = fsio::read_text(dir.join("keycheck"), 256)?.unwrap_or_default();
    let (old_check, new_check) = (key_check(old)?, key_check(new)?);
    if stored.trim() != old_check && stored.trim() != new_check {
        return Err(Error::new("neither key matches this data directory"));
    }
    let old_key = old.derive(KEY_PURPOSE).map_err(|_| Error::new("key derivation failed"))?;
    let new_key = new.derive(KEY_PURPOSE).map_err(|_| Error::new("key derivation failed"))?;
    let mut converted = 0;
    let mut entries: Vec<_> = fs::read_dir(dir.join("blobs"))?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some((kind, id)) = name.split_once('-').filter(|(_, id)| is_id(id)) else { continue };
        let path = entry.path();
        let raw = fsio::read_bounded(&path, BLOB_LIMIT)?.unwrap_or_default();
        let sealed = raw
            .strip_prefix(BLOB_MAGIC.as_slice())
            .ok_or_else(|| Error::new(format!("{name} is corrupt")))?;
        let aad = Store::aad(kind, id);
        if pr_crypto::open(new_key.bytes(), aad.as_bytes(), sealed).is_ok() {
            continue;
        }
        let plain = pr_crypto::open(old_key.bytes(), aad.as_bytes(), sealed)
            .map_err(|_| Error::new(format!("{name} opens under neither key")))?;
        let resealed = pr_crypto::seal(new_key.bytes(), aad.as_bytes(), plain.expose())
            .map_err(|_| Error::new("encryption failed"))?;
        let mut out = BLOB_MAGIC.to_vec();
        out.extend_from_slice(&resealed);
        fsio::atomic_replace(&path, &out, BLOB_LIMIT)?;
        converted += 1;
    }
    fsio::atomic_replace(dir.join("keycheck"), format!("{new_check}\n").as_bytes(), 256)?;
    Ok(converted)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pr-store-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn key(c: u8) -> MasterKey {
        MasterKey::from_hex(&[c; 64]).unwrap()
    }

    fn secret(id: &str, name: &str) -> Secret {
        Secret {
            id: id.into(),
            name: name.into(),
            kind: SecretKind::VaultPassword,
            vault_id: "default".into(),
            fingerprint: String::new(),
            created: 1,
            updated: 2,
        }
    }

    #[test]
    fn records_round_trip_and_names_are_unique() {
        let dir = scratch("records");
        let store = Store::open(&dir, &key(b'1')).unwrap();
        let a = new_id().unwrap();
        store.put(secret(&a, "Vault \"prod\"")).unwrap();
        assert_eq!(store.get::<Secret>(&a).unwrap().unwrap().name, "Vault \"prod\"");
        let b = new_id().unwrap();
        assert!(store.put(secret(&b, "vault \"PROD\"")).is_err());
        store.put(secret(&b, "Another")).unwrap();
        let names: Vec<_> = store.list::<Secret>().unwrap().into_iter().map(|s| s.name).collect();
        assert_eq!(names, ["Another", "Vault \"prod\""]);
        store.delete::<Secret>(&a).unwrap();
        assert!(store.get::<Secret>(&a).unwrap().is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn blobs_are_encrypted_bound_to_their_record_and_key() {
        let dir = scratch("blobs");
        let store = Store::open(&dir, &key(b'1')).unwrap();
        let a = new_id().unwrap();
        let b = new_id().unwrap();
        store.put_blob("secret", &a, b"plaintext-vault-password").unwrap();
        assert_eq!(store.get_blob("secret", &a).unwrap().expose(), b"plaintext-vault-password");
        // Nothing under the data directory holds the plaintext.
        for entry in fs::read_dir(dir.join("blobs")).unwrap() {
            let bytes = fs::read(entry.unwrap().path()).unwrap();
            assert!(!bytes.windows(9).any(|w| w == b"plaintext"));
        }
        // A blob copied onto another record's name fails authentication.
        fs::copy(
            dir.join("blobs").join(format!("secret-{a}")),
            dir.join("blobs").join(format!("secret-{b}")),
        )
        .unwrap();
        assert!(store.get_blob("secret", &b).is_err());
        assert!(store.get_blob("secret", "../../etc/passwd").is_err());
        drop(store);
        // The wrong master key is refused at open.
        assert!(Store::open(&dir, &key(b'2')).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rekey_moves_every_blob_and_can_be_repeated() {
        let dir = scratch("rekey");
        let id = new_id().unwrap();
        Store::open(&dir, &key(b'1'))
            .unwrap()
            .put_blob("inventory", &id, b"all:\n  vars: {}\n")
            .unwrap();
        assert_eq!(rekey(&dir, &key(b'1'), &key(b'2')).unwrap(), 1);
        assert_eq!(rekey(&dir, &key(b'1'), &key(b'2')).unwrap(), 0);
        assert!(Store::open(&dir, &key(b'1')).is_err());
        let store = Store::open(&dir, &key(b'2')).unwrap();
        assert_eq!(store.get_blob("inventory", &id).unwrap().expose(), b"all:\n  vars: {}\n");
        assert!(rekey(&dir, &key(b'3'), &key(b'4')).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
