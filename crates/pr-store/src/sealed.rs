//! Whole files sealed with the master key: the record collections, run
//! records, and the admin password hash.
//!
//! A sealed file is `"PRF1" || nonce || ciphertext || tag`, encrypted with
//! AES-256-GCM under a key derived for this purpose only. The authenticated
//! label names the file (`collection/templates.json`, `run/7`), so a file
//! copied over another one fails to open instead of being believed.
//!
//! Files written before sealing existed are plain text. [`Sealer::open_any`]
//! reads both so an upgrade needs no manual step; the next write seals them.

use pr_common::{Error, Result};
use pr_crypto::{MasterKey, SecretBytes, SubKey};

const MAGIC: &[u8; 4] = b"PRF1";
/// What sealing adds to a file: the magic, the nonce, and the tag.
pub const OVERHEAD: usize = 4 + 12 + 16;
const PURPOSE: &str = "files/v1";

#[derive(Debug)]
pub struct Sealer {
    key: SubKey,
}

impl Sealer {
    pub fn new(master: &MasterKey) -> Result<Self> {
        let key = master.derive(PURPOSE).map_err(|_| Error::new("key derivation failed"))?;
        Ok(Self { key })
    }

    fn aad(label: &str) -> String {
        format!("playbook-runner/v1/file/{label}")
    }

    /// The key log records are sealed under; see [`crate::seallog`].
    pub(crate) fn key(&self) -> &[u8; 32] {
        self.key.bytes()
    }

    pub fn is_sealed(raw: &[u8]) -> bool {
        raw.starts_with(MAGIC)
    }

    pub fn seal(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let sealed = pr_crypto::seal(self.key.bytes(), Self::aad(label).as_bytes(), plaintext)
            .map_err(|_| Error::new("encryption failed"))?;
        let mut out = Vec::with_capacity(MAGIC.len() + sealed.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Opens a sealed file. A plain file, a file sealed for another label,
    /// or one sealed under another key all fail.
    pub fn open(&self, label: &str, raw: &[u8]) -> Result<SecretBytes> {
        let sealed = raw.strip_prefix(MAGIC.as_slice()).ok_or_else(|| Error::new("not sealed"))?;
        pr_crypto::open(self.key.bytes(), Self::aad(label).as_bytes(), sealed)
            .map_err(|_| Error::new(format!("{label} failed authentication")))
    }

    /// The contents of a sealed or (from before sealing) plain file, and
    /// whether it was sealed.
    pub fn open_any(&self, label: &str, raw: Vec<u8>) -> Result<(SecretBytes, bool)> {
        if Self::is_sealed(&raw) {
            Ok((self.open(label, &raw)?, true))
        } else {
            Ok((SecretBytes::new(raw), false))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealer(c: u8) -> Sealer {
        Sealer::new(&MasterKey::from_hex(&[c; 64]).unwrap()).unwrap()
    }

    #[test]
    fn files_round_trip_and_are_bound_to_label_and_key() {
        let s = sealer(b'1');
        let sealed = s.seal("run/1", b"{\"status\":\"ok\"}").unwrap();
        assert!(!sealed.windows(6).any(|w| w == b"status"));
        assert_eq!(s.open("run/1", &sealed).unwrap().expose(), b"{\"status\":\"ok\"}");
        assert!(s.open("run/2", &sealed).is_err());
        assert!(sealer(b'2').open("run/1", &sealed).is_err());
        let mut flipped = sealed.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(s.open("run/1", &flipped).is_err());
    }

    #[test]
    fn plain_files_from_before_sealing_still_open() {
        let s = sealer(b'1');
        let (plain, sealed) = s.open_any("run/1", b"{\"a\":1}".to_vec()).unwrap();
        assert!(!sealed);
        assert_eq!(plain.expose(), b"{\"a\":1}");
        assert!(s.open("run/1", b"{\"a\":1}").is_err());
    }
}
