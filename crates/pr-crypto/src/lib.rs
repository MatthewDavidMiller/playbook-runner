//! The cryptographic primitives the runner uses, all from OpenSSL's libcrypto.
//! Nothing here implements a primitive; it only adapts libcrypto to safe Rust.
//! HKDF is the RFC 5869 construction over libcrypto's HMAC, not a primitive
//! of its own.

#![forbid(unsafe_code)]

use std::fmt;

use pr_sys::crypto::safe;

pub use safe::{AES256_KEY_LEN, GCM_NONCE_LEN, GCM_TAG_LEN, SHA256_LEN};

/// libcrypto reported a failure, or an input was out of range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoError;

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cryptographic operation failed")
    }
}

impl std::error::Error for CryptoError {}

pub type Result<T> = std::result::Result<T, CryptoError>;

pub fn sha256(data: &[u8]) -> Result<[u8; SHA256_LEN]> {
    safe::sha256(data).ok_or(CryptoError)
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; SHA256_LEN]> {
    safe::hmac_sha256(key, data).ok_or(CryptoError)
}

pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) -> Result<()> {
    safe::pbkdf2_sha256(password, salt, iterations, out).then_some(()).ok_or(CryptoError)
}

/// HKDF-SHA256 (RFC 5869): extract with `salt`, then expand to fill `out`,
/// which may be at most 255 hash lengths.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    if out.len() > 255 * SHA256_LEN {
        return Err(CryptoError);
    }
    let zero_salt = [0_u8; SHA256_LEN];
    let mut prk = hmac_sha256(if salt.is_empty() { &zero_salt } else { salt }, ikm)?;
    let mut block = [0_u8; SHA256_LEN];
    let mut input = Vec::with_capacity(SHA256_LEN + info.len() + 1);
    let mut result = Ok(());
    for (i, chunk) in out.chunks_mut(SHA256_LEN).enumerate() {
        input.clear();
        if i > 0 {
            input.extend_from_slice(&block);
        }
        input.extend_from_slice(info);
        // At most 255 blocks, checked above.
        input.push(u8::try_from(i + 1).unwrap_or(u8::MAX));
        match hmac_sha256(&prk, &input) {
            Ok(b) => block = b,
            Err(e) => {
                result = Err(e);
                break;
            }
        }
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
    cleanse(&mut prk);
    cleanse(&mut block);
    cleanse(&mut input);
    if result.is_err() {
        cleanse(out);
    }
    result
}

/// Fills `out` from libcrypto's CSPRNG.
pub fn random_bytes(out: &mut [u8]) -> Result<()> {
    safe::random_bytes(out).then_some(()).ok_or(CryptoError)
}

pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0_u8; N];
    random_bytes(&mut out)?;
    Ok(out)
}

/// Constant-time equality; different lengths compare unequal.
pub fn ct_equal(a: &[u8], b: &[u8]) -> bool {
    safe::ct_equal(a, b)
}

/// Zeroes `buf` in a way the optimiser cannot remove.
pub fn cleanse(buf: &mut [u8]) {
    safe::cleanse(buf);
}

/// Encrypts `plaintext` with AES-256-GCM under a fresh random nonce and
/// returns `nonce || ciphertext || tag`.
pub fn seal(key: &[u8; AES256_KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce: [u8; GCM_NONCE_LEN] = random_array()?;
    seal_with_nonce(key, &nonce, aad, plaintext)
}

/// [`seal`] with a caller-chosen nonce. A nonce must never be reused under
/// one key; only the tests and [`seal`] call this.
pub fn seal_with_nonce(
    key: &[u8; AES256_KEY_LEN],
    nonce: &[u8; GCM_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(GCM_NONCE_LEN + plaintext.len() + GCM_TAG_LEN);
    out.extend_from_slice(nonce);
    out.extend_from_slice(plaintext);
    let tag =
        safe::aes256gcm_seal(key, nonce, aad, &mut out[GCM_NONCE_LEN..]).ok_or(CryptoError)?;
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Reverses [`seal`]. Any tampering with the nonce, ciphertext, tag, or
/// `aad` fails, and no plaintext is returned.
pub fn open(key: &[u8; AES256_KEY_LEN], aad: &[u8], sealed: &[u8]) -> Result<SecretBytes> {
    if sealed.len() < GCM_NONCE_LEN + GCM_TAG_LEN {
        return Err(CryptoError);
    }
    let (nonce, rest) = sealed.split_at(GCM_NONCE_LEN);
    let (body, tag) = rest.split_at(rest.len() - GCM_TAG_LEN);
    let nonce: &[u8; GCM_NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError)?;
    let tag: &[u8; GCM_TAG_LEN] = tag.try_into().map_err(|_| CryptoError)?;
    let mut plain = SecretBytes::new(body.to_vec());
    if safe::aes256gcm_open(key, nonce, aad, &mut plain.0, tag) {
        Ok(plain)
    } else {
        Err(CryptoError)
    }
}

/// Bytes that are cleansed when dropped. Debug output never shows them.
#[derive(Default)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Cleanse the whole allocation, spare capacity included.
        let cap = self.0.capacity();
        self.0.resize(cap, 0);
        cleanse(&mut self.0);
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes({} bytes)", self.0.len())
    }
}

/// The 256-bit master key every other key is derived from. It is read once
/// from a file outside the data directory (a Podman secret in production),
/// held in memory for the life of the process, and cleansed on drop.
pub struct MasterKey([u8; AES256_KEY_LEN]);

/// The most a key file may hold: 64 hex digits plus surrounding whitespace.
const KEY_FILE_LIMIT: usize = 256;

impl MasterKey {
    /// Parses 64 hex digits, ignoring surrounding whitespace.
    pub fn from_hex(text: &[u8]) -> Result<Self> {
        let trimmed = text.trim_ascii();
        if trimmed.len() != AES256_KEY_LEN * 2 {
            return Err(CryptoError);
        }
        let mut key = [0_u8; AES256_KEY_LEN];
        let digit = |c: u8| char::from(c).to_digit(16).and_then(|d| u8::try_from(d).ok());
        for (slot, &[hi, lo]) in key.iter_mut().zip(trimmed.as_chunks::<2>().0) {
            if let (Some(hi), Some(lo)) = (digit(hi), digit(lo)) {
                *slot = hi << 4 | lo;
            } else {
                cleanse(&mut key);
                return Err(CryptoError);
            }
        }
        if key.iter().all(|&b| b == 0) {
            return Err(CryptoError);
        }
        Ok(Self(key))
    }

    /// Reads a key file of at most a few hundred bytes. The caller reports
    /// which path failed; the error never says why, so it cannot leak key
    /// material into a log.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        use std::io::Read;
        let mut file = std::fs::File::open(path).map_err(|_| CryptoError)?;
        // One byte past the limit tells an oversized file apart.
        let mut text = [0_u8; KEY_FILE_LIMIT + 1];
        let mut len = 0;
        let read = loop {
            match file.read(&mut text[len..]) {
                Ok(0) => break Ok(len),
                Ok(n) => {
                    len += n;
                    if len == text.len() {
                        break Err(CryptoError);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break Err(CryptoError),
            }
        };
        let key = read.and_then(|n| Self::from_hex(&text[..n]));
        cleanse(&mut text);
        key
    }
    /// A fresh random key as 64 hex digits, for `playbook-runner gen-key`.
    pub fn generate_hex() -> Result<SecretBytes> {
        let mut key: [u8; AES256_KEY_LEN] = random_array()?;
        let text = hex(&key).into_bytes();
        cleanse(&mut key);
        Ok(SecretBytes::new(text))
    }

    /// A subkey for one purpose: HKDF-SHA256 with the purpose as `info`.
    /// Distinct purposes yield independent keys, so a key used for sessions
    /// can never decrypt a stored secret.
    pub fn derive(&self, purpose: &str) -> Result<SubKey> {
        let mut out = [0_u8; AES256_KEY_LEN];
        hkdf_sha256(&self.0, b"playbook-runner", purpose.as_bytes(), &mut out)?;
        Ok(SubKey(out))
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        cleanse(&mut self.0);
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey(..)")
    }
}

/// A derived 256-bit key, cleansed on drop.
pub struct SubKey([u8; AES256_KEY_LEN]);

impl SubKey {
    pub fn bytes(&self) -> &[u8; AES256_KEY_LEN] {
        &self.0
    }
}

impl Drop for SubKey {
    fn drop(&mut self) {
        cleanse(&mut self.0);
    }
}

impl fmt::Debug for SubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SubKey(..)")
    }
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 15)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn sha256_fips_180_vector() {
        assert_eq!(
            hex(&sha256(b"abc").unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_rfc_4231_case_2() {
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?").unwrap()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hkdf_rfc_5869_case_1() {
        let mut okm = [0_u8; 42];
        hkdf_sha256(
            &[0x0b; 22],
            &unhex("000102030405060708090a0b0c"),
            &unhex("f0f1f2f3f4f5f6f7f8f9"),
            &mut okm,
        )
        .unwrap();
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_rfc_5869_case_3_empty_salt_and_info() {
        let mut okm = [0_u8; 42];
        hkdf_sha256(&[0x0b; 22], b"", b"", &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn hkdf_refuses_oversized_output() {
        let mut okm = vec![0_u8; 255 * 32 + 1];
        assert!(hkdf_sha256(b"k", b"", b"", &mut okm).is_err());
    }

    #[test]
    fn pbkdf2_vectors() {
        let mut out = [0_u8; 32];
        pbkdf2_sha256(b"password", b"salt", 1, &mut out).unwrap();
        assert_eq!(hex(&out), "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
        pbkdf2_sha256(b"password", b"salt", 2, &mut out).unwrap();
        assert_eq!(hex(&out), "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
        assert!(pbkdf2_sha256(b"password", b"salt", 0, &mut out).is_err());
    }

    #[test]
    fn aes_gcm_spec_case_14() {
        let sealed = seal_with_nonce(&[0; 32], &[0; 12], b"", &[0; 16]).unwrap();
        assert_eq!(
            hex(&sealed[12..]),
            "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
        );
    }

    #[test]
    fn aes_gcm_spec_case_16_with_aad() {
        let key: [u8; 32] =
            unhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
                .try_into()
                .unwrap();
        let nonce: [u8; 12] = unhex("cafebabefacedbaddecaf888").try_into().unwrap();
        let plain = unhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let sealed = seal_with_nonce(&key, &nonce, &aad, &plain).unwrap();
        assert_eq!(
            hex(&sealed[12..]),
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662\
             76fc6ece0f4e1768cddf8853bb2d551b"
        );
        assert_eq!(open(&key, &aad, &sealed).unwrap().expose(), plain.as_slice());
    }

    #[test]
    fn seal_round_trips_and_rejects_every_kind_of_tampering() {
        let key = random_array::<32>().unwrap();
        let sealed = seal(&key, b"secret:abc", b"vault password").unwrap();
        assert_eq!(open(&key, b"secret:abc", &sealed).unwrap().expose(), b"vault password");
        // A fresh nonce each time: the same input never seals the same way.
        assert_ne!(sealed, seal(&key, b"secret:abc", b"vault password").unwrap());
        assert!(open(&key, b"secret:abd", &sealed).is_err());
        for i in [0, 12, sealed.len() - 1] {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert!(open(&key, b"secret:abc", &bad).is_err(), "byte {i}");
        }
        let other = random_array::<32>().unwrap();
        assert!(open(&other, b"secret:abc", &sealed).is_err());
        assert!(open(&key, b"secret:abc", &sealed[..27]).is_err());
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_equal(b"abc", b"abc"));
        assert!(!ct_equal(b"abc", b"abd"));
        assert!(!ct_equal(b"abc", b"ab"));
        assert!(ct_equal(b"", b""));
    }

    #[test]
    fn master_key_parsing_and_derivation() {
        let text = MasterKey::generate_hex().unwrap();
        assert_eq!(text.len(), 64);
        let key = MasterKey::from_hex(text.expose()).unwrap();
        let mut padded = b"  ".to_vec();
        padded.extend_from_slice(text.expose());
        padded.push(b'\n');
        let same = MasterKey::from_hex(&padded).unwrap();
        let a = key.derive("secrets").unwrap();
        assert_eq!(a.bytes(), same.derive("secrets").unwrap().bytes());
        assert_ne!(a.bytes(), key.derive("web").unwrap().bytes());
        for bad in [&b""[..], b"abcd", &[b'0'; 64], &[b'g'; 64]] {
            assert!(MasterKey::from_hex(bad).is_err());
        }
        assert_eq!(format!("{key:?}"), "MasterKey(..)");
    }

    #[test]
    fn secret_debug_hides_contents() {
        assert_eq!(format!("{:?}", SecretBytes::new(b"hunter2".to_vec())), "SecretBytes(7 bytes)");
    }
}
