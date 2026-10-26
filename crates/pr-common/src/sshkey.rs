//! Just enough of the OpenSSH private key format (PROTOCOL.key) to validate
//! a key an operator pastes in and to show its fingerprint.
//!
//! The public half of an `openssh-key-v1` file is stored in the clear, so
//! the fingerprint -- `SHA256:` and the unpadded base64 of the public key
//! blob's SHA-256, exactly what `ssh-keygen -l` prints -- needs no
//! decryption. Passphrase-protected keys are refused: the runner loads keys
//! into ssh-agent non-interactively, which cannot answer a passphrase prompt.

use crate::buf::Cursor;
use crate::{Error, Result, base64};

const BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const END: &str = "-----END OPENSSH PRIVATE KEY-----";
const MAGIC: &[u8] = b"openssh-key-v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// The key type from the public blob, e.g. "ssh-ed25519".
    pub algorithm: String,
    /// The public key blob, for the fingerprint.
    pub public_blob: Vec<u8>,
}

fn string<'a>(c: &mut Cursor<'a>) -> Option<&'a [u8]> {
    let len = usize::try_from(c.be32()?).ok()?;
    c.take(len)
}

/// Parses a PEM-armoured `openssh-key-v1` private key.
pub fn parse_private_key(text: &str) -> Result<KeyInfo> {
    let invalid =
        || Error::new("not an OpenSSH private key (expected -----BEGIN OPENSSH PRIVATE KEY-----)");
    let text = text.trim();
    let body = text.strip_prefix(BEGIN).and_then(|t| t.strip_suffix(END)).ok_or_else(invalid)?;
    let raw = base64::decode(body.as_bytes()).ok_or_else(invalid)?;
    let rest = raw.strip_prefix(MAGIC).ok_or_else(invalid)?;
    let mut c = Cursor::new(rest);
    let cipher = string(&mut c).ok_or_else(invalid)?;
    let kdf = string(&mut c).ok_or_else(invalid)?;
    let _kdf_options = string(&mut c).ok_or_else(invalid)?;
    if cipher != b"none" || kdf != b"none" {
        return Err(Error::new(
            "the key is protected by a passphrase; remove it with ssh-keygen -p -N \"\" -f <file> first",
        ));
    }
    if c.be32() != Some(1) {
        return Err(Error::new("the key file must hold exactly one key"));
    }
    let public_blob = string(&mut c).ok_or_else(invalid)?.to_vec();
    let mut p = Cursor::new(&public_blob);
    let algorithm = string(&mut p)
        .and_then(|a| std::str::from_utf8(a).ok())
        .filter(|a| a.starts_with("ssh-") || a.starts_with("ecdsa-"))
        .ok_or_else(invalid)?
        .to_owned();
    // The private section must be present (it is never examined further).
    if string(&mut c).is_none_or(<[u8]>::is_empty) {
        return Err(invalid());
    }
    Ok(KeyInfo { algorithm, public_blob })
}

/// "SHA256:<base64>" of a public key blob, as `ssh-keygen -l` prints it.
pub fn fingerprint(sha256_of_blob: &[u8]) -> String {
    format!("SHA256:{}", base64::encode_unpadded(sha256_of_blob))
}

/// A throwaway ed25519 key generated solely for this repository's tests
/// (`ssh-keygen -t ed25519 -N "" -C test`). It grants access to nothing.
#[doc(hidden)]
pub const TEST_ONLY_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACA8Tljs8s7hm+1XlBx1CnCaAPrqj4/69ZqXTWRs5++ISwAAAIgl0GsUJdBr
FAAAAAtzc2gtZWQyNTUxOQAAACA8Tljs8s7hm+1XlBx1CnCaAPrqj4/69ZqXTWRs5++ISw
AAAEBWjtd/CbqqYVJZ9fmVTlYxSEJKZBO7DR7iWQbbI/gRTTxOWOzyzuGb7VeUHHUKcJoA
+uqPj/r1mpdNZGzn74hLAAAABHRlc3QB
-----END OPENSSH PRIVATE KEY-----
";

/// The fingerprint `ssh-keygen -l` prints for [`TEST_ONLY_KEY`].
#[doc(hidden)]
pub const TEST_ONLY_KEY_FINGERPRINT: &str = "SHA256:bONoM4jTqdMZh9q1BTJF8tbDRBC7L4gbi9apYSXP74M";

#[cfg(test)]
mod tests {
    use super::*;

    /// The same, protected by the passphrase "secret".
    const ENCRYPTED_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDseOLGmX
m2gTT+pEHJcupIAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIK/pcQp/wiimfYOY
Qmn5CjTuE6UVUkt1vt7trK16AftDAAAAkIUd4bpTkZMWsE6ypi0lwaMxXL7szI8GbsGy8w
kuCDuWtHZCCiKUl6vhlXjGvlNQaIA9qbQTVdb2ZhKQq+RwqDuMIuQ5fJnumpKSeuj52Tlj
rQBss8XkueoZUN7GjUUoreb4KTyf3Xre/Kz+4LVQ+fXogEK+M7u0rdVNeLmMwsmXy22GZ4
VK/SK8u876CUOu+A==
-----END OPENSSH PRIVATE KEY-----
";

    #[test]
    fn parses_an_unencrypted_key() {
        let info = parse_private_key(TEST_ONLY_KEY).unwrap();
        assert_eq!(info.algorithm, "ssh-ed25519");
        assert_eq!(info.public_blob.len(), 51);
    }

    #[test]
    fn refuses_passphrase_protected_keys() {
        let err = parse_private_key(ENCRYPTED_KEY).unwrap_err();
        assert!(err.message().contains("passphrase"), "{err}");
    }

    #[test]
    fn refuses_other_formats() {
        assert!(parse_private_key("ssh-ed25519 AAAA test").is_err());
        assert!(
            parse_private_key(
                "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"
            )
            .is_err()
        );
        let truncated = TEST_ONLY_KEY.replace("+uqPj/r1mpdNZGzn74hLAAAABHRlc3QB", "");
        assert!(parse_private_key(&truncated).is_err());
    }
}
