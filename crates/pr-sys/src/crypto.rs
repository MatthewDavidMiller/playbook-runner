//! OpenSSL 3 libcrypto declarations and their safe wrappers: SHA-256, HMAC,
//! PBKDF2, AES-256-GCM, the CSPRNG, constant-time comparison, and cleansing.
//!
//! Every type is opaque: this crate only holds OpenSSL objects by pointer.

use std::ffi::{c_char, c_int, c_uint, c_void};

opaque!(EVP_MD, ENGINE, EVP_CIPHER, EVP_CIPHER_CTX);

const EVP_CTRL_GCM_SET_IVLEN: c_int = 0x9;
const EVP_CTRL_GCM_GET_TAG: c_int = 0x10;
const EVP_CTRL_GCM_SET_TAG: c_int = 0x11;

unsafe extern "C" {
    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_Digest(
        data: *const c_void,
        count: usize,
        md: *mut u8,
        size: *mut c_uint,
        kind: *const EVP_MD,
        engine: *mut ENGINE,
    ) -> c_int;
    fn HMAC(
        md: *const EVP_MD,
        key: *const c_void,
        key_len: c_int,
        data: *const u8,
        data_len: usize,
        out: *mut u8,
        out_len: *mut c_uint,
    ) -> *mut u8;
    fn PKCS5_PBKDF2_HMAC(
        pass: *const c_char,
        pass_len: c_int,
        salt: *const u8,
        salt_len: c_int,
        iterations: c_int,
        digest: *const EVP_MD,
        key_len: c_int,
        out: *mut u8,
    ) -> c_int;

    fn EVP_aes_256_gcm() -> *const EVP_CIPHER;
    fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;
    fn EVP_CIPHER_CTX_free(ctx: *mut EVP_CIPHER_CTX);
    fn EVP_CipherInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        engine: *mut ENGINE,
        key: *const u8,
        iv: *const u8,
        enc: c_int,
    ) -> c_int;
    fn EVP_CipherUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut u8,
        outl: *mut c_int,
        input: *const u8,
        inl: c_int,
    ) -> c_int;
    fn EVP_CipherFinal_ex(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int) -> c_int;
    fn EVP_CIPHER_CTX_ctrl(
        ctx: *mut EVP_CIPHER_CTX,
        kind: c_int,
        arg: c_int,
        ptr: *mut c_void,
    ) -> c_int;

    fn RAND_bytes(buf: *mut u8, num: c_int) -> c_int;
    fn CRYPTO_memcmp(a: *const c_void, b: *const c_void, len: usize) -> c_int;
    fn OPENSSL_cleanse(ptr: *mut c_void, len: usize);
}

/// Safe wrappers over the declarations above. Each checks the lengths
/// OpenSSL's `int` parameters can carry and reports failure as `None` or
/// `false`; nothing here aborts.
pub mod safe {
    use super::{
        CRYPTO_memcmp, EVP_CIPHER_CTX, EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free,
        EVP_CIPHER_CTX_new, EVP_CTRL_GCM_GET_TAG, EVP_CTRL_GCM_SET_IVLEN, EVP_CTRL_GCM_SET_TAG,
        EVP_CipherFinal_ex, EVP_CipherInit_ex, EVP_CipherUpdate, EVP_Digest, EVP_aes_256_gcm,
        EVP_sha256, HMAC, OPENSSL_cleanse, PKCS5_PBKDF2_HMAC, RAND_bytes,
    };
    use std::ffi::{c_int, c_uint};
    use std::ptr::{self, NonNull};

    pub const SHA256_LEN: usize = 32;
    pub const AES256_KEY_LEN: usize = 32;
    pub const GCM_NONCE_LEN: usize = 12;
    pub const GCM_TAG_LEN: usize = 16;

    fn c_len(len: usize) -> Option<c_int> {
        c_int::try_from(len).ok()
    }

    fn md_sha256() -> *const super::EVP_MD {
        // SAFETY: the getter takes no arguments and returns a static object.
        unsafe { EVP_sha256() }
    }

    fn cipher_aes256gcm() -> *const super::EVP_CIPHER {
        // SAFETY: the getter takes no arguments and returns a static object.
        unsafe { EVP_aes_256_gcm() }
    }

    pub fn sha256(data: &[u8]) -> Option<[u8; SHA256_LEN]> {
        let mut out = [0_u8; SHA256_LEN];
        let mut n: c_uint = 0;
        // SAFETY: `data` is readable for its length; `out` holds a SHA-256
        // digest.
        let ok = unsafe {
            EVP_Digest(
                data.as_ptr().cast(),
                data.len(),
                out.as_mut_ptr(),
                &raw mut n,
                md_sha256(),
                ptr::null_mut(),
            )
        };
        (ok == 1 && n as usize == SHA256_LEN).then_some(out)
    }

    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Option<[u8; SHA256_LEN]> {
        let key_len = c_len(key.len())?;
        let mut out = [0_u8; SHA256_LEN];
        let mut n: c_uint = 0;
        // SAFETY: key and data are readable for their lengths; `out` holds a
        // SHA-256 digest.
        let ret = unsafe {
            HMAC(
                md_sha256(),
                key.as_ptr().cast(),
                key_len,
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &raw mut n,
            )
        };
        (!ret.is_null() && n as usize == SHA256_LEN).then_some(out)
    }

    pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) -> bool {
        let (Some(plen), Some(slen), Ok(iter), Some(olen)) = (
            c_len(password.len()),
            c_len(salt.len()),
            c_int::try_from(iterations),
            c_len(out.len()),
        ) else {
            return false;
        };
        if iter == 0 {
            return false;
        }
        // SAFETY: every buffer is valid for the length passed with it.
        let ok = unsafe {
            PKCS5_PBKDF2_HMAC(
                password.as_ptr().cast(),
                plen,
                salt.as_ptr(),
                slen,
                iter,
                md_sha256(),
                olen,
                out.as_mut_ptr(),
            )
        };
        ok == 1
    }

    /// Fills `buf` from OpenSSL's CSPRNG.
    pub fn random_bytes(buf: &mut [u8]) -> bool {
        let Some(n) = c_len(buf.len()) else { return false };
        // SAFETY: `buf` is writable for `n` bytes.
        unsafe { RAND_bytes(buf.as_mut_ptr(), n) == 1 }
    }

    /// Constant-time equality of two slices; slices of different lengths are
    /// unequal (the length itself is not secret).
    pub fn ct_equal(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        if a.is_empty() {
            return true;
        }
        // SAFETY: both slices are readable for `a.len()` bytes.
        unsafe { CRYPTO_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) == 0 }
    }

    /// Overwrites `buf` with zeroes in a way the optimiser cannot remove.
    pub fn cleanse(buf: &mut [u8]) {
        if !buf.is_empty() {
            // SAFETY: `buf` is writable for its length.
            unsafe { OPENSSL_cleanse(buf.as_mut_ptr().cast(), buf.len()) }
        }
    }

    /// An owned cipher context; freeing it also clears the key schedule.
    struct CipherCtx(NonNull<EVP_CIPHER_CTX>);

    impl Drop for CipherCtx {
        fn drop(&mut self) {
            // SAFETY: created by EVP_CIPHER_CTX_new and freed once.
            unsafe { EVP_CIPHER_CTX_free(self.0.as_ptr()) };
        }
    }

    impl CipherCtx {
        /// A context initialised for AES-256-GCM with a 96-bit nonce.
        fn gcm(
            key: &[u8; AES256_KEY_LEN],
            nonce: &[u8; GCM_NONCE_LEN],
            encrypt: bool,
        ) -> Option<Self> {
            // SAFETY: no preconditions.
            let ctx = Self(NonNull::new(unsafe { EVP_CIPHER_CTX_new() })?);
            let p = ctx.0.as_ptr();
            // SAFETY: the context is live; selecting the cipher with no key
            // first lets the nonce length be set before the nonce is used.
            let selected = unsafe {
                EVP_CipherInit_ex(
                    p,
                    cipher_aes256gcm(),
                    ptr::null_mut(),
                    ptr::null(),
                    ptr::null(),
                    c_int::from(encrypt),
                )
            } == 1;
            // SAFETY: the context is live and has a GCM cipher selected.
            let ivlen = selected
                && unsafe {
                    EVP_CIPHER_CTX_ctrl(
                        p,
                        EVP_CTRL_GCM_SET_IVLEN,
                        GCM_NONCE_LEN as c_int,
                        ptr::null_mut(),
                    )
                } == 1;
            // SAFETY: key is 32 bytes and nonce 12, exactly what AES-256-GCM
            // with the nonce length set above reads.
            let keyed = ivlen
                && unsafe {
                    EVP_CipherInit_ex(
                        p,
                        ptr::null(),
                        ptr::null_mut(),
                        key.as_ptr(),
                        nonce.as_ptr(),
                        -1,
                    )
                } == 1;
            keyed.then_some(ctx)
        }

        fn aad(&mut self, data: &[u8]) -> bool {
            if data.is_empty() {
                return true;
            }
            let Some(n) = c_len(data.len()) else { return false };
            let mut out_len = 0;
            // SAFETY: a NULL output marks the input as AAD; `data` is
            // readable for `n` bytes.
            unsafe {
                EVP_CipherUpdate(
                    self.0.as_ptr(),
                    ptr::null_mut(),
                    &raw mut out_len,
                    data.as_ptr(),
                    n,
                ) == 1
            }
        }

        /// Runs the cipher over `data` in place; GCM is a stream mode, so it
        /// writes exactly as many bytes as it reads.
        fn update_in_place(&mut self, data: &mut [u8]) -> bool {
            for chunk in data.chunks_mut(1 << 30) {
                let Some(n) = c_len(chunk.len()) else { return false };
                let mut out_len = 0;
                // SAFETY: in-place operation is supported for GCM, which
                // writes exactly `n` bytes; `chunk` is valid for both.
                let ok = unsafe {
                    EVP_CipherUpdate(
                        self.0.as_ptr(),
                        chunk.as_mut_ptr(),
                        &raw mut out_len,
                        chunk.as_ptr(),
                        n,
                    )
                };
                if ok != 1 || out_len != n {
                    return false;
                }
            }
            true
        }

        fn finish(&mut self) -> bool {
            let mut scratch = [0_u8; 32];
            let mut out_len = 0;
            // SAFETY: GCM's final call writes nothing; `scratch` covers any
            // block regardless.
            let ok = unsafe {
                EVP_CipherFinal_ex(self.0.as_ptr(), scratch.as_mut_ptr(), &raw mut out_len)
            };
            ok == 1 && out_len == 0
        }
    }

    /// Encrypts `data` in place with AES-256-GCM and returns the tag.
    pub fn aes256gcm_seal(
        key: &[u8; AES256_KEY_LEN],
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> Option<[u8; GCM_TAG_LEN]> {
        let mut ctx = CipherCtx::gcm(key, nonce, true)?;
        if !(ctx.aad(aad) && ctx.update_in_place(data) && ctx.finish()) {
            return None;
        }
        let mut tag = [0_u8; GCM_TAG_LEN];
        // SAFETY: the context is live and finished; `tag` holds 16 bytes.
        let ok = unsafe {
            EVP_CIPHER_CTX_ctrl(
                ctx.0.as_ptr(),
                EVP_CTRL_GCM_GET_TAG,
                GCM_TAG_LEN as c_int,
                tag.as_mut_ptr().cast(),
            )
        };
        (ok == 1).then_some(tag)
    }

    /// Decrypts `data` in place with AES-256-GCM. On a tag mismatch the
    /// buffer is cleansed and `false` returned: unauthenticated plaintext is
    /// never left for a caller to use by mistake.
    pub fn aes256gcm_open(
        key: &[u8; AES256_KEY_LEN],
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; GCM_TAG_LEN],
    ) -> bool {
        let Some(mut ctx) = CipherCtx::gcm(key, nonce, false) else { return false };
        let mut tag = *tag;
        // SAFETY: the context is live; `tag` holds 16 bytes.
        let tagged = unsafe {
            EVP_CIPHER_CTX_ctrl(
                ctx.0.as_ptr(),
                EVP_CTRL_GCM_SET_TAG,
                GCM_TAG_LEN as c_int,
                tag.as_mut_ptr().cast(),
            )
        } == 1;
        let ok = tagged && ctx.aad(aad) && ctx.update_in_place(data) && ctx.finish();
        if !ok {
            cleanse(data);
        }
        ok
    }
}
