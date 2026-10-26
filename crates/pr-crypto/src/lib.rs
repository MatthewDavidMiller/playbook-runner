//! The cryptographic primitives the runner uses, all from OpenSSL's libcrypto.
//! Nothing here implements a primitive; it only adapts libcrypto to safe Rust.

#![forbid(unsafe_code)]
