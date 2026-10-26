//! Link directives for libcrypto.
//!
//! Nothing is compiled here; the build script only tells rustc to link
//! libcrypto, and how. `PR_OPENSSL_STATIC=1` links it statically, which is
//! how the shipped binary is built so the runtime image needs no OpenSSL
//! package of its own.

use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=PR_OPENSSL_STATIC");
    let kind =
        if env::var("PR_OPENSSL_STATIC").is_ok_and(|v| v == "1") { "static" } else { "dylib" };
    println!("cargo:rustc-link-lib={kind}=crypto");
    println!("cargo:rustc-link-lib=dylib=pthread");
}
