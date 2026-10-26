//! Hand-written FFI declarations for OpenSSL's libcrypto and the few POSIX
//! calls std does not wrap. This is the only crate allowed to use `unsafe`;
//! every other crate reaches these through safe wrappers.
