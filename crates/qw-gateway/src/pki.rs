//! Internal PQC certificate authority.
//!
//! The implementation now lives in the shared `qw-pki` crate so the desktop app
//! can run the same local CA. This module re-exports it to keep the existing
//! `crate::pki::CertAuthority` paths stable across the gateway.

pub use qw_pki::CertAuthority;
