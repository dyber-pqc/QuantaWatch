//! Stamp the build time + git hash into the binary so the running app can show
//! exactly which build it is (ending "am I on the latest exe?" confusion).
//! With no `rerun-if-changed` directives, Cargo re-runs this whenever any file
//! in the package changes, so the stamp tracks the last real rebuild.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // ML-DSA-65 (FIPS 204) key generation and signing use several MB of stack in
    // this build. The desktop performs those on the eframe UI/main thread (CA
    // load, certificate issue/renew), and the Windows default main-thread stack
    // is only ~1 MiB - so those operations blew the stack (STATUS_STACK_OVERFLOW,
    // 0xC00000FD). `cargo test` never hit it because test cases run on 2 MiB
    // worker threads. Reserve a generous 32 MiB main-thread stack on Windows.
    // (Linux/macOS main threads already default to 8 MiB, which is enough.)
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("windows") {
        if target.contains("msvc") {
            println!("cargo:rustc-link-arg-bins=/STACK:33554432");
        } else {
            println!("cargo:rustc-link-arg-bins=-Wl,--stack,33554432");
        }
    }

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("cargo:rustc-env=QW_BUILD_UNIX={secs}");

    let hash = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "nogit".to_string());
    println!("cargo:rustc-env=QW_GIT_HASH={hash}");
}
