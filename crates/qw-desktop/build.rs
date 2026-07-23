//! Stamp the build time + git hash into the binary so the running app can show
//! exactly which build it is (ending "am I on the latest exe?" confusion).
//! With no `rerun-if-changed` directives, Cargo re-runs this whenever any file
//! in the package changes, so the stamp tracks the last real rebuild.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
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
