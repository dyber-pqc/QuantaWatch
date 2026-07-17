//! Byte-reproducible CBOM rendering.
//!
//! A CBOM is normally a point-in-time snapshot: random `serialNumber`, random
//! per-component `bomRef`, wall-clock timestamps, and whatever order the
//! filesystem happened to hand back. That is correct for a live attestation,
//! but it makes a *committed* CBOM impossible to verify — you cannot diff it,
//! so it silently rots.
//!
//! [`make_deterministic`] rewrites a CBOM so that the same inputs always
//! produce the same bytes:
//!
//! * components and services sorted by a stable key,
//! * identifiers derived from content instead of random UUIDs,
//! * timestamps pinned to the Unix epoch (a CBOM you can diff is worth more
//!   than one that records when it was generated),
//! * evidence paths normalized to `/` and stripped of a leading `./`, so a
//!   Windows workstation and a Linux CI runner agree.
//!
//! The content-derived `serialNumber` is a useful side effect: it changes if
//! and only if the inventory changes.

use chrono::{DateTime, Utc};
use qw_crypto::sha3_256_hex;
use qw_scanner::{CryptoAssetType, ScanResult};

use crate::model::CryptoBom;

/// Collapse duplicate findings so an inventory describes each thing once.
///
/// A crypto library used by ten workspace crates is still one library; without
/// this it is counted ten times, and the posture summary then disagrees with the
/// component list in the same document. Library findings are keyed by name;
/// everything else (TLS endpoints, certificates) is keyed by name + location +
/// category so genuinely distinct assets are preserved.
pub fn dedupe_scan_results(results: &[ScanResult]) -> Vec<ScanResult> {
    use std::collections::HashSet;
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for result in results {
        let mut kept = result.clone();
        kept.findings.retain(|f| {
            let key = match f.asset.asset_type {
                CryptoAssetType::CryptoLibrary => format!("lib:{}", f.asset.name),
                _ => format!("{}:{}:{}", f.asset.name, f.asset.location.path, f.category),
            };
            seen.insert(key)
        });
        out.push(kept);
    }
    out
}

/// Pinned timestamp for reproducible output (Unix epoch).
fn epoch() -> DateTime<Utc> {
    DateTime::from_timestamp(0, 0).expect("epoch is a valid timestamp")
}

/// Normalize a filesystem path for cross-platform reproducibility:
/// backslashes to `/`, and drop a leading `./`.
fn normalize_path(p: &str) -> String {
    let s = p.replace('\\', "/");
    s.strip_prefix("./").unwrap_or(&s).to_string()
}

/// Rewrite `bom` into a byte-reproducible form. Same inventory in, same bytes
/// out — on any platform, at any time.
pub fn make_deterministic(bom: &mut CryptoBom) {
    let ts = epoch();

    // 1. Normalize evidence: stable paths, pinned timestamps.
    for c in bom.components.iter_mut() {
        c.evidence.source = normalize_path(&c.evidence.source);
        c.evidence.scan_timestamp = ts;
    }

    // 2. Stable ordering. Key on content, not discovery order.
    bom.components.sort_by(|a, b| {
        (&a.name, &a.evidence.source, &a.component_type).cmp(&(
            &b.name,
            &b.evidence.source,
            &b.component_type,
        ))
    });
    bom.services
        .sort_by(|a, b| (&a.name, &a.endpoints).cmp(&(&b.name, &b.endpoints)));

    // 3. Content-derived identifiers, replacing random UUIDs.
    for c in bom.components.iter_mut() {
        let digest = sha3_256_hex(
            format!("{}|{}|{}", c.component_type, c.name, c.evidence.source).as_bytes(),
        );
        c.bom_ref = format!("comp-{}", &digest[..16]);
    }
    for s in bom.services.iter_mut() {
        let digest = sha3_256_hex(format!("{}|{}", s.name, s.endpoints.join(",")).as_bytes());
        s.bom_ref = format!("service-{}", &digest[..16]);
    }

    bom.metadata.timestamp = ts;
    // The posture summary carries its own wall-clock stamp.
    bom.posture.calculated_at = ts;

    // 4. Content-derived serial number: changes iff the inventory changes.
    //    Computed last, over everything else, so it is a digest of the document.
    bom.serial_number = String::new();
    let canonical = serde_json::to_value(&*bom).unwrap_or_default();
    let digest = sha3_256_hex(&serde_json::to_vec(&canonical).unwrap_or_default());
    // Shape the digest as a UUID so `serialNumber` stays a valid urn:uuid.
    bom.serial_number = format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &digest[0..8],
        &digest[8..12],
        &digest[12..16],
        &digest[16..20],
        &digest[20..32]
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CbomBuilder, PostureEngine};
    use qw_scanner::{
        AssetLocation, CryptoAsset, CryptoAssetType, Finding, FindingCategory, FindingSeverity,
        PqcStatus, ScanResult, ScanStatus,
    };

    fn finding(name: &str, source: &str) -> Finding {
        Finding {
            id: uuid::Uuid::new_v4().to_string(), // deliberately random
            category: FindingCategory::ClassicalCrypto,
            severity: FindingSeverity::Medium,
            title: format!("Crypto dependency: {name}"),
            description: "d".into(),
            asset: CryptoAsset {
                id: uuid::Uuid::new_v4().to_string(),
                asset_type: CryptoAssetType::CryptoLibrary,
                name: name.into(),
                algorithm: None,
                key_length: None,
                protocol_version: None,
                location: AssetLocation {
                    source_type: "dependency_file".into(),
                    path: source.into(),
                    line: None,
                },
                discovered_by: "dependency".into(),
                discovered_at: Utc::now(), // deliberately "now"
            },
            remediation: None,
            pqc_status: PqcStatus::ClassicalSecure,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Build a CBOM from findings in the given order.
    fn build(order: &[(&str, &str)]) -> CryptoBom {
        let results = vec![ScanResult {
            scanner_id: "dependency".into(),
            target_id: "t".into(),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            findings: order.iter().map(|(n, s)| finding(n, s)).collect(),
            status: ScanStatus::Completed,
            error: None,
        }];
        let summary = PostureEngine::summarize(&results, &[]);
        let mut b = CbomBuilder::new();
        b.ingest_scan_results(&results);
        b.build_with_posture("test", summary)
    }

    #[test]
    fn same_inventory_produces_identical_bytes() {
        // Two independent builds: different UUIDs, different wall-clock times.
        let mut a = build(&[("ring", "Cargo.toml"), ("ml-dsa", "Cargo.toml")]);
        let mut b = build(&[("ring", "Cargo.toml"), ("ml-dsa", "Cargo.toml")]);
        make_deterministic(&mut a);
        make_deterministic(&mut b);
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap(),
            "same inventory must serialize to identical bytes"
        );
    }

    #[test]
    fn discovery_order_does_not_change_the_output() {
        let mut a = build(&[("ring", "Cargo.toml"), ("ml-dsa", "Cargo.toml")]);
        let mut b = build(&[("ml-dsa", "Cargo.toml"), ("ring", "Cargo.toml")]);
        make_deterministic(&mut a);
        make_deterministic(&mut b);
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap(),
            "filesystem traversal order must not affect the artifact"
        );
    }

    #[test]
    fn windows_and_unix_paths_normalize_to_the_same_artifact() {
        let mut win = build(&[("ml-dsa", ".\\crates\\qw-crypto\\Cargo.toml")]);
        let mut nix = build(&[("ml-dsa", "crates/qw-crypto/Cargo.toml")]);
        make_deterministic(&mut win);
        make_deterministic(&mut nix);
        assert_eq!(
            serde_json::to_string(&win).unwrap(),
            serde_json::to_string(&nix).unwrap(),
            "a Windows workstation and a Linux CI runner must agree"
        );
        assert_eq!(
            win.components[0].evidence.source,
            "crates/qw-crypto/Cargo.toml"
        );
    }

    #[test]
    fn changed_inventory_changes_the_serial_number() {
        let mut a = build(&[("ml-dsa", "Cargo.toml")]);
        let mut b = build(&[("ml-dsa", "Cargo.toml"), ("ring", "Cargo.toml")]);
        make_deterministic(&mut a);
        make_deterministic(&mut b);
        assert_ne!(
            a.serial_number, b.serial_number,
            "serialNumber must be content-derived so drift is visible"
        );
        assert!(a.serial_number.starts_with("urn:uuid:"));
    }

    #[test]
    fn dedupe_makes_posture_agree_with_the_component_list() {
        // The same library discovered in three manifests is one library.
        let raw = vec![ScanResult {
            scanner_id: "dependency".into(),
            target_id: "t".into(),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            findings: vec![
                finding("ml-dsa", "Cargo.toml"),
                finding("ml-dsa", "crates/a/Cargo.toml"),
                finding("ml-dsa", "crates/b/Cargo.toml"),
                finding("ring", "Cargo.toml"),
            ],
            status: ScanStatus::Completed,
            error: None,
        }];
        let deduped = dedupe_scan_results(&raw);
        let total: usize = deduped.iter().map(|r| r.findings.len()).sum();
        assert_eq!(total, 2, "ml-dsa x3 collapses to one; plus ring");

        let summary = PostureEngine::summarize(&deduped, &[]);
        let mut b = CbomBuilder::new();
        b.ingest_scan_results(&deduped);
        let bom = b.build_with_posture("test", summary);
        assert_eq!(
            bom.posture.total_assets as usize,
            bom.components.len(),
            "posture must count exactly the components the document lists"
        );
    }

    #[test]
    fn identifiers_and_timestamps_are_pinned() {
        let mut bom = build(&[("ml-dsa", "Cargo.toml")]);
        make_deterministic(&mut bom);
        assert_eq!(bom.metadata.timestamp, epoch());
        assert_eq!(bom.components[0].evidence.scan_timestamp, epoch());
        // bomRef is content-derived, not a random UUID.
        assert!(bom.components[0].bom_ref.starts_with("comp-"));
        assert_eq!(bom.components[0].bom_ref.len(), "comp-".len() + 16);
    }
}
