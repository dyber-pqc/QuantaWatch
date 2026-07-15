//! Algorithm identifier resolution.
//!
//! X.509 parsing yields bare OIDs (`1.2.840.10045.4.3.2`). Surfacing those in a
//! CBOM, a finding, or a migration plan is useless to the human who has to act
//! on it — and it makes downstream classification match on OID *prefixes*,
//! which is fragile. Resolve them once, at the point of discovery.
//!
//! Unknown identifiers pass through unchanged: an unrecognised OID is reported
//! honestly rather than guessed at.

/// (OID, human-readable name)
const OIDS: &[(&str, &str)] = &[
    // --- RSA / PKCS#1 (1.2.840.113549.1.1.x) ---
    ("1.2.840.113549.1.1.1", "RSA"),
    ("1.2.840.113549.1.1.4", "RSA-MD5"),
    ("1.2.840.113549.1.1.5", "RSA-SHA1"),
    ("1.2.840.113549.1.1.10", "RSASSA-PSS"),
    ("1.2.840.113549.1.1.11", "RSA-SHA256"),
    ("1.2.840.113549.1.1.12", "RSA-SHA384"),
    ("1.2.840.113549.1.1.13", "RSA-SHA512"),
    ("1.2.840.113549.1.1.14", "RSA-SHA224"),
    // --- ECDSA (1.2.840.10045.x) ---
    ("1.2.840.10045.2.1", "ECDSA"),
    ("1.2.840.10045.4.1", "ECDSA-SHA1"),
    ("1.2.840.10045.4.3.1", "ECDSA-SHA224"),
    ("1.2.840.10045.4.3.2", "ECDSA-SHA256"),
    ("1.2.840.10045.4.3.3", "ECDSA-SHA384"),
    ("1.2.840.10045.4.3.4", "ECDSA-SHA512"),
    // --- Named curves ---
    ("1.2.840.10045.3.1.7", "ECDSA P-256"),
    ("1.3.132.0.34", "ECDSA P-384"),
    ("1.3.132.0.35", "ECDSA P-521"),
    ("1.3.132.0.10", "ECDSA secp256k1"),
    // --- EdDSA / X25519 (RFC 8410) ---
    ("1.3.101.110", "X25519"),
    ("1.3.101.111", "X448"),
    ("1.3.101.112", "Ed25519"),
    ("1.3.101.113", "Ed448"),
    // --- DSA ---
    ("1.2.840.10040.4.1", "DSA"),
    ("1.2.840.10040.4.3", "DSA-SHA1"),
    // --- Post-quantum signatures (NIST CSOR, FIPS 204) ---
    ("2.16.840.1.101.3.4.3.17", "ML-DSA-44"),
    ("2.16.840.1.101.3.4.3.18", "ML-DSA-65"),
    ("2.16.840.1.101.3.4.3.19", "ML-DSA-87"),
    // --- Post-quantum KEM (NIST CSOR, FIPS 203) ---
    ("2.16.840.1.101.3.4.4.1", "ML-KEM-512"),
    ("2.16.840.1.101.3.4.4.2", "ML-KEM-768"),
    ("2.16.840.1.101.3.4.4.3", "ML-KEM-1024"),
    // --- Hashes ---
    ("1.3.14.3.2.26", "SHA-1"),
    ("1.2.840.113549.2.5", "MD5"),
    ("2.16.840.1.101.3.4.2.1", "SHA-256"),
    ("2.16.840.1.101.3.4.2.2", "SHA-384"),
    ("2.16.840.1.101.3.4.2.3", "SHA-512"),
    ("2.16.840.1.101.3.4.2.4", "SHA-224"),
    ("2.16.840.1.101.3.4.2.8", "SHA3-256"),
    ("2.16.840.1.101.3.4.2.9", "SHA3-384"),
    ("2.16.840.1.101.3.4.2.10", "SHA3-512"),
];

/// Resolve an algorithm identifier to a human-readable name.
///
/// Exact OID matches resolve to a canonical name. Anything already
/// human-readable (a cipher suite, a library name) is returned untouched, as is
/// an OID we don't recognise — reported as-is rather than guessed.
pub fn resolve(raw: &str) -> String {
    let t = raw.trim();
    if let Some((_, name)) = OIDS.iter().find(|(oid, _)| *oid == t) {
        return (*name).to_string();
    }
    // Unrecognised OID: mark it so a human reading a report knows it's an
    // unresolved identifier and not an algorithm name we invented.
    if is_oid(t) {
        return format!("unknown ({t})");
    }
    t.to_string()
}

/// True if the string looks like a dotted OID.
///
/// Requires at least 4 arcs: every real cryptographic OID has many, and the
/// extra arc keeps version-like strings ("3.0", "1.1") from being mistaken for
/// unresolved OIDs and mangled in reports.
fn is_oid(s: &str) -> bool {
    let arcs: Vec<&str> = s.split('.').collect();
    arcs.len() >= 4
        && arcs
            .iter()
            .all(|a| !a.is_empty() && a.chars().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_the_oids_our_own_scan_produced() {
        // These are the exact identifiers the onboarding scan of github.com /
        // cloudflare.com surfaced as raw OIDs.
        assert_eq!(resolve("1.2.840.10045.4.3.2"), "ECDSA-SHA256");
        assert_eq!(resolve("1.2.840.10045.4.3.3"), "ECDSA-SHA384");
    }

    #[test]
    fn resolves_rsa_and_pqc_families() {
        assert_eq!(resolve("1.2.840.113549.1.1.11"), "RSA-SHA256");
        assert_eq!(resolve("1.2.840.113549.1.1.1"), "RSA");
        assert_eq!(resolve("2.16.840.1.101.3.4.3.18"), "ML-DSA-65");
        assert_eq!(resolve("2.16.840.1.101.3.4.4.2"), "ML-KEM-768");
        assert_eq!(resolve("1.3.101.112"), "Ed25519");
    }

    #[test]
    fn resolved_names_still_classify_downstream() {
        // The migration planner matches on substrings like RSA / ECDSA / SHA1;
        // resolution must not break that contract.
        assert!(resolve("1.2.840.10045.4.3.2")
            .to_uppercase()
            .contains("ECDSA"));
        assert!(resolve("1.2.840.113549.1.1.11")
            .to_uppercase()
            .contains("RSA"));
        assert!(resolve("1.2.840.113549.1.1.5")
            .to_uppercase()
            .contains("SHA1"));
    }

    #[test]
    fn passes_through_human_readable_identifiers() {
        // Cipher suites and library names are already readable — don't touch them.
        assert_eq!(
            resolve("TLS13_AES_256_GCM_SHA384"),
            "TLS13_AES_256_GCM_SHA384"
        );
        assert_eq!(resolve("openssl"), "openssl");
        assert_eq!(resolve("ML-DSA-65"), "ML-DSA-65");
    }

    #[test]
    fn unknown_oids_are_flagged_not_guessed() {
        let out = resolve("1.2.3.4.5.6.7.8");
        assert_eq!(out, "unknown (1.2.3.4.5.6.7.8)");
        assert!(out.contains("1.2.3.4.5.6.7.8"), "the raw OID is preserved");
    }

    #[test]
    fn oid_detection_is_conservative() {
        assert!(is_oid("1.2.840.113549.1.1.11"));
        assert!(!is_oid("1.2.840.")); // trailing dot
        assert!(!is_oid(".1.2"));
        assert!(!is_oid("TLS13_AES_256_GCM_SHA384"));
        assert!(!is_oid("3.0")); // version-like, but still an OID shape
        assert!(!is_oid(""));
    }
}
