//! Reusable X.509 certificate classification.
//!
//! The certificate *scanner* reads certs from disk, but the same
//! algorithm/PQC/expiry classification is needed anywhere a cert turns up —
//! e.g. a Kubernetes TLS secret pulled over the API. This module is that shared
//! core: bytes in, a classified summary out, with algorithm OIDs resolved to
//! human-readable names.

use chrono::{DateTime, Utc};

use crate::algorithms;
use crate::types::PqcStatus;

/// A classified certificate.
#[derive(Debug, Clone)]
pub struct CertSummary {
    pub subject: String,
    pub issuer: String,
    /// Signature algorithm, OID-resolved (e.g. "ECDSA-SHA256").
    pub algorithm: String,
    pub pqc_status: PqcStatus,
    pub not_after: DateTime<Utc>,
    pub rsa_bits: Option<u32>,
}

/// Classify a certificate's PQC status from its signature algorithm + key size.
pub fn classify_signature(sig_alg_lower: &str, rsa_bits: Option<u32>) -> PqcStatus {
    if sig_alg_lower.contains("ml-dsa") || sig_alg_lower.contains("dilithium") {
        PqcStatus::PqcReady
    } else if sig_alg_lower.contains("ecdsa")
        || sig_alg_lower.contains("ed25519")
        || sig_alg_lower.contains("ed448")
    {
        PqcStatus::ClassicalSecure
    } else if sig_alg_lower.contains("rsa") {
        match rsa_bits {
            Some(bits) if bits < 2048 => PqcStatus::ClassicalWeak,
            _ => PqcStatus::ClassicalSecure,
        }
    } else if sig_alg_lower.contains("dsa") || sig_alg_lower.contains("sha1") {
        PqcStatus::ClassicalWeak
    } else {
        PqcStatus::Unknown
    }
}

/// Classify a PEM- or DER-encoded certificate. Returns `None` if it does not
/// parse as an X.509 certificate.
pub fn classify_cert(bytes: &[u8]) -> Option<CertSummary> {
    let der: Vec<u8> = if bytes.starts_with(b"-----BEGIN") {
        let (_, pem) = x509_parser::pem::parse_x509_pem(bytes).ok()?;
        pem.contents
    } else {
        bytes.to_vec()
    };

    let (_, parsed) = x509_parser::parse_x509_certificate(&der).ok()?;
    let algorithm = algorithms::resolve(&parsed.signature_algorithm.algorithm.to_string());
    let rsa_bits = match parsed.public_key().parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => Some(rsa.key_size() as u32),
        _ => None,
    };
    let pqc_status = classify_signature(&algorithm.to_lowercase(), rsa_bits);
    let na = parsed.validity().not_after.to_datetime();
    let not_after = DateTime::<Utc>::from_timestamp(na.unix_timestamp(), na.nanosecond())
        .unwrap_or_else(Utc::now);

    Some(CertSummary {
        subject: parsed.subject().to_string(),
        issuer: parsed.issuer().to_string(),
        algorithm,
        pqc_status,
        not_after,
        rsa_bits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_signature_maps_families() {
        assert_eq!(
            classify_signature("ecdsa-sha256", None),
            PqcStatus::ClassicalSecure
        );
        assert_eq!(classify_signature("ml-dsa-65", None), PqcStatus::PqcReady);
        assert_eq!(
            classify_signature("rsa-sha256", Some(4096)),
            PqcStatus::ClassicalSecure
        );
        assert_eq!(
            classify_signature("rsa-sha1", Some(1024)),
            PqcStatus::ClassicalWeak
        );
        assert_eq!(
            classify_signature("dsa-sha1", None),
            PqcStatus::ClassicalWeak
        );
        assert_eq!(classify_signature("mystery", None), PqcStatus::Unknown);
    }

    #[test]
    fn garbage_bytes_do_not_parse() {
        assert!(classify_cert(b"not a certificate").is_none());
        assert!(
            classify_cert(b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----")
                .is_none()
        );
    }
}
