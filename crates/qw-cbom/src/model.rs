use chrono::{DateTime, Utc};
use qw_scanner::PqcStatus;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Top-level CBOM document (CycloneDX 1.6 compatible)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoBom {
    pub bom_format: String,
    pub spec_version: String,
    pub serial_number: String,
    pub version: u32,
    pub metadata: BomMetadata,
    pub components: Vec<CryptoComponent>,
    pub services: Vec<CryptoService>,
    #[serde(rename = "x-quantawatch-posture")]
    pub posture: PostureSummary,
    #[serde(
        rename = "x-quantawatch-attestation",
        skip_serializing_if = "Option::is_none"
    )]
    pub attestation: Option<Attestation>,
}

/// A signed attestation quote over the CBOM, binding the inventory to the
/// gateway's PQC identity plus platform measurements. This is the software
/// stand-in for a hardware QuantaTPM quote (same interface; honestly labelled).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    /// e.g. "software-ml-dsa-65" (vs. a future "quantatpm-hardware").
    pub attestation_type: String,
    pub algorithm: String,
    pub signer_fingerprint: String,
    /// SHA3-256 of the canonical CBOM payload that was quoted.
    pub bom_digest: String,
    pub nonce: String,
    /// PCR-style platform measurements folded into the quote.
    pub measurements: Vec<Measurement>,
    /// Hex ML-DSA-65 signature over the quote payload.
    pub signature: String,
    /// Hex ML-DSA-65 verifying key, so the quote can be independently checked.
    pub public_key: String,
    pub signed_at: DateTime<Utc>,
    pub note: String,
    /// Certificate chain from the signing key up to a trust anchor. Empty for
    /// the software provider (self-attested); for a hardware-rooted provider it
    /// chains the Attestation Key (AK) → platform → root so a verifier can
    /// establish that the quote came from a genuine, certified platform.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cert_chain: Vec<AttestationCert>,
}

/// One link in an attestation key's certificate chain. Each link binds a
/// subject public key to an issuer and is signed by that issuer's key; the
/// issuer's key is the `subject` of the next link up, until a self-signed root
/// that the verifier can pin as a trust anchor. This is the post-quantum
/// analogue of a TPM AK / EK / vendor-CA chain (all signatures ML-DSA-65).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationCert {
    /// Subject role: "ak" (leaf, signs quotes) | "platform" | "root".
    pub role: String,
    /// SHA3-256 fingerprint of the subject public key.
    pub subject_fingerprint: String,
    /// Hex ML-DSA-65 subject public key.
    pub subject_public_key: String,
    /// SHA3-256 fingerprint of the issuer key (== subject for a self-signed root).
    pub issuer_fingerprint: String,
    /// Hex ML-DSA-65 signature by the issuer over this cert's signed content.
    pub signature: String,
}

impl AttestationCert {
    /// Canonical bytes an issuer signs to certify this subject.
    pub fn signed_content(&self) -> Vec<u8> {
        format!(
            "{}|{}|{}",
            self.role, self.subject_fingerprint, self.subject_public_key
        )
        .into_bytes()
    }
}

/// Verify an attestation certificate chain: the leaf must certify
/// `ak_pubkey_hex` (the quote-signing key), every link must be validly signed
/// by the link above it, and the top must be a self-signed root. Returns the
/// root fingerprint — a trust anchor the caller can pin — or an error naming the
/// first broken link. This is what turns "trust the gateway's self-signed key"
/// into "verify a chain rooted in a hardware/vendor trust anchor".
pub fn verify_cert_chain(chain: &[AttestationCert], ak_pubkey_hex: &str) -> Result<String, String> {
    if chain.is_empty() {
        return Err("empty certificate chain".into());
    }
    // The leaf must certify the key that signed the quote.
    if chain[0].subject_public_key != ak_pubkey_hex {
        return Err("leaf certificate does not certify the quote-signing key".into());
    }
    for (i, cert) in chain.iter().enumerate() {
        // Integrity: the subject fingerprint must match the subject key bytes.
        let subj_bytes = hex::decode(&cert.subject_public_key)
            .map_err(|_| format!("cert {i}: bad subject public key hex"))?;
        if qw_crypto::sha3_256_hex(&subj_bytes) != cert.subject_fingerprint {
            return Err(format!(
                "cert {i}: subject fingerprint does not match subject key"
            ));
        }
        // The issuer's verifying key is the subject of the link above, or —
        // at the top — this cert itself (a self-signed root).
        let issuer_pubkey_hex = if i + 1 < chain.len() {
            let parent = &chain[i + 1];
            if parent.subject_fingerprint != cert.issuer_fingerprint {
                return Err(format!(
                    "cert {i}: issuer fingerprint does not match the parent's subject"
                ));
            }
            &parent.subject_public_key
        } else {
            if cert.issuer_fingerprint != cert.subject_fingerprint {
                return Err("root certificate is not self-signed".into());
            }
            &cert.subject_public_key
        };
        let issuer_bytes = hex::decode(issuer_pubkey_hex)
            .map_err(|_| format!("cert {i}: bad issuer public key hex"))?;
        let sig =
            hex::decode(&cert.signature).map_err(|_| format!("cert {i}: bad signature hex"))?;
        if !qw_crypto::verify(&issuer_bytes, &cert.signed_content(), &sig).unwrap_or(false) {
            return Err(format!(
                "cert {i}: signature does not verify under the issuer key"
            ));
        }
    }
    Ok(chain[chain.len() - 1].subject_fingerprint.clone())
}

#[cfg(test)]
mod attestation_tests {
    use super::*;
    use qw_crypto::SigningKeyPair;

    /// Issue a cert: `issuer` certifies `subject` in the given role.
    fn issue(role: &str, subject: &SigningKeyPair, issuer: &SigningKeyPair) -> AttestationCert {
        let subject_pk = subject.verifying_key_bytes();
        let issuer_pk = issuer.verifying_key_bytes();
        let mut cert = AttestationCert {
            role: role.into(),
            subject_fingerprint: qw_crypto::sha3_256_hex(&subject_pk),
            subject_public_key: hex::encode(&subject_pk),
            issuer_fingerprint: qw_crypto::sha3_256_hex(&issuer_pk),
            signature: String::new(),
        };
        cert.signature = hex::encode(issuer.sign(&cert.signed_content()).unwrap());
        cert
    }

    /// A two-link chain: AK certified by a self-signed root.
    fn synthetic_chain() -> (SigningKeyPair, Vec<AttestationCert>) {
        let root = SigningKeyPair::generate().unwrap();
        let ak = SigningKeyPair::generate().unwrap();
        let ak_cert = issue("ak", &ak, &root);
        let root_cert = issue("root", &root, &root); // self-signed
        (ak, vec![ak_cert, root_cert])
    }

    #[test]
    fn valid_chain_verifies_and_returns_root_fp() {
        let (ak, chain) = synthetic_chain();
        let ak_hex = hex::encode(ak.verifying_key_bytes());
        let root_fp = verify_cert_chain(&chain, &ak_hex).expect("chain should verify");
        assert_eq!(root_fp, chain[1].subject_fingerprint);
    }

    #[test]
    fn rejects_chain_for_a_different_ak() {
        let (_ak, chain) = synthetic_chain();
        let other = SigningKeyPair::generate().unwrap();
        let other_hex = hex::encode(other.verifying_key_bytes());
        assert!(verify_cert_chain(&chain, &other_hex).is_err());
    }

    #[test]
    fn rejects_tampered_leaf_signature() {
        let (ak, mut chain) = synthetic_chain();
        let ak_hex = hex::encode(ak.verifying_key_bytes());
        // Flip a hex nibble in the leaf signature.
        let sig = &mut chain[0].signature;
        let last = sig.pop().unwrap();
        sig.push(if last == '0' { '1' } else { '0' });
        assert!(verify_cert_chain(&chain, &ak_hex).is_err());
    }

    #[test]
    fn rejects_non_self_signed_root() {
        let (ak, mut chain) = synthetic_chain();
        let ak_hex = hex::encode(ak.verifying_key_bytes());
        // Break the root's self-signed property.
        chain[1].issuer_fingerprint = "deadbeef".into();
        assert!(verify_cert_chain(&chain, &ak_hex).is_err());
    }

    #[test]
    fn rejects_empty_chain() {
        assert!(verify_cert_chain(&[], "abcd").is_err());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Measurement {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BomMetadata {
    pub timestamp: DateTime<Utc>,
    pub tools: Vec<ToolInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub vendor: String,
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// A CycloneDX component with cryptoProperties
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoComponent {
    pub bom_ref: String,
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_properties: Option<CryptoProperties>,
    pub evidence: ComponentEvidence,
    #[serde(rename = "x-quantawatch-posture-score")]
    pub posture_score: f64,
    #[serde(rename = "x-quantawatch-pqc-status")]
    pub pqc_status: PqcStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoProperties {
    pub asset_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm_properties: Option<AlgorithmProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_properties: Option<CertificateProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_properties: Option<ProtocolProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmProperties {
    pub primitive: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_set_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classical_security_level: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nist_quantum_security_level: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateProperties {
    pub subject_name: String,
    pub issuer_name: String,
    pub not_valid_before: DateTime<Utc>,
    pub not_valid_after: DateTime<Utc>,
    pub signature_algorithm: String,
    pub subject_public_key_algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_length: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolProperties {
    pub protocol_type: String,
    pub version: String,
    pub cipher_suites: Vec<CipherSuiteInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherSuiteInfo {
    pub name: String,
    pub pqc_status: PqcStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentEvidence {
    pub scanner_id: String,
    pub scan_timestamp: DateTime<Utc>,
    pub source: String,
    pub confidence: f64,
}

/// Live endpoint service entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoService {
    pub bom_ref: String,
    pub name: String,
    pub endpoints: Vec<String>,
    pub authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
    pub pqc_status: PqcStatus,
    pub posture_score: f64,
}

/// Posture summary (QuantaWatch extension)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostureSummary {
    pub overall_score: f64,
    pub total_assets: u32,
    /// BTreeMap, not HashMap: Rust randomizes HashMap iteration per process, so
    /// a HashMap here made the serialized CBOM differ on every run.
    pub by_status: BTreeMap<String, u32>,
    pub by_category: Vec<CategoryScore>,
    pub by_provider: Vec<ProviderScore>,
    pub calculated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryScore {
    pub category: String,
    pub score: f64,
    pub asset_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderScore {
    pub provider: String,
    pub score: f64,
    pub tls_version: Option<String>,
    pub pqc_status: PqcStatus,
}

/// Provider crypto info captured from live traffic
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCryptoInfo {
    pub provider_name: String,
    pub endpoint: String,
    pub tls_version: String,
    pub cipher_suite: String,
    pub pqc_status: PqcStatus,
    pub last_seen: DateTime<Utc>,
}
