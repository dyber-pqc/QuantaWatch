//! Pluggable attestation providers.
//!
//! The CBOM attestation quote binds the inventory digest + platform
//! measurements to a signing key. *Where that key lives, and how a verifier can
//! trust it*, is the whole game:
//!
//! * [`SoftwareAttestor`] — the gateway identity self-signs the quote. Simple,
//!   but anyone who compromises the gateway can forge a quote: there is no root
//!   of trust beyond the gateway process itself.
//! * [`HardwareAttestor`] — the quote is signed by an **Attestation Key (AK)**
//!   whose legitimacy is proven by a certificate chain up to a trusted root
//!   (the post-quantum analogue of a TPM AK / EK / vendor-CA chain). A verifier
//!   checks the chain, so a forged quote requires forging the root — not just
//!   popping the gateway.
//!
//! The hardware provider here builds that chain with an in-process platform CA
//! (a faithful *model* of the flow, honestly labelled `synthetic-tpm-*`). The
//! remaining integration is to have the AK live in and be certified by real
//! silicon (TPM 2.0 quote, AWS Nitro attestation doc, SEV-SNP/TDX report) —
//! that is one more `Attestor` impl behind this same trait.

use std::sync::Arc;

use qw_cbom::{AttestationCert, Measurement};
use qw_crypto::{sha3_256_hex, GatewayIdentity, SigningKeyPair};

/// A source of attestation quotes plus the trust material a verifier needs.
pub trait Attestor: Send + Sync {
    /// Root-of-trust discriminator, e.g. `software-ml-dsa-65`.
    fn kind(&self) -> &str;
    /// Signature algorithm of the quote.
    fn algorithm(&self) -> &str {
        "ML-DSA-65"
    }
    /// Public key that verifies the quote signature.
    fn signer_public_key(&self) -> Vec<u8>;
    /// Fingerprint of the signing key.
    fn signer_fingerprint(&self) -> String;
    /// Sign the quote payload with the attestation key.
    fn sign(&self, quote: &[u8]) -> Vec<u8>;
    /// Extra platform measurements (PCRs, enclave measurements, AK fingerprint).
    fn platform_measurements(&self) -> Vec<Measurement>;
    /// Certificate chain proving the signing key's legitimacy (empty = self-attested).
    fn cert_chain(&self) -> Vec<AttestationCert>;
    /// Human-readable provenance note.
    fn note(&self) -> String;
}

/// Software provider: the gateway identity self-signs the quote.
pub struct SoftwareAttestor {
    identity: Arc<GatewayIdentity>,
}

impl SoftwareAttestor {
    pub fn new(identity: Arc<GatewayIdentity>) -> Self {
        Self { identity }
    }
}

impl Attestor for SoftwareAttestor {
    fn kind(&self) -> &str {
        "software-ml-dsa-65"
    }
    fn signer_public_key(&self) -> Vec<u8> {
        self.identity.public_key_bytes()
    }
    fn signer_fingerprint(&self) -> String {
        self.identity.fingerprint.clone()
    }
    fn sign(&self, quote: &[u8]) -> Vec<u8> {
        self.identity.sign(quote).unwrap_or_default()
    }
    fn platform_measurements(&self) -> Vec<Measurement> {
        Vec::new()
    }
    fn cert_chain(&self) -> Vec<AttestationCert> {
        Vec::new()
    }
    fn note(&self) -> String {
        "Software-emulated attestation over the live CBOM; no hardware root of trust.".into()
    }
}

/// Issue a certificate: `issuer` certifies `subject` in the given role.
fn issue_cert(role: &str, subject: &SigningKeyPair, issuer: &SigningKeyPair) -> AttestationCert {
    let subject_pk = subject.verifying_key_bytes();
    let issuer_pk = issuer.verifying_key_bytes();
    let mut cert = AttestationCert {
        role: role.into(),
        subject_fingerprint: sha3_256_hex(&subject_pk),
        subject_public_key: hex::encode(&subject_pk),
        issuer_fingerprint: sha3_256_hex(&issuer_pk),
        signature: String::new(),
    };
    cert.signature = hex::encode(issuer.sign(&cert.signed_content()).unwrap_or_default());
    cert
}

/// Hardware-rooted provider. The quote is signed by an AK certified up to a
/// self-signed platform root. This builds the chain with an in-process CA — a
/// PQC model of a real TPM/Nitro quote flow (honestly labelled).
pub struct HardwareAttestor {
    ak: SigningKeyPair,
    chain: Vec<AttestationCert>,
    pcrs: Vec<Measurement>,
}

impl HardwareAttestor {
    /// Build a synthetic hardware-rooted attestor: a fresh AK certified by an
    /// in-process platform root CA.
    pub fn synthetic() -> Self {
        let root = SigningKeyPair::generate().expect("root keygen");
        let ak = SigningKeyPair::generate().expect("ak keygen");
        let ak_cert = issue_cert("ak", &ak, &root);
        let root_cert = issue_cert("root", &root, &root); // self-signed anchor
        let pcrs = vec![
            Measurement {
                name: "pcr0-firmware".into(),
                value: sha3_256_hex(b"synthetic-firmware-measurement"),
            },
            Measurement {
                name: "pcr7-secureboot".into(),
                value: sha3_256_hex(b"synthetic-secureboot-policy"),
            },
            Measurement {
                name: "ak-fingerprint".into(),
                value: sha3_256_hex(&ak.verifying_key_bytes()),
            },
        ];
        Self {
            ak,
            chain: vec![ak_cert, root_cert],
            pcrs,
        }
    }
}

impl Attestor for HardwareAttestor {
    fn kind(&self) -> &str {
        "synthetic-tpm-ml-dsa-65"
    }
    fn signer_public_key(&self) -> Vec<u8> {
        self.ak.verifying_key_bytes()
    }
    fn signer_fingerprint(&self) -> String {
        sha3_256_hex(&self.ak.verifying_key_bytes())
    }
    fn sign(&self, quote: &[u8]) -> Vec<u8> {
        self.ak.sign(quote).unwrap_or_default()
    }
    fn platform_measurements(&self) -> Vec<Measurement> {
        self.pcrs.clone()
    }
    fn cert_chain(&self) -> Vec<AttestationCert> {
        self.chain.clone()
    }
    fn note(&self) -> String {
        "Synthetic hardware-rooted attestation: AK certified by an in-process platform CA (PQC \
         model of a TPM 2.0 / AWS Nitro quote). Replace the synthetic root with a real hardware \
         quote to close the trust chain to silicon."
            .into()
    }
}

/// Select an attestor from the configured provider name. Unknown or
/// not-yet-wired hardware backends fall back to software with a warning.
pub fn build_attestor(provider: &str, identity: Arc<GatewayIdentity>) -> Arc<dyn Attestor> {
    match provider {
        "synthetic-tpm" => Arc::new(HardwareAttestor::synthetic()),
        "tpm2" | "nitro" | "sev-snp" | "tdx" => {
            tracing::warn!(
                provider,
                "hardware attestation backend not available in this build; falling back to \
                 software. Use provider: synthetic-tpm to exercise the certificate-chain flow."
            );
            Arc::new(SoftwareAttestor::new(identity))
        }
        _ => Arc::new(SoftwareAttestor::new(identity)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_attestor_has_no_chain_and_signs_verifiably() {
        let id = Arc::new(GatewayIdentity::generate().unwrap());
        let a = SoftwareAttestor::new(id);
        assert_eq!(a.kind(), "software-ml-dsa-65");
        assert!(a.cert_chain().is_empty());
        let sig = a.sign(b"quote");
        assert!(qw_crypto::verify(&a.signer_public_key(), b"quote", &sig).unwrap());
    }

    #[test]
    fn hardware_attestor_chain_verifies_and_anchors_the_ak() {
        let a = HardwareAttestor::synthetic();
        let ak_hex = hex::encode(a.signer_public_key());
        let chain = a.cert_chain();
        assert_eq!(chain.len(), 2);
        // The published chain must verify and certify the quote-signing key.
        let root_fp = qw_cbom::verify_cert_chain(&chain, &ak_hex).expect("chain verifies");
        assert_eq!(root_fp, chain[1].subject_fingerprint);
        // And the AK actually signs quotes.
        let sig = a.sign(b"quote");
        assert!(qw_crypto::verify(&a.signer_public_key(), b"quote", &sig).unwrap());
    }

    #[test]
    fn build_attestor_falls_back_to_software_for_unwired_hardware() {
        let id = Arc::new(GatewayIdentity::generate().unwrap());
        assert_eq!(
            build_attestor("tpm2", id.clone()).kind(),
            "software-ml-dsa-65"
        );
        assert_eq!(
            build_attestor("synthetic-tpm", id).kind(),
            "synthetic-tpm-ml-dsa-65"
        );
    }
}
