//! Internal PQC certificate authority — shared by the gateway and the desktop.
//!
//! Issues **hybrid** certificates: a classical Ed25519 X.509 leaf (usable in TLS
//! today, signed by a persisted CA) plus an **ML-DSA-65 signature binding** over
//! the leaf's DER, produced by an FIPS-204 identity. A relying party that
//! understands the binding gets post-quantum authentication; a classical client
//! still gets a working X.509 chain. This is what lets QuantaWatch *issue* the
//! replacement for a quantum-vulnerable certificate — completing remediation
//! past "open a PR" — rather than only recommending one.
//!
//! Every operation here is local crypto: no network is involved in issuing,
//! renewing, or revoking, so an air-gapped desktop can run its own CA.
//!
//! rcgen has no ML-DSA X.509 support yet, so the PQC assurance rides alongside
//! the classical cert as a detached ML-DSA signature (a QuantaWatch composite
//! binding); a standards-track ML-DSA X.509 is a drop-in follow-up.

use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SerialNumber, PKCS_ED25519,
};

use qw_crypto::GatewayIdentity;
use qw_store::CertificateRow;

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// The internal CA: a persisted classical Ed25519 root plus an ML-DSA-65
/// identity for the post-quantum binding.
pub struct CertAuthority {
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_cert_pem: String,
    common_name: String,
    mldsa: Arc<GatewayIdentity>,
}

fn now_ts() -> (chrono::DateTime<chrono::Utc>, time::OffsetDateTime) {
    let c = chrono::Utc::now();
    let t = time::OffsetDateTime::from_unix_timestamp(c.timestamp()).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    (c, t)
}

impl CertAuthority {
    /// Load the CA from `key_dir` (ca.crt + ca_ed25519.key), or generate and
    /// persist a fresh one. The ML-DSA binding uses the supplied identity.
    pub fn load_or_create(
        common_name: &str,
        key_dir: &Path,
        mldsa: Arc<GatewayIdentity>,
    ) -> anyhow::Result<Self> {
        std::fs::create_dir_all(key_dir).ok();
        let cert_path = key_dir.join("ca.crt");
        let key_path = key_dir.join("ca_ed25519.key");

        let (ca_cert, ca_key, ca_cert_pem) = if cert_path.exists() && key_path.exists() {
            let key_pem = std::fs::read_to_string(&key_path)?;
            let ca_key = KeyPair::from_pem(&key_pem)
                .map_err(|e| anyhow::anyhow!("load CA key: {e}"))?;
            let cert_pem = std::fs::read_to_string(&cert_path)?;
            // Rebuild the issuer Certificate from the persisted PEM so new leaves
            // chain to the same CA subject + key across restarts.
            let params = CertificateParams::from_ca_cert_pem(&cert_pem)
                .map_err(|e| anyhow::anyhow!("parse CA cert: {e}"))?;
            let ca_cert = params
                .self_signed(&ca_key)
                .map_err(|e| anyhow::anyhow!("rebuild CA cert: {e}"))?;
            (ca_cert, ca_key, cert_pem)
        } else {
            let ca_key = KeyPair::generate_for(&PKCS_ED25519)
                .map_err(|e| anyhow::anyhow!("generate CA key: {e}"))?;
            let mut params = CertificateParams::new(Vec::<String>::new())
                .map_err(|e| anyhow::anyhow!("CA params: {e}"))?;
            params.distinguished_name.push(DnType::CommonName, common_name);
            params.distinguished_name.push(DnType::OrganizationName, "QuantaWatch");
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let (_, t_now) = now_ts();
            params.not_before = t_now - time::Duration::days(1);
            params.not_after = t_now + time::Duration::days(3650);
            let ca_cert = params
                .self_signed(&ca_key)
                .map_err(|e| anyhow::anyhow!("self-sign CA: {e}"))?;
            let cert_pem = ca_cert.pem();
            std::fs::write(&cert_path, &cert_pem)?;
            std::fs::write(&key_path, ca_key.serialize_pem())?;
            (ca_cert, ca_key, cert_pem)
        };

        Ok(Self {
            ca_cert,
            ca_key,
            ca_cert_pem,
            common_name: common_name.to_string(),
            mldsa,
        })
    }

    /// The CA's public trust material for relying parties.
    pub fn ca_info(&self) -> serde_json::Value {
        serde_json::json!({
            "commonName": self.common_name,
            "caCertPem": self.ca_cert_pem,
            "mldsaPublicKey": B64.encode(self.mldsa.public_key_bytes()),
            "mldsaFingerprint": self.mldsa.fingerprint,
            "hybrid": true,
        })
    }

    /// The CA's common name.
    pub fn common_name(&self) -> &str {
        &self.common_name
    }

    /// The CA's ML-DSA fingerprint (identifies the issuing PQC identity).
    pub fn fingerprint(&self) -> &str {
        &self.mldsa.fingerprint
    }

    /// The CA's classical root certificate, PEM-encoded.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Issue a certificate. Returns the durable record (no private key) plus the
    /// leaf private key PEM, which is returned to the caller exactly once.
    pub fn issue(
        &self,
        subject: &str,
        sans: &[String],
        validity_days: u32,
        hybrid: bool,
    ) -> anyhow::Result<(CertificateRow, String)> {
        let leaf_key = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|e| anyhow::anyhow!("leaf key: {e}"))?;

        let mut names: Vec<String> = sans.to_vec();
        if !names.iter().any(|n| n == subject) {
            names.insert(0, subject.to_string());
        }
        let mut params =
            CertificateParams::new(names.clone()).map_err(|e| anyhow::anyhow!("leaf params: {e}"))?;
        params.distinguished_name.push(DnType::CommonName, subject);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        let (c_now, t_now) = now_ts();
        let days = validity_days.max(1) as i64;
        params.not_before = t_now - time::Duration::minutes(5);
        params.not_after = t_now + time::Duration::days(days);
        let not_after = c_now + chrono::Duration::days(days);

        let serial_uuid = uuid::Uuid::new_v4();
        params.serial_number = Some(SerialNumber::from_slice(serial_uuid.as_bytes()));

        let leaf = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(|e| anyhow::anyhow!("sign leaf: {e}"))?;

        let cert_der = leaf.der();
        let cert_pem = leaf.pem();
        let key_pem = leaf_key.serialize_pem();

        // The post-quantum binding: ML-DSA-65 signature over the leaf DER.
        let (mldsa_signature, mldsa_public_key, key_type, pqc_status) = if hybrid {
            let sig = self
                .mldsa
                .sign(cert_der.as_ref())
                .map_err(|e| anyhow::anyhow!("ml-dsa sign: {e}"))?;
            (
                Some(B64.encode(sig)),
                Some(B64.encode(self.mldsa.public_key_bytes())),
                "hybrid".to_string(),
                "hybrid".to_string(),
            )
        } else {
            (None, None, "classical".to_string(), "classical_secure".to_string())
        };

        let row = CertificateRow {
            id: uuid::Uuid::new_v4().to_string(),
            subject: subject.to_string(),
            sans: names,
            serial: serial_uuid.simple().to_string(),
            key_type,
            not_before: c_now,
            not_after,
            cert_pem,
            mldsa_public_key,
            mldsa_signature,
            ca_fingerprint: self.mldsa.fingerprint.clone(),
            pqc_status,
            status: "active".to_string(),
            created_at: c_now,
            revoked_at: None,
        };
        Ok((row, key_pem))
    }

    /// Verify a certificate's ML-DSA binding: the CA's ML-DSA key signed this
    /// exact leaf. `cert_pem` is the leaf; the sig/pubkey come from the record.
    pub fn verify_binding(cert_pem: &str, mldsa_pub_b64: &str, mldsa_sig_b64: &str) -> bool {
        let Ok(der) = pem_to_der(cert_pem) else {
            return false;
        };
        let (Ok(pk), Ok(sig)) = (B64.decode(mldsa_pub_b64), B64.decode(mldsa_sig_b64)) else {
            return false;
        };
        qw_crypto::verify(&pk, &der, &sig).unwrap_or(false)
    }
}

/// Decode the first PEM CERTIFICATE block to DER.
fn pem_to_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    let b64: String = pem
        .lines()
        .skip_while(|l| !l.contains("BEGIN CERTIFICATE"))
        .skip(1)
        .take_while(|l| !l.contains("END CERTIFICATE"))
        .collect::<Vec<_>>()
        .join("");
    Ok(B64.decode(b64.trim())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("qw-pki-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn issues_verifiable_hybrid_cert() {
        let id = Arc::new(GatewayIdentity::generate().unwrap());
        let ca = CertAuthority::load_or_create("Test CA", &tmp_dir(), id).unwrap();

        let (row, key_pem) = ca
            .issue("svc.internal", &["svc.internal".into()], 30, true)
            .unwrap();
        assert_eq!(row.key_type, "hybrid");
        assert!(row.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("PRIVATE KEY"));
        let pk = row.mldsa_public_key.clone().unwrap();
        let sig = row.mldsa_signature.clone().unwrap();
        // The ML-DSA binding verifies for this exact cert...
        assert!(CertAuthority::verify_binding(&row.cert_pem, &pk, &sig));
        // ...and fails for a different cert's PEM (tamper).
        let (other, _) = ca.issue("evil.internal", &[], 30, true).unwrap();
        assert!(!CertAuthority::verify_binding(&other.cert_pem, &pk, &sig));
    }

    #[test]
    fn classical_cert_has_no_binding() {
        let id = Arc::new(GatewayIdentity::generate().unwrap());
        let ca = CertAuthority::load_or_create("Test CA", &tmp_dir(), id).unwrap();
        let (row, _) = ca.issue("svc", &[], 30, false).unwrap();
        assert_eq!(row.key_type, "classical");
        assert!(row.mldsa_signature.is_none());
    }

    #[test]
    fn ca_persists_and_reloads() {
        let dir = tmp_dir();
        let id = Arc::new(GatewayIdentity::generate().unwrap());
        let a = CertAuthority::load_or_create("Persist CA", &dir, id.clone()).unwrap();
        let b = CertAuthority::load_or_create("Persist CA", &dir, id).unwrap();
        // Same persisted CA cert across "restarts".
        assert_eq!(a.ca_cert_pem, b.ca_cert_pem);
    }
}
