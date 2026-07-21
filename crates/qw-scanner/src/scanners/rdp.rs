//! RDP (3389) security-layer fingerprinting.
//!
//! Remote Desktop is a quiet harvest-now-decrypt-later exposure: every admin
//! session, every jump-box login. Its security depends entirely on which layer
//! the server negotiates, and a plain port scan can't see that. This speaks the
//! X.224 connection negotiation (MS-RDPBCGR 2.2.1.1) to learn the selected
//! security protocol —
//!   * **Standard RDP Security** (legacy RSA key exchange + RC4) — broken today,
//!     trivially broken by a quantum computer;
//!   * **Enhanced RDP Security (TLS)** — RDP tunnelled in TLS;
//!   * **CredSSP / NLA** — TLS plus network-level authentication;
//! and, whenever the server speaks TLS, completes a TLS handshake (reusing the
//! TLS scanner) to fingerprint the actual key exchange and certificate. A
//! classical TLS key exchange means the session is harvestable.
//!
//! It sends only the negotiation request and, at most, a TLS ClientHello; it
//! never authenticates. It runs only against hosts an operator has declared.

use crate::registry::{Scanner, ScannerError};
use crate::scanners::tls::fingerprint_stream;
use crate::types::*;
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// Negotiation protocols (MS-RDPBCGR 2.2.1.1.1 requestedProtocols / selectedProtocol).
const PROTOCOL_RDP: u32 = 0x0000_0000; // Standard RDP Security (legacy)
const PROTOCOL_SSL: u32 = 0x0000_0001; // TLS
const PROTOCOL_HYBRID: u32 = 0x0000_0002; // CredSSP (NLA)
const PROTOCOL_HYBRID_EX: u32 = 0x0000_0008; // CredSSP + Early User Auth

// RDP negotiation message types (byte 0 of the RDP_NEG_* structure).
const TYPE_RDP_NEG_RSP: u8 = 0x02;
const TYPE_RDP_NEG_FAILURE: u8 = 0x03;

// Selected failure codes (MS-RDPBCGR 2.2.1.2.2).
const SSL_NOT_ALLOWED_BY_SERVER: u32 = 0x0000_0002;

pub struct RdpScanner {
    timeout_secs: u64,
}

#[derive(Debug, Clone, Copy)]
enum NegOutcome {
    /// selectedProtocol from an RDP_NEG_RSP.
    Protocol(u32),
    /// failureCode from an RDP_NEG_FAILURE.
    Failure(u32),
    /// A plain Connection Confirm with no negotiation data: the server only
    /// speaks legacy Standard RDP Security.
    NoNegotiation,
}

impl RdpScanner {
    pub fn new(timeout_secs: u64) -> Self {
        Self { timeout_secs }
    }

    /// X.224 Connection Request wrapping an RDP Negotiation Request that
    /// advertises TLS + CredSSP (so the server reveals the strongest layer it
    /// supports). TPKT + X.224 CR + RDP_NEG_REQ.
    fn build_connection_request() -> Vec<u8> {
        let requested = PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX; // 0x0B
        // RDP_NEG_REQ: type(1)=0x01, flags(1)=0, length(2 LE)=8, requestedProtocols(4 LE).
        let mut neg = vec![0x01u8, 0x00, 0x08, 0x00];
        neg.extend_from_slice(&requested.to_le_bytes());
        // X.224 CR: LI(1), CR-CDT(0xE0), DST-REF(2)=0, SRC-REF(2)=0, class(1)=0, + neg.
        // LI counts the header bytes after the LI octet (6 fixed + neg).
        let li = 6 + neg.len();
        let mut x224 = vec![li as u8, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00];
        x224.extend_from_slice(&neg);
        // TPKT: version(0x03), reserved(0), length(2 BE) over the whole PDU.
        let total = 4 + x224.len();
        let mut pkt = vec![0x03u8, 0x00];
        pkt.extend_from_slice(&(total as u16).to_be_bytes());
        pkt.extend_from_slice(&x224);
        pkt
    }

    /// Read a TPKT-framed X.224 Connection Confirm and parse the negotiation
    /// result.
    async fn read_confirm(stream: &mut TcpStream) -> Result<NegOutcome, ScannerError> {
        let mut hdr = [0u8; 4];
        stream
            .read_exact(&mut hdr)
            .await
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;
        if hdr[0] != 0x03 {
            return Err(ScannerError::ParseError(
                "response is not TPKT-framed (not RDP?)".into(),
            ));
        }
        let total = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        if !(7..=1024).contains(&total) {
            return Err(ScannerError::ParseError(format!(
                "implausible TPKT length {total}"
            )));
        }
        let mut body = vec![0u8; total - 4];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;

        // X.224 CC: LI(1), code(1), DST-REF(2), SRC-REF(2), class(1), [RDP_NEG_*].
        if body.len() < 7 {
            return Err(ScannerError::ParseError("short X.224 Connection Confirm".into()));
        }
        let li = body[0] as usize;
        let code = body[1];
        if code & 0xF0 != 0xD0 {
            return Err(ScannerError::ParseError(format!(
                "unexpected X.224 code 0x{code:02X}"
            )));
        }
        // The negotiation structure (8 bytes) follows the 6-byte fixed CC body.
        // If LI <= 6 there is none: server only offers Standard RDP Security.
        if li <= 6 || body.len() < 7 + 8 {
            return Ok(NegOutcome::NoNegotiation);
        }
        let neg = &body[7..7 + 8];
        // RDP_NEG_*: type(1), flags(1), length(2 LE), data(4 LE).
        let value = u32::from_le_bytes([neg[4], neg[5], neg[6], neg[7]]);
        match neg[0] {
            TYPE_RDP_NEG_RSP => Ok(NegOutcome::Protocol(value)),
            TYPE_RDP_NEG_FAILURE => Ok(NegOutcome::Failure(value)),
            _ => Ok(NegOutcome::NoNegotiation),
        }
    }

    /// Turn the negotiation outcome into (headline finding, whether the server
    /// speaks TLS we should go on to fingerprint).
    fn security_finding(host: &str, address: &str, outcome: NegOutcome) -> (Finding, bool) {
        let (mode, detail, status, severity, tls) = match outcome {
            NegOutcome::Protocol(p) if p & PROTOCOL_HYBRID != 0 || p & PROTOCOL_HYBRID_EX != 0 => (
                "CredSSP / NLA (TLS)",
                "RDP negotiated CredSSP/NLA — TLS with network-level authentication. Authentication posture is good, but the TLS key exchange is classical and harvestable until PQC/hybrid is enabled.".to_string(),
                PqcStatus::ClassicalSecure,
                FindingSeverity::Medium,
                true,
            ),
            NegOutcome::Protocol(PROTOCOL_SSL) => (
                "Enhanced RDP Security (TLS, no NLA)",
                "RDP negotiated TLS without network-level authentication (NLA off). The channel is TLS-protected but its key exchange is classical (harvestable), and disabled NLA widens the pre-auth attack surface.".to_string(),
                PqcStatus::ClassicalSecure,
                FindingSeverity::Medium,
                true,
            ),
            NegOutcome::Protocol(PROTOCOL_RDP) => (
                "Standard RDP Security (legacy)",
                "RDP selected Standard RDP Security — legacy RSA key exchange with RC4. This is broken by modern standards and trivially broken by a quantum computer; every session is harvestable.".to_string(),
                PqcStatus::ClassicalWeak,
                FindingSeverity::High,
                false,
            ),
            // Any other selected protocol is TLS-based (SSL bit or an unknown
            // TLS variant) — fingerprint the TLS to get the real verdict.
            NegOutcome::Protocol(_) => (
                "Enhanced RDP Security (TLS)",
                "RDP negotiated a TLS-based security layer. The channel is TLS-protected but its key exchange is classical and harvestable until PQC/hybrid is enabled.".to_string(),
                PqcStatus::ClassicalSecure,
                FindingSeverity::Medium,
                true,
            ),
            NegOutcome::Failure(SSL_NOT_ALLOWED_BY_SERVER) => (
                "Standard RDP Security (TLS refused)",
                "The server refused TLS (SSL_NOT_ALLOWED_BY_SERVER) and falls back to Standard RDP Security — legacy RSA + RC4, harvestable and quantum-broken.".to_string(),
                PqcStatus::ClassicalWeak,
                FindingSeverity::High,
                false,
            ),
            NegOutcome::Failure(code) => (
                "TLS/NLA enforced",
                format!("RDP negotiation returned failure code 0x{code:08X}; the server appears to enforce TLS/NLA. The transport is classical TLS (harvestable) — characterize the key exchange directly."),
                PqcStatus::ClassicalSecure,
                FindingSeverity::Low,
                false,
            ),
            NegOutcome::NoNegotiation => (
                "Standard RDP Security (no negotiation)",
                "The server answered without RDP security negotiation — it only offers legacy Standard RDP Security (RSA + RC4), harvestable and quantum-broken.".to_string(),
                PqcStatus::ClassicalWeak,
                FindingSeverity::High,
                false,
            ),
        };

        let category = if matches!(status, PqcStatus::ClassicalWeak) {
            FindingCategory::WeakAlgorithm
        } else {
            FindingCategory::MissingPqc
        };
        let remediation = if tls {
            Some("Enable PQC/hybrid key exchange on the RDP TLS listener (or front it with the QuantaWatch PQC overlay). Keep NLA enabled.".to_string())
        } else {
            Some("Disable Standard RDP Security: require TLS + NLA (Group Policy: 'Require use of specific security layer' = SSL, 'Require NLA' = Enabled), then adopt hybrid PQC.".to_string())
        };

        let mut metadata = HashMap::new();
        metadata.insert("security_mode".to_string(), mode.to_string());

        let finding = Finding {
            id: uuid::Uuid::new_v4().to_string(),
            category,
            severity,
            title: format!("RDP security layer on {host}: {mode}"),
            description: detail,
            asset: CryptoAsset {
                id: uuid::Uuid::new_v4().to_string(),
                asset_type: CryptoAssetType::ProtocolEndpoint,
                name: format!("RDP ({mode}) on {host}"),
                algorithm: Some(mode.to_string()),
                key_length: None,
                protocol_version: Some("RDP".to_string()),
                location: AssetLocation {
                    source_type: "rdp_endpoint".to_string(),
                    path: address.to_string(),
                    line: None,
                },
                discovered_by: "rdp".to_string(),
                discovered_at: Utc::now(),
            },
            remediation,
            pqc_status: status,
            metadata,
        };
        (finding, tls)
    }
}

#[async_trait]
impl Scanner for RdpScanner {
    fn id(&self) -> &str {
        "rdp"
    }
    fn display_name(&self) -> &str {
        "RDP Security-Layer Scanner"
    }

    fn categories(&self) -> Vec<FindingCategory> {
        vec![
            FindingCategory::WeakAlgorithm,
            FindingCategory::MissingPqc,
            FindingCategory::ClassicalCrypto,
            FindingCategory::DeprecatedProtocol,
        ]
    }

    fn supports(&self, target_type: &TargetType) -> bool {
        matches!(target_type, TargetType::RdpEndpoint)
    }

    async fn scan(&self, target: &ScanTarget) -> Result<ScanResult, ScannerError> {
        let started_at = Utc::now();
        let address = if target.address.contains(':') {
            target.address.clone()
        } else {
            format!("{}:3389", target.address)
        };
        let host = address.split(':').next().unwrap_or(&target.address).to_string();
        let timeout = Duration::from_secs(self.timeout_secs.max(3));

        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&address))
            .await
            .map_err(|_| ScannerError::Timeout)?
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;

        stream
            .write_all(&Self::build_connection_request())
            .await
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;

        let outcome = tokio::time::timeout(timeout, Self::read_confirm(&mut stream))
            .await
            .map_err(|_| ScannerError::Timeout)??;

        let (headline, tls_available) = Self::security_finding(&host, &address, outcome);
        let mut findings = vec![headline];

        // If the server speaks TLS, complete the handshake to fingerprint the
        // actual key exchange + certificate (the RDP client would start TLS on
        // this same socket right after the negotiation).
        if tls_available {
            match fingerprint_stream(&host, &address, stream, timeout, "rdp").await {
                Ok(tls_findings) => findings.extend(tls_findings),
                Err(e) => tracing::debug!(%address, error = %e, "RDP TLS fingerprint failed"),
            }
        }

        Ok(ScanResult {
            scanner_id: "rdp".to_string(),
            target_id: target.id.clone(),
            started_at,
            completed_at: Utc::now(),
            findings,
            status: ScanStatus::Completed,
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_request_is_well_formed() {
        let pkt = RdpScanner::build_connection_request();
        // TPKT version + total length.
        assert_eq!(pkt[0], 0x03);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]) as usize, pkt.len());
        assert_eq!(pkt.len(), 19);
        // X.224 CR code.
        assert_eq!(pkt[5], 0xE0);
        // RDP_NEG_REQ type + requestedProtocols = SSL|HYBRID|HYBRID_EX.
        assert_eq!(pkt[11], 0x01);
        let requested = u32::from_le_bytes([pkt[15], pkt[16], pkt[17], pkt[18]]);
        assert_eq!(requested, PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX);
    }

    fn confirm(neg: Option<(u8, u32)>) -> Vec<u8> {
        // Build a TPKT + X.224 CC, optionally with an RDP_NEG_* structure.
        let mut x224 = vec![0x00u8, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00]; // LI filled below
        if let Some((ty, val)) = neg {
            x224.extend_from_slice(&[ty, 0x00, 0x08, 0x00]);
            x224.extend_from_slice(&val.to_le_bytes());
        }
        x224[0] = (x224.len() - 1) as u8; // LI = bytes after the LI octet
        let total = 4 + x224.len();
        let mut pkt = vec![0x03u8, 0x00];
        pkt.extend_from_slice(&(total as u16).to_be_bytes());
        pkt.extend_from_slice(&x224);
        pkt
    }

    async fn parse(bytes: Vec<u8>) -> NegOutcome {
        use tokio::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(&bytes).await.unwrap();
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        RdpScanner::read_confirm(&mut client).await.unwrap()
    }

    #[tokio::test]
    async fn parses_tls_selection() {
        let out = parse(confirm(Some((TYPE_RDP_NEG_RSP, PROTOCOL_HYBRID)))).await;
        assert!(matches!(out, NegOutcome::Protocol(p) if p == PROTOCOL_HYBRID));
        let (f, tls) = RdpScanner::security_finding("h", "h:3389", out);
        assert!(tls);
        assert!(f.title.contains("CredSSP"));
    }

    #[tokio::test]
    async fn parses_standard_security_and_failure() {
        // Plain CC (no negotiation) -> legacy Standard RDP Security -> weak.
        let out = parse(confirm(None)).await;
        assert!(matches!(out, NegOutcome::NoNegotiation));
        let (f, tls) = RdpScanner::security_finding("h", "h:3389", out);
        assert!(!tls);
        assert_eq!(f.pqc_status, PqcStatus::ClassicalWeak);
        assert_eq!(f.severity, FindingSeverity::High);

        // Explicit RDP_NEG_FAILURE: SSL not allowed -> weak.
        let out = parse(confirm(Some((TYPE_RDP_NEG_FAILURE, SSL_NOT_ALLOWED_BY_SERVER)))).await;
        assert!(matches!(out, NegOutcome::Failure(c) if c == SSL_NOT_ALLOWED_BY_SERVER));
        let (f, _) = RdpScanner::security_finding("h", "h:3389", out);
        assert_eq!(f.pqc_status, PqcStatus::ClassicalWeak);
    }
}
