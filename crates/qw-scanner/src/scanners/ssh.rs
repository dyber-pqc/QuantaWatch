//! SSH key-exchange fingerprinting for post-quantum readiness.
//!
//! SSH is one of the biggest harvest-now-decrypt-later blind spots in an
//! estate: every interactive session, every `git push`, every SCP transfer is
//! protected by a key exchange that — on the overwhelming majority of servers —
//! is classical (curve25519 / ECDH / finite-field DH). Recorded today, that
//! traffic is decryptable the day a cryptographically-relevant quantum computer
//! exists.
//!
//! This scanner speaks just enough of the transport protocol (RFC 4253) to read
//! the server's `SSH_MSG_KEXINIT`: it completes the version-string exchange,
//! reads the first binary packet, and parses the advertised algorithm
//! name-lists (key exchange, host key, cipher, MAC). It never authenticates,
//! never completes a handshake, and never sends anything beyond its own version
//! string — it is a read-only fingerprint of what the server is willing to
//! negotiate. It only runs against hosts an operator has explicitly declared.

use crate::registry::{Scanner, ScannerError};
use crate::types::*;
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SSH_MSG_KEXINIT: u8 = 20;
const CR: u8 = 13;
const LF: u8 = 10;
/// Our version string. The comment field identifies the probe so it is obvious
/// in a server's auth log that this was QuantaWatch, not an intruder.
const CLIENT_IDENT: &[u8] = b"SSH-2.0-QuantaWatch_scan";
/// Guard against a hostile or broken peer announcing a huge packet.
const MAX_PACKET: usize = 128 * 1024;

pub struct SshScanner {
    config: SshScannerConfig,
}

/// The four algorithm families we classify, plus the parsed name-lists.
struct KexInit {
    kex: Vec<String>,
    host_key: Vec<String>,
    ciphers: Vec<String>,
    macs: Vec<String>,
}

impl SshScanner {
    pub fn new(config: SshScannerConfig) -> Self {
        Self { config }
    }

    /// Classify a single key-exchange algorithm name.
    fn classify_kex(name: &str) -> PqcStatus {
        let n = name.to_lowercase();
        // Hybrids pair a classical curve with a PQC KEM — the only PQC that ships
        // in real SSH servers today (OpenSSH 9.x defaults to sntrup761x25519).
        if n.contains("sntrup761x25519")
            || n.contains("mlkem768x25519")
            || n.contains("mlkem768nistp256")
            || n.contains("mlkem1024nistp384")
            || n.contains("curve25519-frodokem")
            || n.contains("ecdh-nistp256-kyber")
            || n.contains("x25519-kyber")
            || n.contains("kyber-512-x25519")
        {
            PqcStatus::Hybrid
        } else if n.contains("mlkem") || n.contains("sntrup") || n.contains("kyber") {
            PqcStatus::PqcReady
        } else if n.contains("sha1") || n.contains("group1-") || n.contains("group-exchange-sha1") {
            // SHA-1 KEX (group1, gex-sha1) is broken independently of quantum.
            PqcStatus::ClassicalWeak
        } else if n.contains("curve25519")
            || n.contains("ecdh-sha2")
            || n.contains("group14-sha256")
            || n.contains("group16")
            || n.contains("group18")
            || n.contains("group-exchange-sha256")
        {
            PqcStatus::ClassicalSecure
        } else if n.contains("group14-sha1") {
            PqcStatus::ClassicalWeak
        } else {
            PqcStatus::Unknown
        }
    }

    fn classify_host_key(name: &str) -> PqcStatus {
        let n = name.to_lowercase();
        if n.contains("ml-dsa") || n.contains("dilithium") || n.contains("sphincs") {
            PqcStatus::PqcReady
        } else if n.contains("ssh-rsa") || n.contains("ssh-dss") {
            // "ssh-rsa" is the SHA-1 RSA signature; ssh-dss is 1024-bit DSA.
            PqcStatus::ClassicalWeak
        } else if n.contains("ed25519")
            || n.contains("ed448")
            || n.contains("ecdsa-sha2")
            || n.contains("rsa-sha2-256")
            || n.contains("rsa-sha2-512")
        {
            PqcStatus::ClassicalSecure
        } else {
            PqcStatus::Unknown
        }
    }

    fn classify_cipher(name: &str) -> PqcStatus {
        let n = name.to_lowercase();
        if n.contains("chacha20-poly1305")
            || n.contains("aes256-gcm")
            || n.contains("aes128-gcm")
            || n.contains("aes256-ctr")
            || n.contains("aes192-ctr")
            || n.contains("aes128-ctr")
        {
            PqcStatus::ClassicalSecure
        } else if n.contains("3des")
            || n.contains("arcfour")
            || n.contains("blowfish")
            || n.contains("cast128")
            || n.ends_with("-cbc")
            || n.contains("des-")
            || n.contains("none")
        {
            PqcStatus::ClassicalWeak
        } else {
            PqcStatus::Unknown
        }
    }

    fn classify_mac(name: &str) -> PqcStatus {
        let n = name.to_lowercase();
        if n.contains("md5") || n.contains("sha1") || n.contains("ripemd160") || n.contains("-96") {
            PqcStatus::ClassicalWeak
        } else if n.contains("hmac-sha2-256")
            || n.contains("hmac-sha2-512")
            || n.contains("umac-128")
            || n.contains("umac-64")
        {
            PqcStatus::ClassicalSecure
        } else {
            PqcStatus::Unknown
        }
    }

    /// Read the server version-identification string, skipping any pre-banner
    /// lines (which, per RFC 4253 §4.2, may precede the `SSH-` line).
    async fn read_ident(stream: &mut TcpStream) -> Result<String, ScannerError> {
        for _ in 0..64 {
            let mut line = Vec::with_capacity(128);
            loop {
                let b = stream
                    .read_u8()
                    .await
                    .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;
                if b == LF {
                    break;
                }
                if b != CR {
                    line.push(b);
                }
                if line.len() > 255 {
                    return Err(ScannerError::ParseError("ident line too long".into()));
                }
            }
            let text = String::from_utf8_lossy(&line).to_string();
            if text.starts_with("SSH-") {
                return Ok(text);
            }
            // else: a banner line before the ident — keep reading.
        }
        Err(ScannerError::ParseError(
            "no SSH identification string".into(),
        ))
    }

    /// Read and parse the server's `SSH_MSG_KEXINIT` (the first binary packet,
    /// sent unencrypted before keys are established).
    async fn read_kexinit(stream: &mut TcpStream) -> Result<KexInit, ScannerError> {
        let mut lenbuf = [0u8; 4];
        stream
            .read_exact(&mut lenbuf)
            .await
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;
        let packet_length = u32::from_be_bytes(lenbuf) as usize;
        if !(2..=MAX_PACKET).contains(&packet_length) {
            return Err(ScannerError::ParseError(format!(
                "implausible packet length {packet_length}"
            )));
        }

        let mut packet = vec![0u8; packet_length];
        stream
            .read_exact(&mut packet)
            .await
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;

        let padding_length = packet[0] as usize;
        if padding_length + 1 > packet_length {
            return Err(ScannerError::ParseError("bad padding length".into()));
        }
        let payload = &packet[1..packet_length - padding_length];
        if payload.is_empty() || payload[0] != SSH_MSG_KEXINIT {
            return Err(ScannerError::ParseError(
                "first packet was not KEXINIT".into(),
            ));
        }

        // payload: msg(1) + cookie(16) + 10 name-lists + bool + reserved(4).
        let mut pos = 1 + 16;
        let kex = read_name_list(payload, &mut pos)?;
        let host_key = read_name_list(payload, &mut pos)?;
        let ciphers = read_name_list(payload, &mut pos)?; // enc c2s
        let _enc_s2c = read_name_list(payload, &mut pos)?;
        let macs = read_name_list(payload, &mut pos)?; // mac c2s

        Ok(KexInit {
            kex,
            host_key,
            ciphers,
            macs,
        })
    }

    /// Turn a parsed KEXINIT into findings. The headline finding is always the
    /// key exchange — that is the HNDL-critical decision.
    fn evaluate(target: &ScanTarget, host: &str, server_ident: &str, k: &KexInit) -> Vec<Finding> {
        let mut findings = Vec::new();

        // --- Key exchange (the HNDL-critical family) ---
        let offers_pqc = k.kex.iter().any(|a| {
            matches!(
                Self::classify_kex(a),
                PqcStatus::Hybrid | PqcStatus::PqcReady
            )
        });
        let preferred = k.kex.first().cloned().unwrap_or_default();
        let preferred_status = Self::classify_kex(&preferred);

        let (kex_status, kex_severity, kex_category, kex_desc) = if offers_pqc {
            if matches!(preferred_status, PqcStatus::Hybrid | PqcStatus::PqcReady) {
                (
                    PqcStatus::Hybrid,
                    FindingSeverity::Info,
                    FindingCategory::PqcReady,
                    format!("SSH server prefers a post-quantum key exchange ({preferred})"),
                )
            } else {
                (
                    PqcStatus::Hybrid,
                    FindingSeverity::Low,
                    FindingCategory::MissingPqc,
                    format!(
                        "SSH server supports a post-quantum key exchange but prefers classical \
                         {preferred}; a legacy client will still negotiate a harvestable session"
                    ),
                )
            }
        } else {
            (
                PqcStatus::ClassicalSecure,
                FindingSeverity::High,
                FindingCategory::MissingPqc,
                format!(
                    "SSH server offers no post-quantum key exchange (preferred: {preferred}). \
                     Every session is exposed to harvest-now-decrypt-later."
                ),
            )
        };

        findings.push(make_finding(
            target,
            host,
            server_ident,
            kex_category,
            kex_severity,
            format!("SSH key exchange on {host}"),
            kex_desc,
            "key_exchange",
            &preferred,
            k.kex.join(","),
            kex_status,
            if offers_pqc {
                None
            } else {
                Some(
                    "Enable a hybrid PQC key exchange (e.g. sntrup761x25519-sha512 on OpenSSH 9+ \
                     or mlkem768x25519-sha256) and make it the preferred algorithm."
                        .to_string(),
                )
            },
        ));

        // --- Weak algorithms in the other families ---
        for (family, list) in [
            ("host_key", &k.host_key),
            ("cipher", &k.ciphers),
            ("mac", &k.macs),
        ] {
            let weak: Vec<String> = list
                .iter()
                .filter(|a| {
                    let s = match family {
                        "host_key" => Self::classify_host_key(a),
                        "cipher" => Self::classify_cipher(a),
                        _ => Self::classify_mac(a),
                    };
                    matches!(s, PqcStatus::ClassicalWeak)
                })
                .cloned()
                .collect();
            if !weak.is_empty() {
                findings.push(make_finding(
                    target,
                    host,
                    server_ident,
                    FindingCategory::WeakAlgorithm,
                    FindingSeverity::Medium,
                    format!("Weak SSH {family} algorithms on {host}"),
                    format!(
                        "SSH server still offers deprecated {family} algorithm(s): {}",
                        weak.join(", ")
                    ),
                    family,
                    &weak.join(","),
                    list.join(","),
                    PqcStatus::ClassicalWeak,
                    Some(format!(
                        "Remove the legacy {family} algorithm(s) from the server configuration."
                    )),
                ));
            }
        }

        findings
    }
}

#[allow(clippy::too_many_arguments)]
fn make_finding(
    target: &ScanTarget,
    host: &str,
    server_ident: &str,
    category: FindingCategory,
    severity: FindingSeverity,
    title: String,
    description: String,
    family: &str,
    algorithm: &str,
    offered: String,
    pqc_status: PqcStatus,
    remediation: Option<String>,
) -> Finding {
    let mut metadata = HashMap::new();
    metadata.insert("family".to_string(), family.to_string());
    metadata.insert("offered".to_string(), offered);
    metadata.insert("server_ident".to_string(), server_ident.to_string());
    Finding {
        id: uuid::Uuid::new_v4().to_string(),
        category,
        severity,
        title,
        description,
        asset: CryptoAsset {
            id: uuid::Uuid::new_v4().to_string(),
            asset_type: CryptoAssetType::ProtocolEndpoint,
            name: format!("SSH {family} on {host}"),
            algorithm: Some(algorithm.to_string()),
            key_length: None,
            protocol_version: Some("SSH-2.0".to_string()),
            location: AssetLocation {
                source_type: "ssh_endpoint".to_string(),
                path: target.address.clone(),
                line: None,
            },
            discovered_by: "ssh".to_string(),
            discovered_at: Utc::now(),
        },
        remediation,
        pqc_status,
        metadata,
    }
}

fn read_u32(buf: &[u8], pos: &mut usize) -> Result<u32, ScannerError> {
    if *pos + 4 > buf.len() {
        return Err(ScannerError::ParseError(
            "truncated name-list length".into(),
        ));
    }
    let v = u32::from_be_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]);
    *pos += 4;
    Ok(v)
}

fn read_name_list(buf: &[u8], pos: &mut usize) -> Result<Vec<String>, ScannerError> {
    let len = read_u32(buf, pos)? as usize;
    if *pos + len > buf.len() {
        return Err(ScannerError::ParseError("truncated name-list".into()));
    }
    let s = std::str::from_utf8(&buf[*pos..*pos + len])
        .map_err(|_| ScannerError::ParseError("non-utf8 name-list".into()))?;
    *pos += len;
    Ok(s.split(',')
        .filter(|x| !x.is_empty())
        .map(|x| x.to_string())
        .collect())
}

#[async_trait]
impl Scanner for SshScanner {
    fn id(&self) -> &str {
        "ssh"
    }
    fn display_name(&self) -> &str {
        "SSH Key-Exchange Scanner"
    }

    fn categories(&self) -> Vec<FindingCategory> {
        vec![
            FindingCategory::MissingPqc,
            FindingCategory::PqcReady,
            FindingCategory::WeakAlgorithm,
        ]
    }

    fn supports(&self, target_type: &TargetType) -> bool {
        matches!(target_type, TargetType::SshEndpoint)
    }

    async fn scan(&self, target: &ScanTarget) -> Result<ScanResult, ScannerError> {
        let started_at = Utc::now();

        let address = if target.address.contains(':') {
            target.address.clone()
        } else {
            format!("{}:22", target.address)
        };
        let host = address
            .split(':')
            .next()
            .unwrap_or(&target.address)
            .to_string();

        let timeout = std::time::Duration::from_secs(self.config.timeout_secs);

        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&address))
            .await
            .map_err(|_| ScannerError::Timeout)?
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;

        let server_ident = tokio::time::timeout(timeout, Self::read_ident(&mut stream))
            .await
            .map_err(|_| ScannerError::Timeout)??;

        // Send our identification so the server proceeds with the exchange.
        stream
            .write_all(CLIENT_IDENT)
            .await
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;
        stream
            .write_all(&[CR, LF])
            .await
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;

        let kexinit = tokio::time::timeout(timeout, Self::read_kexinit(&mut stream))
            .await
            .map_err(|_| ScannerError::Timeout)??;

        let findings = Self::evaluate(target, &host, &server_ident, &kexinit);

        Ok(ScanResult {
            scanner_id: "ssh".to_string(),
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
    fn classifies_pqc_hybrid_kex() {
        assert_eq!(
            SshScanner::classify_kex("sntrup761x25519-sha512@openssh.com"),
            PqcStatus::Hybrid
        );
        assert_eq!(
            SshScanner::classify_kex("mlkem768x25519-sha256"),
            PqcStatus::Hybrid
        );
    }

    #[test]
    fn classifies_classical_kex() {
        assert_eq!(
            SshScanner::classify_kex("curve25519-sha256"),
            PqcStatus::ClassicalSecure
        );
        assert_eq!(
            SshScanner::classify_kex("ecdh-sha2-nistp256"),
            PqcStatus::ClassicalSecure
        );
    }

    #[test]
    fn classifies_weak_kex() {
        assert_eq!(
            SshScanner::classify_kex("diffie-hellman-group1-sha1"),
            PqcStatus::ClassicalWeak
        );
        assert_eq!(
            SshScanner::classify_kex("diffie-hellman-group14-sha1"),
            PqcStatus::ClassicalWeak
        );
    }

    #[test]
    fn classifies_host_keys() {
        assert_eq!(
            SshScanner::classify_host_key("ssh-ed25519"),
            PqcStatus::ClassicalSecure
        );
        assert_eq!(
            SshScanner::classify_host_key("ssh-rsa"),
            PqcStatus::ClassicalWeak
        );
        assert_eq!(
            SshScanner::classify_host_key("ssh-dss"),
            PqcStatus::ClassicalWeak
        );
    }

    #[test]
    fn classifies_ciphers_and_macs() {
        assert_eq!(
            SshScanner::classify_cipher("chacha20-poly1305@openssh.com"),
            PqcStatus::ClassicalSecure
        );
        assert_eq!(
            SshScanner::classify_cipher("3des-cbc"),
            PqcStatus::ClassicalWeak
        );
        assert_eq!(
            SshScanner::classify_mac("hmac-sha2-256"),
            PqcStatus::ClassicalSecure
        );
        assert_eq!(
            SshScanner::classify_mac("hmac-md5"),
            PqcStatus::ClassicalWeak
        );
    }

    #[test]
    fn parses_name_list() {
        // uint32 length (7) + "a,b,cd"
        let buf = [0u8, 0, 0, 6, b'a', b',', b'b', b',', b'c', b'd'];
        let mut pos = 0;
        let list = read_name_list(&buf, &mut pos).unwrap();
        assert_eq!(list, vec!["a", "b", "cd"]);
        assert_eq!(pos, 10);
    }

    #[test]
    fn evaluate_flags_missing_pqc() {
        let target = ScanTarget::ssh("legacy.example.com:22");
        let k = KexInit {
            kex: vec!["curve25519-sha256".into(), "ecdh-sha2-nistp256".into()],
            host_key: vec!["ssh-ed25519".into()],
            ciphers: vec!["aes256-gcm@openssh.com".into()],
            macs: vec!["hmac-sha2-256".into()],
        };
        let findings =
            SshScanner::evaluate(&target, "legacy.example.com", "SSH-2.0-OpenSSH_8.9", &k);
        let kex = &findings[0];
        assert!(matches!(kex.category, FindingCategory::MissingPqc));
        assert_eq!(kex.severity, FindingSeverity::High);
    }

    fn encode_name_list(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        let mut v = (b.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(b);
        v
    }

    /// Build a wire-format SSH_MSG_KEXINIT packet (RFC 4253 §7.1).
    fn build_kexinit(kex: &str, host_key: &str, enc: &str, mac: &str) -> Vec<u8> {
        let mut payload = vec![SSH_MSG_KEXINIT];
        payload.extend_from_slice(&[0u8; 16]); // cookie
        payload.extend(encode_name_list(kex));
        payload.extend(encode_name_list(host_key));
        payload.extend(encode_name_list(enc)); // enc c2s
        payload.extend(encode_name_list(enc)); // enc s2c
        payload.extend(encode_name_list(mac)); // mac c2s
        payload.extend(encode_name_list(mac)); // mac s2c
        payload.extend(encode_name_list("none")); // comp c2s
        payload.extend(encode_name_list("none")); // comp s2c
        payload.extend(encode_name_list("")); // lang c2s
        payload.extend(encode_name_list("")); // lang s2c
        payload.push(0); // first_kex_packet_follows
        payload.extend_from_slice(&[0u8; 4]); // reserved
        let padding_len: u8 = 8;
        let packet_length = (1 + payload.len() + padding_len as usize) as u32;
        let mut pkt = packet_length.to_be_bytes().to_vec();
        pkt.push(padding_len);
        pkt.extend(payload);
        pkt.extend(vec![0u8; padding_len as usize]);
        pkt
    }

    /// Full wire round-trip: a mock SSH server sends an identification line and
    /// a real KEXINIT packet; the scanner must read the protocol off the socket
    /// and produce the right findings. This exercises `read_ident` +
    /// `read_kexinit` (the binary framing) without any external network.
    #[tokio::test]
    async fn live_wire_roundtrip_against_mock_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Mock server: no PQC KEX, a legacy ssh-rsa host key.
        let kexinit = build_kexinit(
            "curve25519-sha256,ecdh-sha2-nistp256",
            "ssh-ed25519,ssh-rsa",
            "chacha20-poly1305@openssh.com,3des-cbc",
            "hmac-sha2-256,hmac-md5",
        );
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"SSH-2.0-OpenSSH_8.9p1\r\n").await.unwrap();
            // Consume the client's identification line.
            let mut byte = [0u8; 1];
            loop {
                sock.read_exact(&mut byte).await.unwrap();
                if byte[0] == LF {
                    break;
                }
            }
            sock.write_all(&kexinit).await.unwrap();
        });

        let scanner = SshScanner::new(SshScannerConfig {
            enabled: true,
            timeout_secs: 5,
            targets: vec![],
        });
        let result = scanner
            .scan(&ScanTarget::ssh(&addr.to_string()))
            .await
            .expect("scan should complete");

        assert!(matches!(result.status, ScanStatus::Completed));
        // Headline KEX finding: no PQC offered -> High / MissingPqc.
        let kex = &result.findings[0];
        assert!(matches!(kex.category, FindingCategory::MissingPqc));
        assert_eq!(kex.severity, FindingSeverity::High);
        // Weak findings for ssh-rsa host key, 3des-cbc cipher, hmac-md5 MAC.
        let weak = result
            .findings
            .iter()
            .filter(|f| matches!(f.category, FindingCategory::WeakAlgorithm))
            .count();
        assert_eq!(weak, 3, "expected weak host_key + cipher + mac findings");
        // The server ident is captured in metadata.
        assert!(kex
            .metadata
            .get("server_ident")
            .unwrap()
            .contains("OpenSSH_8.9"));
    }

    #[test]
    fn evaluate_flags_weak_and_pqc_pref() {
        let target = ScanTarget::ssh("modern.example.com:22");
        let k = KexInit {
            kex: vec![
                "sntrup761x25519-sha512@openssh.com".into(),
                "curve25519-sha256".into(),
            ],
            host_key: vec!["ssh-ed25519".into(), "ssh-rsa".into()],
            ciphers: vec!["chacha20-poly1305@openssh.com".into()],
            macs: vec!["hmac-sha2-256".into()],
        };
        let findings =
            SshScanner::evaluate(&target, "modern.example.com", "SSH-2.0-OpenSSH_9.6", &k);
        assert!(matches!(findings[0].category, FindingCategory::PqcReady));
        // ssh-rsa host key should raise a weak-algorithm finding.
        assert!(findings
            .iter()
            .any(|f| matches!(f.category, FindingCategory::WeakAlgorithm)));
    }
}
