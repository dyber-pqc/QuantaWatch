//! Network discovery: a scoped TCP connect-scan that finds the cryptographic
//! attack surface of an **authorized** host and fingerprints it in place.
//!
//! Given a host an operator has declared, this sweeps a small set of
//! crypto-relevant ports with a plain TCP connect (no raw sockets, no SYN
//! tricks, no exploitation). For every open port it can, it hands off to the
//! right protocol scanner — SSH on 22, TLS on 443/993/8443/… — so a single
//! network target expands into real per-service PQC findings. Ports that speak
//! a protocol needing STARTTLS negotiation (Postgres, RDP) are recorded as open
//! surface for follow-up rather than force-fingerprinted.
//!
//! This scanner is off by default and only ever touches hosts in its allow-list
//! — it is emphatically not an internet-wide port scanner.

use crate::registry::{Scanner, ScannerError};
use crate::scanners::ssh::SshScanner;
use crate::scanners::starttls::StartTlsScanner;
use crate::scanners::tls::TlsScanner;
use crate::types::*;
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use tokio::net::TcpStream;

pub struct NetworkScanner {
    config: NetworkScannerConfig,
}

/// Ports we know how to fingerprint over immediate TLS (server speaks TLS the
/// moment the socket opens — no STARTTLS dance).
fn is_immediate_tls_port(port: u16) -> bool {
    matches!(port, 443 | 465 | 636 | 853 | 993 | 995 | 6443 | 8443)
}

/// Ports that speak a STARTTLS-style upgrade we can fingerprint. Returns the
/// protocol dialect for the STARTTLS scanner.
fn starttls_protocol(port: u16) -> Option<&'static str> {
    match port {
        5432 => Some("postgres"),
        25 | 587 | 2525 => Some("smtp"),
        _ => None,
    }
}

fn service_name(port: u16) -> &'static str {
    match port {
        22 => "ssh",
        25 => "smtp",
        443 => "https",
        465 => "smtps",
        587 => "smtp-submission",
        636 => "ldaps",
        853 => "dns-over-tls",
        993 => "imaps",
        995 => "pop3s",
        3389 => "rdp",
        5432 => "postgresql",
        6443 => "kubernetes-api",
        8443 => "https-alt",
        _ => "unknown",
    }
}

impl NetworkScanner {
    pub fn new(config: NetworkScannerConfig) -> Self {
        Self { config }
    }

    /// Is `port` open on `host`? A plain connect within the timeout.
    async fn is_open(host: &str, port: u16, timeout: std::time::Duration) -> bool {
        let addr = format!("{host}:{port}");
        matches!(
            tokio::time::timeout(timeout, TcpStream::connect(&addr)).await,
            Ok(Ok(_))
        )
    }
}

#[async_trait]
impl Scanner for NetworkScanner {
    fn id(&self) -> &str {
        "network"
    }
    fn display_name(&self) -> &str {
        "Network Surface Scanner"
    }

    fn categories(&self) -> Vec<FindingCategory> {
        vec![
            FindingCategory::MissingPqc,
            FindingCategory::WeakAlgorithm,
            FindingCategory::ClassicalCrypto,
        ]
    }

    fn supports(&self, target_type: &TargetType) -> bool {
        matches!(target_type, TargetType::NetworkHost)
    }

    async fn scan(&self, target: &ScanTarget) -> Result<ScanResult, ScannerError> {
        let started_at = Utc::now();
        let mut findings = Vec::new();

        // A target may pin a single port (host:port) or name a bare host (sweep
        // the configured crypto-port list).
        let (host, ports): (String, Vec<u16>) = match target.address.rsplit_once(':') {
            Some((h, p)) if p.parse::<u16>().is_ok() => {
                (h.to_string(), vec![p.parse().unwrap()])
            }
            _ => (target.address.clone(), self.config.ports.clone()),
        };

        let timeout = std::time::Duration::from_millis(self.config.connect_timeout_ms);

        // Probe all ports concurrently.
        let mut open_ports = Vec::new();
        let mut set = tokio::task::JoinSet::new();
        for &port in &ports {
            let host = host.clone();
            set.spawn(async move { (port, Self::is_open(&host, port, timeout).await) });
        }
        while let Some(res) = set.join_next().await {
            if let Ok((port, true)) = res {
                open_ports.push(port);
            }
        }
        open_ports.sort_unstable();

        if open_ports.is_empty() {
            return Ok(ScanResult {
                scanner_id: "network".to_string(),
                target_id: target.id.clone(),
                started_at,
                completed_at: Utc::now(),
                findings,
                status: ScanStatus::Completed,
                error: None,
            });
        }

        // Surface-summary finding: what crypto-relevant ports are exposed.
        let surface: Vec<String> = open_ports
            .iter()
            .map(|p| format!("{p}/{}", service_name(*p)))
            .collect();
        let mut meta = HashMap::new();
        meta.insert("open_ports".to_string(), surface.join(","));
        findings.push(Finding {
            id: uuid::Uuid::new_v4().to_string(),
            category: FindingCategory::ClassicalCrypto,
            severity: FindingSeverity::Info,
            title: format!("{} crypto-relevant port(s) open on {host}", open_ports.len()),
            description: format!("Exposed cryptographic surface: {}", surface.join(", ")),
            asset: CryptoAsset {
                id: uuid::Uuid::new_v4().to_string(),
                asset_type: CryptoAssetType::ProtocolEndpoint,
                name: format!("Network surface of {host}"),
                algorithm: None,
                key_length: None,
                protocol_version: None,
                location: AssetLocation {
                    source_type: "network_host".to_string(),
                    path: host.clone(),
                    line: None,
                },
                discovered_by: "network".to_string(),
                discovered_at: Utc::now(),
            },
            remediation: None,
            pqc_status: PqcStatus::Unknown,
            metadata: meta,
        });

        // Fingerprint each open port with the right protocol scanner.
        let ssh = SshScanner::new(SshScannerConfig {
            enabled: true,
            timeout_secs: self.config.connect_timeout_ms.div_ceil(1000).max(3),
            targets: vec![],
        });
        let tls = TlsScanner::new(TlsScannerConfig {
            enabled: true,
            timeout_secs: self.config.connect_timeout_ms.div_ceil(1000).max(3),
            targets: vec![],
        });
        let starttls = StartTlsScanner::new(StartTlsScannerConfig {
            enabled: true,
            timeout_secs: self.config.connect_timeout_ms.div_ceil(1000).max(3),
            targets: vec![],
        });

        for port in open_ports {
            let addr = format!("{host}:{port}");
            if port == 22 {
                if let Ok(r) = ssh.scan(&ScanTarget::ssh(&addr)).await {
                    findings.extend(r.findings);
                }
            } else if is_immediate_tls_port(port) {
                match tls.scan(&ScanTarget::tls(&addr)).await {
                    Ok(r) => findings.extend(r.findings),
                    Err(e) => tracing::debug!(%addr, error = %e, "TLS fingerprint failed"),
                }
            } else if let Some(proto) = starttls_protocol(port) {
                // Postgres / SMTP: upgrade via STARTTLS, then fingerprint.
                match starttls.scan(&ScanTarget::starttls(&addr, proto)).await {
                    Ok(r) => findings.extend(r.findings),
                    Err(e) => tracing::debug!(%addr, error = %e, "STARTTLS fingerprint failed"),
                }
            } else {
                // Open, but needs protocol-specific negotiation to fingerprint.
                let mut m = HashMap::new();
                m.insert("service".to_string(), service_name(port).to_string());
                findings.push(Finding {
                    id: uuid::Uuid::new_v4().to_string(),
                    category: FindingCategory::ClassicalCrypto,
                    severity: FindingSeverity::Info,
                    title: format!("{}/{} open on {host}", port, service_name(port)),
                    description: format!(
                        "Port {port} ({}) is open but needs protocol-specific negotiation \
                         (e.g. STARTTLS) to fingerprint its cryptography.",
                        service_name(port)
                    ),
                    asset: CryptoAsset {
                        id: uuid::Uuid::new_v4().to_string(),
                        asset_type: CryptoAssetType::ProtocolEndpoint,
                        name: format!("{} on {host}:{port}", service_name(port)),
                        algorithm: None,
                        key_length: None,
                        protocol_version: None,
                        location: AssetLocation {
                            source_type: "network_host".to_string(),
                            path: addr.clone(),
                            line: None,
                        },
                        discovered_by: "network".to_string(),
                        discovered_at: Utc::now(),
                    },
                    remediation: None,
                    pqc_status: PqcStatus::Unknown,
                    metadata: m,
                });
            }
        }

        Ok(ScanResult {
            scanner_id: "network".to_string(),
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
    fn tls_and_ssh_ports_classified() {
        assert!(is_immediate_tls_port(443));
        assert!(is_immediate_tls_port(8443));
        assert!(!is_immediate_tls_port(22));
        assert!(!is_immediate_tls_port(5432));
        assert_eq!(service_name(22), "ssh");
        assert_eq!(service_name(5432), "postgresql");
    }
}
