//! STARTTLS fingerprinting for protocols that negotiate TLS mid-session.
//!
//! Databases and mail relays don't speak TLS the moment the socket opens —
//! they start in plaintext and upgrade on request. PostgreSQL uses its own
//! `SSLRequest` handshake; SMTP uses the `STARTTLS` verb. Both leave a huge
//! harvest-now-decrypt-later surface: replication streams, query traffic, and
//! mail-in-transit are protected by whatever TLS the server negotiates *after*
//! the upgrade, which on most deployments is classical.
//!
//! This scanner performs just the plaintext negotiation needed to upgrade the
//! socket, then reuses the TLS fingerprinter (`tls::fingerprint_stream`) to read
//! the negotiated version, cipher, and certificate crypto. It authenticates to
//! nothing and only runs against declared targets.

use crate::registry::{Scanner, ScannerError};
use crate::scanners::tls;
use crate::types::*;
use async_trait::async_trait;
use chrono::Utc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CR: u8 = 13;
const LF: u8 = 10;

/// PostgreSQL `SSLRequest`: length prefix (8) + the magic request code
/// 80877103 (0x04D2162F), both big-endian. See the Postgres frontend/backend
/// protocol, "SSL Session Encryption".
const PG_SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F];

pub struct StartTlsScanner {
    config: StartTlsScannerConfig,
}

impl StartTlsScanner {
    pub fn new(config: StartTlsScannerConfig) -> Self {
        Self { config }
    }

    /// Upgrade a PostgreSQL connection to TLS. Returns Ok once the server has
    /// agreed and the socket is ready for the TLS ClientHello.
    async fn negotiate_postgres(stream: &mut TcpStream) -> Result<(), ScannerError> {
        stream
            .write_all(&PG_SSL_REQUEST)
            .await
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;
        let mut reply = [0u8; 1];
        stream
            .read_exact(&mut reply)
            .await
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;
        match reply[0] {
            b'S' => Ok(()), // server supports TLS
            b'N' => Err(ScannerError::Other(
                "PostgreSQL server does not support TLS (SSLRequest -> 'N'); \
                 connections are plaintext"
                    .to_string(),
            )),
            other => Err(ScannerError::ParseError(format!(
                "unexpected PostgreSQL SSLRequest reply: 0x{other:02x}"
            ))),
        }
    }

    /// Upgrade an SMTP connection to TLS via the STARTTLS verb. Returns Ok once
    /// the server has replied 220 and the socket is ready for TLS.
    async fn negotiate_smtp(stream: &mut TcpStream) -> Result<(), ScannerError> {
        // Server greeting.
        let (greet_code, _) = read_smtp_reply(stream).await?;
        if greet_code != 220 {
            return Err(ScannerError::ParseError(format!(
                "unexpected SMTP greeting code {greet_code}"
            )));
        }

        // EHLO to enumerate capabilities.
        stream
            .write_all(b"EHLO quantawatch.scan\r\n")
            .await
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;
        let (ehlo_code, ehlo_body) = read_smtp_reply(stream).await?;
        if ehlo_code != 250 {
            return Err(ScannerError::ParseError(format!(
                "SMTP EHLO rejected with code {ehlo_code}"
            )));
        }
        if !ehlo_body.to_uppercase().contains("STARTTLS") {
            return Err(ScannerError::Other(
                "SMTP server does not advertise STARTTLS; mail is accepted in plaintext"
                    .to_string(),
            ));
        }

        // Request the upgrade.
        stream
            .write_all(b"STARTTLS\r\n")
            .await
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;
        let (code, _) = read_smtp_reply(stream).await?;
        if code != 220 {
            return Err(ScannerError::ParseError(format!(
                "SMTP STARTTLS refused with code {code}"
            )));
        }
        Ok(())
    }

    /// Resolve the STARTTLS protocol: explicit metadata wins, otherwise infer
    /// from the port. Returns (protocol, host, address-with-port).
    fn resolve(target: &ScanTarget) -> Result<(&'static str, String, String), ScannerError> {
        let declared = target.metadata.get("protocol").map(|s| s.to_lowercase());

        // Default port depends on protocol; if the address already has one, use it.
        let has_port = target
            .address
            .rsplit_once(':')
            .map(|(_, p)| p.parse::<u16>().is_ok())
            .unwrap_or(false);

        let proto: &'static str = match declared.as_deref() {
            Some("postgres") | Some("postgresql") => "postgres",
            Some("smtp") => "smtp",
            Some(other) => {
                return Err(ScannerError::Other(format!(
                    "unsupported STARTTLS protocol '{other}'"
                )))
            }
            None => {
                // Infer from port.
                let port = target
                    .address
                    .rsplit_once(':')
                    .and_then(|(_, p)| p.parse::<u16>().ok());
                match port {
                    Some(5432) => "postgres",
                    Some(25) | Some(587) | Some(2525) => "smtp",
                    _ => {
                        return Err(ScannerError::Other(
                            "cannot infer STARTTLS protocol; set metadata.protocol to \
                             postgres or smtp"
                                .to_string(),
                        ))
                    }
                }
            }
        };

        let default_port = if proto == "postgres" { 5432 } else { 587 };
        let address = if has_port {
            target.address.clone()
        } else {
            format!("{}:{default_port}", target.address)
        };
        let host = address
            .split(':')
            .next()
            .unwrap_or(&target.address)
            .to_string();
        Ok((proto, host, address))
    }
}

/// Read one SMTP reply (handling multi-line `250-...` continuations) and return
/// its status code plus the full body text.
async fn read_smtp_reply(stream: &mut TcpStream) -> Result<(u16, String), ScannerError> {
    let mut body = String::new();
    for _ in 0..64 {
        let line = read_line(stream).await?;
        body.push_str(&line);
        body.push('\n');
        // A reply line is "NNN<sep>text"; sep is '-' for continuation, ' ' for
        // the final line.
        if line.len() >= 4 && line.as_bytes()[3] == b' ' {
            let code = line[..3].parse::<u16>().unwrap_or(0);
            return Ok((code, body));
        }
        if line.len() == 3 {
            let code = line.parse::<u16>().unwrap_or(0);
            return Ok((code, body));
        }
    }
    Err(ScannerError::ParseError("SMTP reply too long".to_string()))
}

/// Read a single CRLF-terminated line, returning it without the line ending.
async fn read_line(stream: &mut TcpStream) -> Result<String, ScannerError> {
    let mut buf = Vec::with_capacity(128);
    loop {
        let b = stream
            .read_u8()
            .await
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;
        if b == LF {
            break;
        }
        if b != CR {
            buf.push(b);
        }
        if buf.len() > 4096 {
            return Err(ScannerError::ParseError("line too long".to_string()));
        }
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

#[async_trait]
impl Scanner for StartTlsScanner {
    fn id(&self) -> &str {
        "starttls"
    }
    fn display_name(&self) -> &str {
        "STARTTLS Scanner (Postgres/SMTP)"
    }

    fn categories(&self) -> Vec<FindingCategory> {
        vec![
            FindingCategory::DeprecatedProtocol,
            FindingCategory::MissingPqc,
            FindingCategory::ClassicalCrypto,
            FindingCategory::ExpiredCertificate,
        ]
    }

    fn supports(&self, target_type: &TargetType) -> bool {
        matches!(target_type, TargetType::StartTlsEndpoint)
    }

    async fn scan(&self, target: &ScanTarget) -> Result<ScanResult, ScannerError> {
        let started_at = Utc::now();
        let (proto, host, address) = Self::resolve(target)?;
        let timeout = Duration::from_secs(self.config.timeout_secs);

        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&address))
            .await
            .map_err(|_| ScannerError::Timeout)?
            .map_err(|e| ScannerError::ConnectionFailed(e.to_string()))?;

        // Plaintext upgrade dance.
        let negotiate = async {
            match proto {
                "postgres" => Self::negotiate_postgres(&mut stream).await,
                _ => Self::negotiate_smtp(&mut stream).await,
            }
        };
        tokio::time::timeout(timeout, negotiate)
            .await
            .map_err(|_| ScannerError::Timeout)??;

        // Socket is now ready for the TLS ClientHello — fingerprint it.
        let findings = tls::fingerprint_stream(&host, &address, stream, timeout, "starttls").await?;

        Ok(ScanResult {
            scanner_id: "starttls".to_string(),
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
    use std::collections::HashMap;

    #[test]
    fn resolves_protocol_from_metadata_and_port() {
        let mut md = HashMap::new();
        md.insert("protocol".to_string(), "postgres".to_string());
        let t = ScanTarget {
            id: "x".into(),
            target_type: TargetType::StartTlsEndpoint,
            address: "db.internal".into(),
            metadata: md,
        };
        let (proto, host, addr) = StartTlsScanner::resolve(&t).unwrap();
        assert_eq!(proto, "postgres");
        assert_eq!(host, "db.internal");
        assert_eq!(addr, "db.internal:5432");

        // Infer smtp from port 587.
        let t2 = ScanTarget::starttls("mail.internal:587", "");
        let (proto2, _, addr2) = StartTlsScanner::resolve(&t2).unwrap();
        assert_eq!(proto2, "smtp");
        assert_eq!(addr2, "mail.internal:587");

        // Infer postgres from port 5432.
        let t3 = ScanTarget::starttls("10.0.0.5:5432", "");
        let (proto3, _, _) = StartTlsScanner::resolve(&t3).unwrap();
        assert_eq!(proto3, "postgres");
    }

    #[test]
    fn resolve_rejects_ambiguous() {
        let t = ScanTarget::starttls("host:9999", "");
        assert!(StartTlsScanner::resolve(&t).is_err());
    }

    /// Mock a PostgreSQL server that accepts the SSLRequest: it must read the
    /// 8-byte request and reply 'S'. Proves the binary negotiation is correct.
    #[tokio::test]
    async fn postgres_ssl_request_accepted() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 8];
            sock.read_exact(&mut req).await.unwrap();
            assert_eq!(req, PG_SSL_REQUEST);
            sock.write_all(b"S").await.unwrap();
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        assert!(StartTlsScanner::negotiate_postgres(&mut client).await.is_ok());
    }

    /// Mock a PostgreSQL server that refuses TLS ('N') -> negotiation errors.
    #[tokio::test]
    async fn postgres_ssl_request_refused() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 8];
            sock.read_exact(&mut req).await.unwrap();
            sock.write_all(b"N").await.unwrap();
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        assert!(StartTlsScanner::negotiate_postgres(&mut client).await.is_err());
    }

    /// Mock an SMTP server with a multi-line EHLO advertising STARTTLS, then a
    /// 220 to the STARTTLS command. Proves greeting + multiline reply + verb.
    #[tokio::test]
    async fn smtp_starttls_negotiated() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"220 mail.test ESMTP ready\r\n").await.unwrap();
            // read EHLO line
            let mut b = [0u8; 1];
            let mut line = Vec::new();
            loop {
                sock.read_exact(&mut b).await.unwrap();
                if b[0] == LF { break; }
                line.push(b[0]);
            }
            sock.write_all(b"250-mail.test\r\n250-PIPELINING\r\n250 STARTTLS\r\n").await.unwrap();
            // read STARTTLS line
            let mut line2 = Vec::new();
            loop {
                sock.read_exact(&mut b).await.unwrap();
                if b[0] == LF { break; }
                line2.push(b[0]);
            }
            assert!(String::from_utf8_lossy(&line2).to_uppercase().contains("STARTTLS"));
            sock.write_all(b"220 ready to start TLS\r\n").await.unwrap();
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        assert!(StartTlsScanner::negotiate_smtp(&mut client).await.is_ok());
    }

    /// SMTP server that omits STARTTLS from EHLO -> negotiation errors.
    #[tokio::test]
    async fn smtp_without_starttls_errors() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"220 mail.test ESMTP\r\n").await.unwrap();
            let mut b = [0u8; 1];
            loop { sock.read_exact(&mut b).await.unwrap(); if b[0]==LF {break;} }
            sock.write_all(b"250-mail.test\r\n250 PIPELINING\r\n").await.unwrap();
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        assert!(StartTlsScanner::negotiate_smtp(&mut client).await.is_err());
    }
}
