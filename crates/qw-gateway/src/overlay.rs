//! PQC-terminating proxy overlay.
//!
//! Fronts a legacy upstream with a TLS listener that offers the **X25519MLKEM768
//! hybrid** key exchange (via rustls' aws-lc-rs backend). A client connects to
//! QuantaWatch over a post-quantum-safe channel; QuantaWatch decrypts and
//! forwards to the upstream over its existing transport. The harvest-now-
//! decrypt-later exposure on the client leg is eliminated **without changing the
//! upstream** — the thing a passive scanner can only report on, and the pitch
//! behind QuSecure's "Resilience" overlay, here in the open.
//!
//! Per-connection the overlay records the negotiated key-exchange group, so the
//! dashboard can prove a leg is actually PQC-protected rather than merely
//! offered. `pqc-only` mode drops any handshake that didn't land on the hybrid
//! group.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::config::{OverlayConfig, OverlayRoute};

/// Live counters for one protected route.
#[derive(Debug)]
pub struct RouteStats {
    pub id: String,
    pub listen: String,
    pub upstream: String,
    pub upstream_tls: bool,
    pub mode: String,
    pub active: AtomicU64,
    pub total: AtomicU64,
    /// Connections whose client leg negotiated a hybrid/PQC group.
    pub pqc_connections: AtomicU64,
    /// Connections dropped by `pqc-only` mode (classical handshake).
    pub rejected_classical: AtomicU64,
    pub bytes: AtomicU64,
    pub errors: AtomicU64,
    pub last_group: Mutex<Option<String>>,
}

impl RouteStats {
    fn new(r: &OverlayRoute) -> Self {
        Self {
            id: r.id.clone(),
            listen: r.listen.clone(),
            upstream: r.upstream.clone(),
            upstream_tls: r.upstream_tls,
            mode: r.mode.clone(),
            active: AtomicU64::new(0),
            total: AtomicU64::new(0),
            pqc_connections: AtomicU64::new(0),
            rejected_classical: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            last_group: Mutex::new(None),
        }
    }

    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "listen": self.listen,
            "upstream": self.upstream,
            "upstreamTls": self.upstream_tls,
            "mode": self.mode,
            "active": self.active.load(Ordering::Relaxed),
            "total": self.total.load(Ordering::Relaxed),
            "pqcConnections": self.pqc_connections.load(Ordering::Relaxed),
            "rejectedClassical": self.rejected_classical.load(Ordering::Relaxed),
            "bytes": self.bytes.load(Ordering::Relaxed),
            "errors": self.errors.load(Ordering::Relaxed),
            "lastGroup": self.last_group.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            // A route is proven PQC-protected once any connection landed on hybrid.
            "pqcProtected": self.pqc_connections.load(Ordering::Relaxed) > 0,
        })
    }
}

/// Shared overlay state, exposed to the admin API. Routes are interior-mutable
/// so the dashboard can protect a discovered service at runtime (one-click),
/// not only from static config.
pub struct OverlayState {
    pub enabled: bool,
    pub cert_source: Mutex<String>,
    pub routes: Mutex<Vec<Arc<RouteStats>>>,
    /// The client-facing TLS config (hybrid-PQC). Built lazily (self-signed) the
    /// first time a route is added if the overlay wasn't configured with one.
    server_cfg: Mutex<Option<Arc<ServerConfig>>>,
    connector: Arc<TlsConnector>,
    audit: Arc<qw_audit::AuditLogger>,
}

impl OverlayState {
    pub fn disabled(audit: Arc<qw_audit::AuditLogger>) -> Self {
        Self {
            enabled: false,
            cert_source: Mutex::new("n/a".to_string()),
            routes: Mutex::new(vec![]),
            server_cfg: Mutex::new(None),
            connector: Arc::new(upstream_connector()),
            audit,
        }
    }

    pub fn snapshot(&self) -> serde_json::Value {
        let routes_guard = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        let routes: Vec<serde_json::Value> = routes_guard.iter().map(|r| r.snapshot()).collect();
        let protected = routes_guard
            .iter()
            .filter(|r| r.pqc_connections.load(Ordering::Relaxed) > 0)
            .count();
        let total = routes_guard.len();
        serde_json::json!({
            "enabled": self.enabled || total > 0,
            "certSource": self.cert_source.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            "hybridGroup": "X25519MLKEM768",
            "routes": routes,
            "total": total,
            "pqcProtectedRoutes": protected,
        })
    }

    /// Drop a route from the snapshot (e.g. its target was deleted). The bound
    /// listener task is orphaned and stops accepting usefully after the next
    /// restart, when it is simply not re-bound.
    pub fn remove_route(&self, id: &str) {
        self.routes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|r| r.id != id);
    }

    /// Ensure a client-facing server TLS config exists (lazily self-signed).
    fn ensure_server_cfg(&self) -> anyhow::Result<Arc<ServerConfig>> {
        let mut guard = self.server_cfg.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let (cfg, source) = server_config(&OverlayConfig::default())?;
        *self.cert_source.lock().unwrap_or_else(|e| e.into_inner()) = format!("{source} (runtime)");
        *guard = Some(cfg.clone());
        Ok(cfg)
    }

    /// Bind a new protected route at runtime and start forwarding. `listen` may
    /// use `:0` to let the OS pick a free port; the actual bound address is
    /// recorded on the returned stats.
    pub async fn add_route(
        &self,
        id: &str,
        listen: &str,
        upstream: &str,
        upstream_tls: bool,
        mode: &str,
    ) -> anyhow::Result<Arc<RouteStats>> {
        let server_cfg = self.ensure_server_cfg()?;
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|e| anyhow::anyhow!("overlay bind {listen}: {e}"))?;
        let actual = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| listen.to_string());
        let route = OverlayRoute {
            id: id.to_string(),
            listen: actual,
            upstream: upstream.to_string(),
            upstream_tls,
            mode: mode.to_string(),
        };
        let stats = Arc::new(RouteStats::new(&route));

        let acceptor = TlsAcceptor::from(server_cfg);
        let connector = self.connector.clone();
        let stats_task = stats.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((tcp, _peer)) => {
                        tokio::spawn(handle_conn(
                            tcp,
                            acceptor.clone(),
                            connector.clone(),
                            stats_task.clone(),
                        ));
                    }
                    Err(e) => {
                        tracing::warn!(route = %stats_task.id, error = %e, "overlay: accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });

        // Replace any prior in-memory route with the same id (e.g. re-protect).
        {
            let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
            routes.retain(|r| r.id != stats.id);
            routes.push(stats.clone());
        }
        tracing::info!(route = %route.id, listen = %route.listen, upstream = %route.upstream, "overlay: runtime route protected");
        let _ = self
            .audit
            .log(
                "system",
                qw_audit::AuditEvent::OverlayRouteProtected {
                    route_id: route.id.clone(),
                    listen: route.listen.clone(),
                    upstream: route.upstream.clone(),
                    mode: route.mode.clone(),
                },
            )
            .await;
        Ok(stats)
    }
}

/// Is a rustls key-exchange group name a PQC hybrid?
fn is_pqc_group(name: &str) -> bool {
    let n = name.to_uppercase();
    n.contains("MLKEM") || n.contains("KYBER")
}

fn load_certificate(
    cfg: &OverlayConfig,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, String)> {
    if let (Some(cf), Some(kf)) = (&cfg.cert_file, &cfg.key_file) {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cf)
            .map_err(|e| anyhow::anyhow!("overlay cert_file {cf}: {e}"))?
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow::anyhow!("overlay cert_file {cf}: {e}"))?;
        let key = PrivateKeyDer::from_pem_file(kf)
            .map_err(|e| anyhow::anyhow!("overlay key_file {kf}: {e}"))?;
        Ok((certs, key, "configured".to_string()))
    } else {
        // Self-signed cert for the client-facing leg (internal/dev overlays).
        let ck = rcgen::generate_simple_self_signed(vec!["quantawatch-overlay".to_string()])?;
        let cert = CertificateDer::from(ck.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
        Ok((vec![cert], key, "self-signed".to_string()))
    }
}

/// Build the client-facing server config on the aws-lc-rs provider, which
/// offers the X25519MLKEM768 hybrid group by default.
fn server_config(cfg: &OverlayConfig) -> anyhow::Result<(Arc<ServerConfig>, String)> {
    let (certs, key, source) = load_certificate(cfg)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok((Arc::new(config), source))
}

/// An encrypt-only client verifier for the upstream leg (upstream_tls=true):
/// protect the wire, don't validate the internal cert chain.
#[derive(Debug)]
struct EncryptOnly(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for EncryptOnly {
    fn verify_server_cert(
        &self,
        _e: &CertificateDer<'_>,
        _i: &[CertificateDer<'_>],
        _n: &ServerName<'_>,
        _o: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn upstream_connector() -> TlsConnector {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(EncryptOnly(provider)))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// Handle one client connection: PQC-terminate, then forward to the upstream.
async fn handle_conn(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    connector: Arc<TlsConnector>,
    stats: Arc<RouteStats>,
) {
    stats.total.fetch_add(1, Ordering::Relaxed);
    stats.active.fetch_add(1, Ordering::Relaxed);

    let result = async {
        let mut client = acceptor
            .accept(tcp)
            .await
            .map_err(|e| format!("client TLS handshake: {e}"))?;

        // Record the negotiated key-exchange group on the client leg.
        let group = {
            let (_, conn) = client.get_ref();
            conn.negotiated_key_exchange_group()
                .map(|g| format!("{:?}", g.name()))
        };
        let is_pqc = group.as_deref().map(is_pqc_group).unwrap_or(false);
        if let Some(g) = &group {
            *stats.last_group.lock().unwrap_or_else(|e| e.into_inner()) = Some(g.clone());
        }
        if is_pqc {
            stats.pqc_connections.fetch_add(1, Ordering::Relaxed);
        }
        // pqc-only: drop a connection that didn't negotiate a hybrid group.
        if stats.mode == "pqc-only" && !is_pqc {
            stats.rejected_classical.fetch_add(1, Ordering::Relaxed);
            return Err(format!(
                "pqc-only: rejected classical handshake ({})",
                group.as_deref().unwrap_or("unknown")
            ));
        }

        let up = TcpStream::connect(&stats.upstream)
            .await
            .map_err(|e| format!("upstream connect {}: {e}", stats.upstream))?;

        let (a, b) = if stats.upstream_tls {
            let host = stats.upstream.split(':').next().unwrap_or("upstream");
            let sni =
                ServerName::try_from(host.to_string()).map_err(|e| format!("upstream SNI: {e}"))?;
            let mut up = connector
                .connect(sni, up)
                .await
                .map_err(|e| format!("upstream TLS: {e}"))?;
            copy_bidirectional(&mut client, &mut up)
                .await
                .map_err(|e| format!("pipe: {e}"))?
        } else {
            let mut up = up;
            copy_bidirectional(&mut client, &mut up)
                .await
                .map_err(|e| format!("pipe: {e}"))?
        };
        Ok::<u64, String>(a + b)
    }
    .await;

    match result {
        Ok(bytes) => {
            stats.bytes.fetch_add(bytes, Ordering::Relaxed);
        }
        Err(e) => {
            stats.errors.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(route = %stats.id, error = %e, "overlay connection ended");
        }
    }
    stats.active.fetch_sub(1, Ordering::Relaxed);
}

/// Bind every configured route and start forwarding. Returns the shared state
/// for the admin API. Routes that fail to bind are logged and skipped.
pub async fn spawn(
    cfg: &OverlayConfig,
    audit_logger: Arc<qw_audit::AuditLogger>,
) -> anyhow::Result<Arc<OverlayState>> {
    if !cfg.enabled || cfg.routes.is_empty() {
        return Ok(Arc::new(OverlayState::disabled(audit_logger)));
    }

    let (server_cfg, cert_source) = server_config(cfg)?;
    let connector = Arc::new(upstream_connector());
    let mut route_stats = Vec::new();

    for route in &cfg.routes {
        let stats = Arc::new(RouteStats::new(route));
        let listener = match TcpListener::bind(&route.listen).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(route = %route.id, listen = %route.listen, error = %e, "overlay: bind failed");
                stats.errors.fetch_add(1, Ordering::Relaxed);
                route_stats.push(stats);
                continue;
            }
        };

        tracing::info!(
            route = %route.id, listen = %route.listen, upstream = %route.upstream,
            mode = %route.mode, "overlay: protecting route with hybrid PQC TLS"
        );
        let _ = audit_logger
            .log(
                "system",
                qw_audit::AuditEvent::OverlayRouteProtected {
                    route_id: route.id.clone(),
                    listen: route.listen.clone(),
                    upstream: route.upstream.clone(),
                    mode: route.mode.clone(),
                },
            )
            .await;

        let acceptor = TlsAcceptor::from(server_cfg.clone());
        let connector = connector.clone();
        let stats_task = stats.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((tcp, _peer)) => {
                        tokio::spawn(handle_conn(
                            tcp,
                            acceptor.clone(),
                            connector.clone(),
                            stats_task.clone(),
                        ));
                    }
                    Err(e) => {
                        tracing::warn!(route = %stats_task.id, error = %e, "overlay: accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });

        route_stats.push(stats);
    }

    Ok(Arc::new(OverlayState {
        enabled: true,
        cert_source: Mutex::new(cert_source),
        routes: Mutex::new(route_stats),
        server_cfg: Mutex::new(Some(server_cfg)),
        connector,
        audit: audit_logger,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pqc_group_detection() {
        assert!(is_pqc_group("X25519MLKEM768"));
        assert!(is_pqc_group("SecP256r1MLKEM768"));
        assert!(is_pqc_group("X25519Kyber768Draft00"));
        assert!(!is_pqc_group("X25519"));
        assert!(!is_pqc_group("secp256r1"));
    }

    #[test]
    fn self_signed_server_config_builds() {
        // Proves the aws-lc-rs server config (with the hybrid group) constructs.
        let cfg = OverlayConfig {
            enabled: true,
            ..Default::default()
        };
        let (_c, source) = server_config(&cfg).expect("server config builds");
        assert_eq!(source, "self-signed");
    }
}
