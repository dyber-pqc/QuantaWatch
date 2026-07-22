//! Shared gateway startup, used by both the console binary and the Windows
//! service. Takes a shutdown future so the Service Control Manager (or Ctrl-C)
//! can stop the listeners gracefully instead of killing the process.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;

use crate::config::{GatewayConfig, TlsConfig};
use crate::router;
use crate::state::AppState;

/// Boot the gateway and serve until `shutdown` resolves.
pub async fn run_gateway<S>(config_path: &str, shutdown: S) -> Result<()>
where
    S: Future<Output = ()> + Send + 'static,
{
    tracing::info!("QuantaWatch Gateway starting...");

    // rustls needs a process-default crypto provider before any `ServerConfig`
    // is built (axum-server's TLS config, the overlay, the PG client). Install
    // aws-lc-rs so the HTTPS listeners can offer the X25519MLKEM768 hybrid
    // group; ignore the error if another component already installed one.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config = GatewayConfig::load(config_path)?;
    tracing::info!(config_path = %config_path, "Configuration loaded");

    // Fail closed: never expose a public interface with demo/shared credentials.
    config.assert_deployment_safe()?;

    let state = AppState::new(config.clone()).await?;
    tracing::info!(
        fingerprint = %state.gateway_identity.fingerprint,
        "Gateway identity initialized"
    );

    // One-time cleanup of the historical append-only duplicate findings, and
    // enforce the stable-id uniqueness that keeps re-scans from re-accumulating.
    let removed = state.store.dedupe_findings();
    if removed > 0 {
        tracing::info!(removed, "collapsed duplicate findings at startup");
    }

    crate::background::spawn(state.clone());

    let listen_addr = config.gateway.listen.clone();
    let admin_addr = config.gateway.admin_listen.clone();
    let tls = config.gateway.tls.clone();

    let proxy_app = router::build_proxy_router(state.clone());
    let admin_app = router::build_admin_router(state);

    let scheme = if tls.is_some() { "https" } else { "http" };
    if tls.is_some() {
        tracing::info!("gateway TLS: enabled (rustls / aws-lc-rs)");
    } else {
        tracing::warn!(
            "gateway TLS: disabled — serving plain HTTP. Terminate TLS at a trusted reverse \
             proxy, or set `gateway.tls` (cert_file + key_file) before public exposure."
        );
    }
    tracing::info!(proxy = %format!("{scheme}://{listen_addr}"), admin = %format!("{scheme}://{admin_addr}"), "QuantaWatch Gateway listening");

    // One shutdown signal, fanned out to both listeners.
    let (tx, rx_proxy) = tokio::sync::watch::channel(false);
    let rx_admin = rx_proxy.clone();
    tokio::spawn(async move {
        shutdown.await;
        tracing::info!("shutdown signal received; draining listeners");
        let _ = tx.send(true);
    });

    let proxy = tokio::spawn(serve_listener(proxy_app, listen_addr, tls.clone(), rx_proxy));
    let admin = tokio::spawn(serve_listener(admin_app, admin_addr, tls, rx_admin));

    // Either listener finishing (graceful stop or error) ends the run.
    tokio::select! {
        r = proxy => { r??; }
        r = admin => { r??; }
    }

    tracing::info!("QuantaWatch Gateway stopped");
    Ok(())
}

/// Serve one axum app on `addr`, over TLS when configured, draining gracefully
/// when `rx` flips to `true`.
async fn serve_listener(
    app: axum::Router,
    addr: String,
    tls: Option<TlsConfig>,
    mut rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    match tls {
        Some(tls) => {
            let rustls_cfg = axum_server::tls_rustls::RustlsConfig::from_pem_file(
                &tls.cert_file,
                &tls.key_file,
            )
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "loading gateway TLS cert '{}' / key '{}': {e}",
                    tls.cert_file,
                    tls.key_file
                )
            })?;

            let handle = axum_server::Handle::new();
            let drain = handle.clone();
            tokio::spawn(async move {
                let _ = rx.wait_for(|v| *v).await;
                drain.graceful_shutdown(Some(Duration::from_secs(10)));
            });

            let sockaddr: SocketAddr = addr
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid TLS listen address '{addr}': {e}"))?;
            axum_server::bind_rustls(sockaddr, rustls_cfg)
                .handle(handle)
                .serve(app.into_make_service())
                .await?;
        }
        None => {
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.wait_for(|v| *v).await;
                })
                .await?;
        }
    }
    Ok(())
}
