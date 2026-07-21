//! Shared gateway startup, used by both the console binary and the Windows
//! service. Takes a shutdown future so the Service Control Manager (or Ctrl-C)
//! can stop the listeners gracefully instead of killing the process.

use std::future::Future;

use anyhow::Result;

use crate::config::GatewayConfig;
use crate::router;
use crate::state::AppState;

/// Boot the gateway and serve until `shutdown` resolves.
pub async fn run_gateway<S>(config_path: &str, shutdown: S) -> Result<()>
where
    S: Future<Output = ()> + Send + 'static,
{
    tracing::info!("QuantaWatch Gateway starting...");

    let config = GatewayConfig::load(config_path)?;
    tracing::info!(config_path = %config_path, "Configuration loaded");

    let state = AppState::new(config.clone()).await?;
    tracing::info!(
        fingerprint = %state.gateway_identity.fingerprint,
        "Gateway identity initialized"
    );

    crate::background::spawn(state.clone());

    let listen_addr = config.gateway.listen.clone();
    let admin_addr = config.gateway.admin_listen.clone();

    let proxy_app = router::build_proxy_router(state.clone());
    let admin_app = router::build_admin_router(state);

    let proxy_listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    let admin_listener = tokio::net::TcpListener::bind(&admin_addr).await?;

    tracing::info!(proxy = %listen_addr, admin = %admin_addr, "QuantaWatch Gateway listening");

    // One shutdown signal, fanned out to both listeners.
    let (tx, rx_proxy) = tokio::sync::watch::channel(false);
    let mut rx_admin = rx_proxy.clone();
    let mut rx_proxy = rx_proxy;
    tokio::spawn(async move {
        shutdown.await;
        tracing::info!("shutdown signal received; draining listeners");
        let _ = tx.send(true);
    });

    let proxy = tokio::spawn(async move {
        axum::serve(proxy_listener, proxy_app)
            .with_graceful_shutdown(async move {
                let _ = rx_proxy.wait_for(|v| *v).await;
            })
            .await
    });
    let admin = tokio::spawn(async move {
        axum::serve(admin_listener, admin_app)
            .with_graceful_shutdown(async move {
                let _ = rx_admin.wait_for(|v| *v).await;
            })
            .await
    });

    // Either listener finishing (graceful stop or error) ends the run.
    tokio::select! {
        r = proxy => { r??; }
        r = admin => { r??; }
    }

    tracing::info!("QuantaWatch Gateway stopped");
    Ok(())
}
