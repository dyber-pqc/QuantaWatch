use tracing_subscriber::EnvFilter;
use anyhow::Result;

use qw_gateway::config::GatewayConfig;
use qw_gateway::state::AppState;
use qw_gateway::router;

fn main() -> Result<()> {
    // ML-DSA-65 key generation uses large stack-allocated arrays. The async runtime's
    // entry future runs on the main OS thread, which has a small (~1MB) stack on Windows.
    // Run everything on a dedicated thread with a generous stack to avoid overflow.
    let worker = std::thread::Builder::new()
        .name("quantawatch-main".to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(16 * 1024 * 1024)
                .build()?;
            runtime.block_on(run())
        })?;

    worker.join().expect("main worker thread panicked")
}

async fn run() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,qw_gateway=debug"))
        )
        .json()
        .init();

    tracing::info!("QuantaWatch Gateway starting...");

    // Load configuration
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "quantawatch.yaml".to_string());

    let config = GatewayConfig::load(&config_path)?;
    tracing::info!(config_path = %config_path, "Configuration loaded");

    // Build application state
    let state = AppState::new(config.clone()).await?;
    tracing::info!(
        fingerprint = %state.gateway_identity.fingerprint,
        "Gateway identity initialized"
    );

    // Spawn background tasks (startup scan, scheduled scans, posture snapshots)
    qw_gateway::background::spawn(state.clone());

    // Bind the proxy (provider-facing) and admin (dashboard-facing) listeners.
    let listen_addr = config.gateway.listen.clone();
    let admin_addr = config.gateway.admin_listen.clone();

    let proxy_app = router::build_proxy_router(state.clone());
    let admin_app = router::build_admin_router(state);

    let proxy_listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    let admin_listener = tokio::net::TcpListener::bind(&admin_addr).await?;

    tracing::info!(proxy = %listen_addr, admin = %admin_addr, "QuantaWatch Gateway listening");

    println!("\n  QuantaWatch Gateway v{}", env!("CARGO_PKG_VERSION"));
    println!("  Proxy:     http://{}", listen_addr);
    println!("  Dashboard: http://{}", admin_addr);
    println!();

    // Serve both concurrently; exit if either stops.
    let proxy = tokio::spawn(async move { axum::serve(proxy_listener, proxy_app).await });
    let admin = tokio::spawn(async move { axum::serve(admin_listener, admin_app).await });

    tokio::select! {
        r = proxy => { r??; }
        r = admin => { r??; }
    }

    Ok(())
}
