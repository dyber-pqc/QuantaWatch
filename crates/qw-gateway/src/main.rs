use anyhow::Result;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    // `quantawatch service <run|install|uninstall> [config]` manages the Windows
    // service; anything else is the normal console launch (config path is the
    // first positional argument).
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("service") {
        #[cfg(windows)]
        {
            let config = args.get(3).cloned().unwrap_or_else(|| "quantawatch.yaml".to_string());
            return match args.get(2).map(String::as_str) {
                // Invoked by the Service Control Manager, not by a human.
                Some("run") => qw_gateway::service::start_dispatcher(),
                Some("install") => qw_gateway::service::install(&config),
                Some("uninstall") => qw_gateway::service::uninstall(),
                _ => {
                    eprintln!("usage: quantawatch service <install [config.yaml]|uninstall|run>");
                    std::process::exit(2);
                }
            };
        }
        #[cfg(not(windows))]
        {
            eprintln!("`service` is only supported on Windows; use systemd elsewhere.");
            std::process::exit(2);
        }
    }

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
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,qw_gateway=debug")),
        )
        .json()
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "quantawatch.yaml".to_string());

    println!("\n  QuantaWatch Gateway v{}", env!("CARGO_PKG_VERSION"));

    // Console mode: Ctrl-C drains the listeners instead of killing the process.
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    qw_gateway::server::run_gateway(&config_path, shutdown).await
}
