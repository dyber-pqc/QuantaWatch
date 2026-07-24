//! Windows service integration.
//!
//! `quantawatch.exe` is a console program; the Service Control Manager expects a
//! process that reports its status back over the SCM protocol (a plain exe
//! registered with `sc create` is started and then killed with error 1053). This
//! module implements that protocol so the gateway can run as a real service —
//! surviving logoff and restarting automatically after a crash or reboot.
//!
//! Two details matter for services specifically:
//!   * the SCM starts the process with the working directory set to
//!     `C:\Windows\System32`, so the config path is resolved to an **absolute**
//!     path at install time and passed on the service command line;
//!   * there is no console, so logs go to a **file** next to the executable
//!     rather than stdout.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub const SERVICE_NAME: &str = "QuantaWatch";
pub const SERVICE_DISPLAY_NAME: &str = "QuantaWatch PQC Gateway";
pub const SERVICE_DESCRIPTION: &str =
    "QuantaWatch post-quantum cryptographic posture gateway (proxy + admin API).";

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

windows_service::define_windows_service!(ffi_service_main, service_main);

/// Entry point used by `quantawatch service run` (invoked by the SCM).
pub fn start_dispatcher() -> Result<()> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| anyhow!("service dispatcher failed: {e}"))
}

/// SCM calls this on the service's own thread. Catch panics here: this function
/// is invoked from a C callback, so a panic unwinding past it is undefined
/// behaviour (in practice, a process abort → error 1067 with no diagnostics).
fn service_main(arguments: Vec<OsString>) {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_service(arguments))) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!(error = %e, "service terminated with an error"),
        Err(_) => tracing::error!("service panicked during startup"),
    }
}

fn run_service(arguments: Vec<OsString>) -> Result<()> {
    // The config path is set in the service's binPath ("...exe service run
    // <config>"), which the SCM passes as the PROCESS command line — visible via
    // std::env::args(), NOT via this `arguments` parameter (that only carries the
    // extra args from the StartService call, usually just the service name). So
    // read argv[3] first, then fall back to any StartService arg, then a default.
    let config_path = std::env::args()
        .nth(3)
        .or_else(|| arguments.get(1).map(|s| s.to_string_lossy().to_string()))
        .unwrap_or_else(default_config_path);

    // The SCM starts us in C:\Windows\System32. The config uses paths relative
    // to itself (./data, ./keys, ./audit), so anchor the working directory to
    // the config's own directory — otherwise the service would scatter its
    // database and keys under System32. Logs go there too, keeping all mutable
    // state in one place.
    let state_dir = Path::new(&config_path)
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(exe_dir);
    let cwd_err = std::env::set_current_dir(&state_dir).err();

    init_file_logging(&state_dir);
    if let Some(e) = cwd_err {
        tracing::error!(dir = %state_dir.display(), error = %e, "could not set working directory");
    } else {
        tracing::info!(dir = %state_dir.display(), "working directory anchored to the config");
    }
    tracing::info!(%config_path, "QuantaWatch service starting");

    // Bridge the SCM's stop control into an async shutdown signal.
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })
        .map_err(|e| anyhow!("could not register control handler: {e}"))?;

    let set_status = |state: ServiceState, accept: ServiceControlAccept, wait: Duration| {
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: wait,
            process_id: None,
        })
    };

    // Tell the SCM we're coming up so it doesn't time us out (error 1053).
    set_status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(30),
    )?;

    // ML-DSA keygen uses large stack arrays; run on a generous-stack thread as
    // the console path does.
    let worker = std::thread::Builder::new()
        .name("quantawatch-service".to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || -> Result<()> {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(16 * 1024 * 1024)
                .build()?;
            runtime.block_on(async move {
                let shutdown = async move {
                    // Block on the sync channel off-runtime, then resolve.
                    let _ = tokio::task::spawn_blocking(move || shutdown_rx.recv()).await;
                };
                crate::server::run_gateway(&config_path, shutdown).await
            })
        })?;

    set_status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        Duration::default(),
    )?;

    let result = worker
        .join()
        .unwrap_or_else(|_| Err(anyhow!("service worker panicked")));

    set_status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        Duration::default(),
    )?;

    if let Err(e) = &result {
        tracing::error!(error = %e, "gateway exited with an error");
    }
    result
}

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn default_config_path() -> String {
    exe_dir()
        .join("quantawatch.yaml")
        .to_string_lossy()
        .to_string()
}

/// Services have no console: write JSON logs to a rolling file in the state dir.
///
/// Uses the fallible builder rather than `rolling::daily()`, which `.expect()`s
/// on failure — a panic here would unwind across the SCM's C callback and abort
/// the whole process (error 1067) before any log exists. If the file can't be
/// opened we fall back to a discard writer so the service still runs.
fn init_file_logging(dir: &Path) {
    use tracing_appender::rolling::{RollingFileAppender, Rotation};
    use tracing_subscriber::EnvFilter;
    let filter = || {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,qw_gateway=debug"))
    };
    match RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("quantawatch-service")
        .filename_suffix("log")
        .build(dir)
    {
        Ok(appender) => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter())
                .json()
                .with_writer(appender)
                .with_ansi(false)
                .try_init();
        }
        Err(_) => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter())
                .json()
                .with_writer(std::io::sink)
                .try_init();
        }
    }
}

/// Register the service. Requires an elevated process.
///
/// `account` defaults to the per-service **virtual account**
/// `NT SERVICE\QuantaWatch`: Windows creates it automatically, it has no
/// password to manage or leak, and it is far less privileged than LocalSystem —
/// it can only reach what it has explicitly been granted. Pass "LocalSystem"
/// (or a domain account) to override.
pub fn install(config_path: &str, account: Option<&str>) -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| anyhow!("open SCM (are you elevated?): {e}"))?;

    let exe = std::env::current_exe()?;
    // Absolute config path: the SCM runs us from C:\Windows\System32.
    let config = std::fs::canonicalize(config_path)
        .map_err(|e| anyhow!("config '{config_path}' not found: {e}"))?;
    let config = strip_unc(&config);

    // Virtual service account unless overridden. "LocalSystem" maps to None,
    // which is how the SCM spells the built-in account.
    let default_account = format!("NT SERVICE\\{SERVICE_NAME}");
    let account = account.unwrap_or(&default_account).to_string();
    let account_name = if account.eq_ignore_ascii_case("localsystem") {
        None
    } else {
        Some(OsString::from(&account))
    };

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        // argv[0] is the exe; these follow it -> arguments[1] = config path.
        launch_arguments: vec![
            OsString::from("service"),
            OsString::from("run"),
            OsString::from(&config),
        ],
        dependencies: vec![],
        // A virtual account has no password; Windows manages it.
        account_name,
        account_password: None,
    };

    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(|e| anyhow!("create service: {e}"))?;
    service
        .set_description(SERVICE_DESCRIPTION)
        .map_err(|e| anyhow!("set description: {e}"))?;

    // Relative paths in the config (./data, ./keys, ./audit) and the log file
    // all resolve against the config's directory at run time.
    let state_dir = Path::new(&config)
        .parent()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    println!("Installed service '{SERVICE_NAME}' ({SERVICE_DISPLAY_NAME})");
    println!("  exe    : {}", std::env::current_exe()?.display());
    println!("  account: {account}");
    println!("  config : {config}");
    println!("  state  : {state_dir}  (data/, keys/, audit/)");
    println!("  logs   : {state_dir}\\quantawatch-service.log");
    println!("\nStart it with:  sc start {SERVICE_NAME}");
    println!("Configure auto-restart on failure:");
    println!(
        "  sc failure {SERVICE_NAME} reset= 86400 actions= restart/5000/restart/5000/restart/30000"
    );
    Ok(())
}

/// Stop (if running) and delete the service. Requires an elevated process.
pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| anyhow!("open SCM (are you elevated?): {e}"))?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .map_err(|e| anyhow!("open service: {e}"))?;

    if service
        .query_status()
        .map(|s| s.current_state != ServiceState::Stopped)
        .unwrap_or(false)
    {
        let _ = service.stop();
        // Give it a moment to wind down before deleting.
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(250));
            if service
                .query_status()
                .map(|s| s.current_state == ServiceState::Stopped)
                .unwrap_or(true)
            {
                break;
            }
        }
    }

    service
        .delete()
        .map_err(|e| anyhow!("delete service: {e}"))?;
    println!("Removed service '{SERVICE_NAME}'");
    Ok(())
}

/// `canonicalize` yields a `\\?\` UNC prefix that some tooling mishandles.
fn strip_unc(p: &Path) -> String {
    let s = p.to_string_lossy().to_string();
    s.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(s)
}
