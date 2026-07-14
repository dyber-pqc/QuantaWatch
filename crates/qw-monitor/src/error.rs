use thiserror::Error;

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("pattern compilation error: {0}")]
    PatternCompilation(String),

    #[error("scan error: {0}")]
    ScanError(String),
}
