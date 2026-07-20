use crate::types::*;
use async_trait::async_trait;
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Timeout")]
    Timeout,
    #[error("{0}")]
    Other(String),
}

#[async_trait]
pub trait Scanner: Send + Sync + 'static {
    fn id(&self) -> &str;
    fn display_name(&self) -> &str;
    fn categories(&self) -> Vec<FindingCategory>;
    async fn scan(&self, target: &ScanTarget) -> Result<ScanResult, ScannerError>;
    fn supports(&self, target_type: &TargetType) -> bool;
}

pub struct ScannerRegistry {
    scanners: HashMap<String, Box<dyn Scanner>>,
}

impl Default for ScannerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ScannerRegistry {
    pub fn new() -> Self {
        Self {
            scanners: HashMap::new(),
        }
    }

    pub fn register(&mut self, scanner: Box<dyn Scanner>) {
        self.scanners.insert(scanner.id().to_string(), scanner);
    }

    pub fn get(&self, id: &str) -> Option<&dyn Scanner> {
        self.scanners.get(id).map(|s| s.as_ref())
    }

    pub fn list(&self) -> Vec<&str> {
        self.scanners.keys().map(|s| s.as_str()).collect()
    }

    pub async fn scan_all(&self, target: &ScanTarget) -> Vec<ScanResult> {
        let mut results = Vec::new();
        for scanner in self.scanners.values() {
            if scanner.supports(&target.target_type) {
                match scanner.scan(target).await {
                    Ok(r) => results.push(r),
                    Err(e) => {
                        tracing::warn!(scanner = scanner.id(), error = %e, "Scanner failed");
                        results.push(ScanResult {
                            scanner_id: scanner.id().to_string(),
                            target_id: target.id.clone(),
                            started_at: chrono::Utc::now(),
                            completed_at: chrono::Utc::now(),
                            findings: vec![],
                            status: ScanStatus::Failed,
                            error: Some(e.to_string()),
                        });
                    }
                }
            }
        }
        results
    }
}

pub fn build_scanner_registry(config: &ScannerConfig) -> ScannerRegistry {
    let mut registry = ScannerRegistry::new();
    if config.tls.enabled {
        registry.register(Box::new(crate::scanners::tls::TlsScanner::new(
            config.tls.clone(),
        )));
    }
    if config.dependencies.enabled {
        registry.register(Box::new(
            crate::scanners::dependency::DependencyScanner::new(),
        ));
    }
    if config.certificates.enabled {
        registry.register(Box::new(
            crate::scanners::certificate::CertificateScanner::new(config.certificates.clone()),
        ));
    }
    if config.code.enabled {
        registry.register(Box::new(crate::scanners::code::CodeScanner::new(
            config.code.clone(),
        )));
    }
    if config.data_at_rest.enabled {
        registry.register(Box::new(
            crate::scanners::data_at_rest::DataAtRestScanner::new(&config.data_at_rest),
        ));
    }
    registry
}
