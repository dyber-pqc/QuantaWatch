// Audit logging happens in the proxy handler after the response is received.
// This module provides helper types for audit context.

#[derive(Debug, Clone)]
pub struct AuditContext {
    pub start_time: std::time::Instant,
}

impl AuditContext {
    pub fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
        }
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }
}
