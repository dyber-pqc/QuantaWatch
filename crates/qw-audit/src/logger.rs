use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::io::AsyncWriteExt;
use tracing;

use qw_crypto::{GatewayIdentity, sha3_256_hex};
use crate::entry::{AuditEntry, AuditEvent};
use crate::chain::AuditChain;
use crate::AuditError;

/// Async audit logger. Sends events through a channel to a background writer.
#[derive(Clone)]
pub struct AuditLogger {
    tx: mpsc::Sender<LogCommand>,
}

enum LogCommand {
    Log {
        session_id: String,
        event: AuditEvent,
    },
    Flush,
    Shutdown,
}

impl AuditLogger {
    /// Create a new audit logger that writes to the given directory.
    pub fn new(
        audit_dir: PathBuf,
        identity: std::sync::Arc<GatewayIdentity>,
        merkle_batch_size: usize,
    ) -> Result<Self, AuditError> {
        std::fs::create_dir_all(&audit_dir)?;

        let (tx, rx) = mpsc::channel(1024);

        tokio::spawn(Self::writer_task(rx, audit_dir, identity, merkle_batch_size));

        Ok(Self { tx })
    }

    /// Log an audit event (non-blocking).
    pub async fn log(&self, session_id: &str, event: AuditEvent) -> Result<(), AuditError> {
        self.tx.send(LogCommand::Log {
            session_id: session_id.to_string(),
            event,
        }).await.map_err(|_| AuditError::ChannelClosed)
    }

    /// Flush pending writes.
    pub async fn flush(&self) -> Result<(), AuditError> {
        self.tx.send(LogCommand::Flush).await.map_err(|_| AuditError::ChannelClosed)
    }

    /// Shutdown the logger gracefully.
    pub async fn shutdown(&self) -> Result<(), AuditError> {
        self.tx.send(LogCommand::Shutdown).await.map_err(|_| AuditError::ChannelClosed)
    }

    async fn writer_task(
        mut rx: mpsc::Receiver<LogCommand>,
        audit_dir: PathBuf,
        identity: std::sync::Arc<GatewayIdentity>,
        merkle_batch_size: usize,
    ) {
        let log_path = audit_dir.join("audit.jsonl");
        let mut chain = AuditChain::new(merkle_batch_size);

        // Try to resume from existing log
        if let Ok(content) = std::fs::read_to_string(&log_path) {
            for line in content.lines().rev() {
                if let Ok(entry) = serde_json::from_str::<AuditEntry>(line) {
                    chain = AuditChain::resume(
                        entry.content_hash,
                        entry.sequence + 1,
                        merkle_batch_size,
                    );
                    tracing::info!(sequence = entry.sequence + 1, "Resumed audit chain");
                    break;
                }
            }
        }

        let mut file = match tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .await
        {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(error = %e, "Failed to open audit log file");
                return;
            }
        };

        while let Some(cmd) = rx.recv().await {
            match cmd {
                LogCommand::Log { session_id, event } => {
                    let sequence = chain.next_sequence();
                    let prev_hash = chain.prev_hash().to_string();

                    let mut entry = AuditEntry::new(sequence, &session_id, event, &prev_hash);

                    // Compute content hash
                    let content_bytes = entry.content_bytes();
                    let content_hash = sha3_256_hex(&content_bytes);
                    entry.content_hash = content_hash.clone();

                    // Sign with ML-DSA-65
                    match identity.sign(content_hash.as_bytes()) {
                        Ok(sig) => {
                            entry.signature = base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                &sig,
                            );
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Failed to sign audit entry");
                            continue;
                        }
                    }

                    // Advance chain, check for Merkle root
                    entry.merkle_root = chain.advance(&content_hash);

                    // Write to file
                    match serde_json::to_string(&entry) {
                        Ok(json) => {
                            let line = format!("{json}\n");
                            if let Err(e) = file.write_all(line.as_bytes()).await {
                                tracing::error!(error = %e, "Failed to write audit entry");
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Failed to serialize audit entry");
                        }
                    }
                }
                LogCommand::Flush => {
                    if let Err(e) = file.flush().await {
                        tracing::error!(error = %e, "Failed to flush audit log");
                    }
                }
                LogCommand::Shutdown => {
                    let _ = file.flush().await;
                    break;
                }
            }
        }

        tracing::info!("Audit logger shut down");
    }
}
