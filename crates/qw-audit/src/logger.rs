use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::backend::AuditBackend;
use crate::chain::AuditChain;
use crate::checkpoint::AuditCheckpoint;
use crate::entry::{AuditEntry, AuditEvent};
use crate::AuditError;
use chrono::Utc;
use qw_crypto::{sha3_256_hex, GatewayIdentity};

/// Async audit logger. Sends events through a channel to a background writer,
/// which appends them to this replica's chain in the shared [`AuditBackend`] and
/// periodically commits a global [`AuditCheckpoint`].
#[derive(Clone)]
pub struct AuditLogger {
    tx: mpsc::Sender<LogCommand>,
    writer_id: String,
}

#[allow(clippy::large_enum_variant)] // Log dominates; boxing the hot path adds an alloc per event
enum LogCommand {
    Log {
        session_id: String,
        event: AuditEvent,
    },
    Checkpoint,
    Flush,
    Shutdown,
}

impl AuditLogger {
    /// Create a logger backed by shared storage.
    ///
    /// `writer_id` identifies this replica's chain and must be stable across
    /// restarts of the same replica and unique across replicas (e.g. the pod
    /// hostname). `checkpoint_interval` of zero disables periodic checkpoints.
    pub fn new(
        backend: Arc<dyn AuditBackend>,
        identity: Arc<GatewayIdentity>,
        merkle_batch_size: usize,
        writer_id: String,
        checkpoint_interval: Duration,
    ) -> Self {
        let (tx, rx) = mpsc::channel(1024);

        tokio::spawn(Self::writer_task(
            rx,
            backend,
            identity,
            merkle_batch_size,
            writer_id.clone(),
        ));

        // Periodic global checkpoint ticker.
        if !checkpoint_interval.is_zero() {
            let tx2 = tx.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(checkpoint_interval);
                ticker.tick().await; // skip the immediate first tick
                loop {
                    ticker.tick().await;
                    if tx2.send(LogCommand::Checkpoint).await.is_err() {
                        break;
                    }
                }
            });
        }

        Self { tx, writer_id }
    }

    /// This replica's writer id.
    pub fn writer_id(&self) -> &str {
        &self.writer_id
    }

    /// Log an audit event (non-blocking).
    pub async fn log(&self, session_id: &str, event: AuditEvent) -> Result<(), AuditError> {
        self.tx
            .send(LogCommand::Log {
                session_id: session_id.to_string(),
                event,
            })
            .await
            .map_err(|_| AuditError::ChannelClosed)
    }

    /// Request an immediate global checkpoint.
    pub async fn checkpoint(&self) -> Result<(), AuditError> {
        self.tx
            .send(LogCommand::Checkpoint)
            .await
            .map_err(|_| AuditError::ChannelClosed)
    }

    /// No-op retained for API compatibility (store appends are durable per-write).
    pub async fn flush(&self) -> Result<(), AuditError> {
        self.tx
            .send(LogCommand::Flush)
            .await
            .map_err(|_| AuditError::ChannelClosed)
    }

    /// Shut down the logger gracefully (commits a final checkpoint first).
    pub async fn shutdown(&self) -> Result<(), AuditError> {
        self.tx
            .send(LogCommand::Shutdown)
            .await
            .map_err(|_| AuditError::ChannelClosed)
    }

    async fn writer_task(
        mut rx: mpsc::Receiver<LogCommand>,
        backend: Arc<dyn AuditBackend>,
        identity: Arc<GatewayIdentity>,
        merkle_batch_size: usize,
        writer_id: String,
    ) {
        // Resume THIS writer's chain from the shared store.
        let mut chain = match backend.writer_tip(&writer_id) {
            Some((seq, hash)) => {
                tracing::info!(writer_id, next_sequence = seq + 1, "Resumed audit chain");
                AuditChain::resume(hash, seq + 1, merkle_batch_size)
            }
            None => AuditChain::new(merkle_batch_size),
        };

        while let Some(cmd) = rx.recv().await {
            match cmd {
                LogCommand::Log { session_id, event } => {
                    let sequence = chain.next_sequence();
                    let prev_hash = chain.prev_hash().to_string();

                    let mut entry =
                        AuditEntry::new(&writer_id, sequence, &session_id, event, &prev_hash);
                    let content_hash = sha3_256_hex(&entry.content_bytes());
                    entry.content_hash = content_hash.clone();

                    // Sign with ML-DSA-65.
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

                    entry.merkle_root = chain.advance(&content_hash);

                    // Persist off the async worker (the store backend is blocking).
                    let backend2 = backend.clone();
                    if let Err(e) =
                        tokio::task::spawn_blocking(move || backend2.append_entry(&entry)).await
                    {
                        tracing::error!(error = %e, "audit append task panicked");
                    }
                }
                LogCommand::Checkpoint => {
                    let backend2 = backend.clone();
                    let identity2 = identity.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        commit_checkpoint(&*backend2, &identity2)
                    })
                    .await;
                }
                LogCommand::Flush => {}
                LogCommand::Shutdown => {
                    // Anchor the final state before exiting.
                    let backend2 = backend.clone();
                    let identity2 = identity.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        commit_checkpoint(&*backend2, &identity2)
                    })
                    .await;
                    break;
                }
            }
        }

        tracing::info!("Audit logger shut down");
    }
}

/// Build, sign, and persist the next global checkpoint. Returns the checkpoint
/// if one was committed (None if there are no entries yet or a race was lost).
fn commit_checkpoint(
    backend: &dyn AuditBackend,
    identity: &GatewayIdentity,
) -> Option<AuditCheckpoint> {
    backend.commit_checkpoint(&|seq, prev, tips| {
        let mut cp = AuditCheckpoint::build(seq, prev, tips, Utc::now());
        match identity.sign(cp.content_hash.as_bytes()) {
            Ok(sig) => {
                cp.signature =
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &sig);
            }
            Err(e) => tracing::error!(error = %e, "Failed to sign audit checkpoint"),
        }
        cp
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::WriterTip;
    use crate::verifier::verify_sharded;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// In-memory AuditBackend for exercising the logger without a database.
    #[derive(Default)]
    struct MemBackend {
        entries: Mutex<Vec<AuditEntry>>,
        checkpoints: Mutex<Vec<AuditCheckpoint>>,
    }

    impl AuditBackend for MemBackend {
        fn append_entry(&self, e: &AuditEntry) {
            self.entries.lock().unwrap().push(e.clone());
        }
        fn writer_tip(&self, writer_id: &str) -> Option<(u64, String)> {
            self.entries
                .lock()
                .unwrap()
                .iter()
                .filter(|e| e.writer_id == writer_id)
                .max_by_key(|e| e.sequence)
                .map(|e| (e.sequence, e.content_hash.clone()))
        }
        fn all_writer_tips(&self) -> Vec<WriterTip> {
            let es = self.entries.lock().unwrap();
            let mut m: BTreeMap<String, &AuditEntry> = BTreeMap::new();
            for e in es.iter() {
                m.entry(e.writer_id.clone())
                    .and_modify(|c| {
                        if e.sequence > c.sequence {
                            *c = e;
                        }
                    })
                    .or_insert(e);
            }
            m.values()
                .map(|e| WriterTip {
                    writer_id: e.writer_id.clone(),
                    seq: e.sequence,
                    content_hash: e.content_hash.clone(),
                })
                .collect()
        }
        fn list_entries(&self, _limit: usize) -> Vec<AuditEntry> {
            self.entries.lock().unwrap().clone()
        }
        fn list_checkpoints(&self) -> Vec<AuditCheckpoint> {
            self.checkpoints.lock().unwrap().clone()
        }
        fn latest_checkpoint(&self) -> Option<AuditCheckpoint> {
            self.checkpoints.lock().unwrap().last().cloned()
        }
        fn commit_checkpoint(
            &self,
            build: &dyn Fn(u64, &str, Vec<WriterTip>) -> AuditCheckpoint,
        ) -> Option<AuditCheckpoint> {
            let tips = self.all_writer_tips();
            if tips.is_empty() {
                return None;
            }
            let (seq, prev) = self
                .checkpoints
                .lock()
                .unwrap()
                .last()
                .map(|c| (c.checkpoint_seq + 1, c.content_hash.clone()))
                .unwrap_or((0, String::new()));
            let cp = build(seq, &prev, tips);
            self.checkpoints.lock().unwrap().push(cp.clone());
            Some(cp)
        }
    }

    fn identity() -> Arc<GatewayIdentity> {
        let dir = tempfile::tempdir().unwrap();
        Arc::new(GatewayIdentity::load_or_generate(dir.path()).unwrap())
    }

    /// End-to-end: log events through the async logger, commit a checkpoint,
    /// then verify the whole sharded trail under the signing key.
    #[tokio::test]
    async fn logger_writes_and_verifies() {
        let backend = Arc::new(MemBackend::default());
        let id = identity();
        let pk = id.public_key_bytes();

        let logger = AuditLogger::new(
            backend.clone(),
            id.clone(),
            4,
            "node-A".to_string(),
            Duration::ZERO, // no periodic ticker; we checkpoint explicitly
        );

        for i in 0..3u64 {
            logger
                .log(
                    "sess",
                    AuditEvent::SessionClosed {
                        total_requests: i,
                        total_tokens: 0,
                    },
                )
                .await
                .unwrap();
        }
        logger.checkpoint().await.unwrap();

        // Wait for the writer task to drain (append + checkpoint are async).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if backend.entries.lock().unwrap().len() == 3
                && !backend.checkpoints.lock().unwrap().is_empty()
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "logger did not drain"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let entries = backend.list_entries(1000);
        let checkpoints = backend.list_checkpoints();
        let r = verify_sharded(&entries, &checkpoints, &pk);
        assert!(r.valid, "expected valid, errors: {:?}", r.errors);
        assert_eq!(r.writers_checked, 1);
        assert_eq!(r.entries_checked, 3);
        assert_eq!(r.checkpoints_checked, 1);

        // Entries form a proper 0,1,2 chain under one writer.
        let mut seqs: Vec<u64> = entries.iter().map(|e| e.sequence).collect();
        seqs.sort_unstable();
        assert_eq!(seqs, vec![0, 1, 2]);
    }
}
