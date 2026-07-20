use crate::checkpoint::{AuditCheckpoint, WriterTip};
use crate::entry::AuditEntry;

/// Storage backend for the sharded audit log. Implemented by `qw_store::Store`
/// (shared Postgres or local SQLite). Synchronous by design so it matches the
/// Store's API; the async [`crate::AuditLogger`] calls these on a blocking task.
///
/// Entry appends are lock-free — a replica only ever writes its own `writer_id`
/// rows, so `(writer_id, sequence)` never collides across replicas. Only
/// checkpoint creation is serialized, inside [`AuditBackend::commit_checkpoint`].
pub trait AuditBackend: Send + Sync {
    /// Append one entry to its writer's chain.
    fn append_entry(&self, entry: &AuditEntry);

    /// The tip of `writer_id`'s chain — `(sequence, content_hash)` — for resume.
    fn writer_tip(&self, writer_id: &str) -> Option<(u64, String)>;

    /// The current tip of every writer's chain (for building a checkpoint).
    fn all_writer_tips(&self) -> Vec<WriterTip>;

    /// Entries in global insertion order (newest last), capped at `limit`.
    fn list_entries(&self, limit: usize) -> Vec<AuditEntry>;

    /// All checkpoints in order (oldest first).
    fn list_checkpoints(&self) -> Vec<AuditCheckpoint>;

    /// The most recent checkpoint, if any.
    fn latest_checkpoint(&self) -> Option<AuditCheckpoint>;

    /// Create the next checkpoint atomically: under a serialization lock, read
    /// the next sequence + previous checkpoint hash + all writer tips, hand them
    /// to `build` (which signs), persist the result, and return it. Returns
    /// `None` if nothing could be committed (e.g. lost a race, or no writers yet).
    fn commit_checkpoint(
        &self,
        build: &dyn Fn(u64, &str, Vec<WriterTip>) -> AuditCheckpoint,
    ) -> Option<AuditCheckpoint>;
}
