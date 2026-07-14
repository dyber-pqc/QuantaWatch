use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::types::RemediationTicket;

/// Append-only JSONL store of remediation tickets, mirroring the posture/scan
/// store pattern: `std::fs` append on disk plus an in-memory vector.
pub struct RemediationStore {
    path: PathBuf,
    tickets: Arc<RwLock<Vec<RemediationTicket>>>,
}

impl RemediationStore {
    pub fn new(store_dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&store_dir)?;
        let path = store_dir.join("remediations.jsonl");
        let existing = Self::load(&path);
        Ok(Self {
            path,
            tickets: Arc::new(RwLock::new(existing)),
        })
    }

    fn load(path: &PathBuf) -> Vec<RemediationTicket> {
        match std::fs::read_to_string(path) {
            Ok(content) => content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Append a ticket to the log and the in-memory vector.
    pub async fn record(&self, ticket: RemediationTicket) {
        if let Ok(json) = serde_json::to_string(&ticket) {
            use std::io::Write;
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
            {
                let _ = writeln!(file, "{json}");
            }
        }
        self.tickets.write().await.push(ticket);
    }

    /// Return all tickets, newest first.
    pub async fn list(&self) -> Vec<RemediationTicket> {
        let tickets = self.tickets.read().await;
        tickets.iter().rev().cloned().collect()
    }
}
