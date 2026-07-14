use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::model::PostureSummary;

/// A point-in-time snapshot of overall cryptographic posture.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostureSnapshot {
    pub timestamp: DateTime<Utc>,
    pub overall_score: f64,
    pub total_assets: u32,
    pub by_status: HashMap<String, u32>,
    pub trigger: String,
}

impl PostureSnapshot {
    pub fn from_summary(summary: &PostureSummary, trigger: impl Into<String>) -> Self {
        Self {
            timestamp: summary.calculated_at,
            overall_score: summary.overall_score,
            total_assets: summary.total_assets,
            by_status: summary.by_status.clone(),
            trigger: trigger.into(),
        }
    }
}

/// Append-only JSONL store of posture snapshots, mirroring the audit/scan store pattern.
pub struct PostureHistoryStore {
    path: PathBuf,
    snapshots: Arc<RwLock<Vec<PostureSnapshot>>>,
}

impl PostureHistoryStore {
    pub fn new(store_dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&store_dir)?;
        let path = store_dir.join("posture_history.jsonl");
        let existing = Self::load(&path);
        Ok(Self {
            path,
            snapshots: Arc::new(RwLock::new(existing)),
        })
    }

    fn load(path: &PathBuf) -> Vec<PostureSnapshot> {
        match std::fs::read_to_string(path) {
            Ok(content) => content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Record a snapshot. Skips writing if the score is unchanged from the most recent
    /// snapshot to avoid filling the log with identical entries.
    pub async fn record(&self, snapshot: PostureSnapshot) {
        {
            let snaps = self.snapshots.read().await;
            if let Some(last) = snaps.last() {
                if (last.overall_score - snapshot.overall_score).abs() < f64::EPSILON
                    && last.total_assets == snapshot.total_assets
                {
                    return;
                }
            }
        }

        if let Ok(json) = serde_json::to_string(&snapshot) {
            use std::io::Write;
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
            {
                let _ = writeln!(file, "{json}");
            }
        }
        self.snapshots.write().await.push(snapshot);
    }

    pub async fn history(&self, limit: usize) -> Vec<PostureSnapshot> {
        let snaps = self.snapshots.read().await;
        snaps.iter().rev().take(limit).rev().cloned().collect()
    }

    pub async fn latest(&self) -> Option<PostureSnapshot> {
        self.snapshots.read().await.last().cloned()
    }
}
