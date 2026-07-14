use crate::types::*;
use qw_crypto::sha3_256_hex;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

enum StoreCommand {
    RecordScan(ScanRecord),
    RecordFinding(FindingRecord),
}

pub struct ScanStore {
    tx: mpsc::Sender<StoreCommand>,
    scans: std::sync::Arc<tokio::sync::RwLock<Vec<ScanRecord>>>,
    findings: std::sync::Arc<tokio::sync::RwLock<Vec<FindingRecord>>>,
}

impl ScanStore {
    pub fn new(store_dir: PathBuf) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&store_dir)?;
        let scans_path = store_dir.join("scans.jsonl");
        let findings_path = store_dir.join("findings.jsonl");

        // Load existing data
        let existing_scans = Self::load_records::<ScanRecord>(&scans_path);
        let existing_findings = Self::load_records::<FindingRecord>(&findings_path);

        let scans = std::sync::Arc::new(tokio::sync::RwLock::new(existing_scans));
        let findings = std::sync::Arc::new(tokio::sync::RwLock::new(existing_findings));

        let (tx, mut rx) = mpsc::channel::<StoreCommand>(256);

        let scans_clone = scans.clone();
        let findings_clone = findings.clone();

        tokio::spawn(async move {
            let mut scans_file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&scans_path)
                .await
                .expect("Failed to open scans file");
            let mut findings_file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&findings_path)
                .await
                .expect("Failed to open findings file");

            while let Some(cmd) = rx.recv().await {
                match cmd {
                    StoreCommand::RecordScan(record) => {
                        if let Ok(json) = serde_json::to_string(&record) {
                            let _ = scans_file.write_all(format!("{json}\n").as_bytes()).await;
                            let _ = scans_file.flush().await;
                            scans_clone.write().await.push(record);
                        }
                    }
                    StoreCommand::RecordFinding(record) => {
                        if let Ok(json) = serde_json::to_string(&record) {
                            let _ = findings_file
                                .write_all(format!("{json}\n").as_bytes())
                                .await;
                            let _ = findings_file.flush().await;
                            findings_clone.write().await.push(record);
                        }
                    }
                }
            }
        });

        Ok(Self {
            tx,
            scans,
            findings,
        })
    }

    fn load_records<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Vec<T> {
        match std::fs::read_to_string(path) {
            Ok(content) => content
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    pub async fn record_scan(&self, result: &ScanResult, target: &ScanTarget) {
        let content = serde_json::to_vec(&result.findings).unwrap_or_default();
        let record = ScanRecord {
            id: uuid::Uuid::new_v4().to_string(),
            scanner_id: result.scanner_id.clone(),
            target_id: result.target_id.clone(),
            target_address: target.address.clone(),
            status: result.status.clone(),
            finding_count: result.findings.len() as u32,
            started_at: result.started_at,
            completed_at: result.completed_at,
            content_hash: sha3_256_hex(&content),
        };
        let scan_id = record.id.clone();
        let _ = self.tx.send(StoreCommand::RecordScan(record)).await;

        for finding in &result.findings {
            let fr = FindingRecord {
                id: finding.id.clone(),
                scan_id: scan_id.clone(),
                category: finding.category.clone(),
                severity: finding.severity.clone(),
                title: finding.title.clone(),
                description: finding.description.clone(),
                asset_type: finding.asset.asset_type.clone(),
                algorithm: finding.asset.algorithm.clone(),
                pqc_status: finding.pqc_status.clone(),
                location: finding.asset.location.path.clone(),
                remediation: finding.remediation.clone(),
                created_at: chrono::Utc::now(),
            };
            let _ = self.tx.send(StoreCommand::RecordFinding(fr)).await;
        }
    }

    pub async fn get_scans(&self, limit: usize) -> Vec<ScanRecord> {
        let scans = self.scans.read().await;
        scans.iter().rev().take(limit).cloned().collect()
    }

    pub async fn get_scan(&self, id: &str) -> Option<ScanRecord> {
        let scans = self.scans.read().await;
        scans.iter().find(|s| s.id == id).cloned()
    }

    pub async fn get_findings_for_scan(&self, scan_id: &str) -> Vec<FindingRecord> {
        let findings = self.findings.read().await;
        findings
            .iter()
            .filter(|f| f.scan_id == scan_id)
            .cloned()
            .collect()
    }

    pub async fn get_all_findings(&self) -> Vec<FindingRecord> {
        self.findings.read().await.clone()
    }

    pub async fn get_finding(&self, id: &str) -> Option<FindingRecord> {
        let findings = self.findings.read().await;
        findings.iter().find(|f| f.id == id).cloned()
    }
}
