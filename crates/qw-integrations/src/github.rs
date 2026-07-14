use async_trait::async_trait;
use base64::Engine;
use qw_scanner::{ScanTarget, Finding, TargetType};
use crate::types::*;
use crate::registry::{Integration, IntegrationError};

pub struct GitHubIntegration {
    id: String,
    token: String,
    base_url: String,
    org: Option<String>,
    /// owner/repo where auto-remediation PRs are opened.
    repo: Option<String>,
    client: reqwest::Client,
}

impl GitHubIntegration {
    pub fn from_config(config: &IntegrationConfig) -> Option<Self> {
        let token = std::env::var(&config.api_token_env).ok()?;
        Some(Self {
            id: config.id.clone(),
            token,
            base_url: config.base_url.clone().unwrap_or_else(|| "https://api.github.com".to_string()),
            org: config.settings.get("org").cloned(),
            repo: config.settings.get("repo").cloned(),
            client: reqwest::Client::new(),
        })
    }

    fn gh(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        self.client.request(method, url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "QuantaWatch")
    }
}

#[async_trait]
impl Integration for GitHubIntegration {
    fn id(&self) -> &str { &self.id }
    fn display_name(&self) -> &str { "GitHub" }

    fn capabilities(&self) -> Vec<IntegrationCapability> {
        let mut caps = vec![IntegrationCapability::DiscoverTargets];
        // PR-based auto-remediation is available when a target repo is configured.
        if self.repo.is_some() {
            caps.push(IntegrationCapability::CreateRemediation);
        }
        caps
    }

    async fn test_connection(&self) -> Result<ConnectionStatus, IntegrationError> {
        let resp = self.client.get(format!("{}/user", self.base_url))
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "QuantaWatch")
            .send()
            .await?;

        if resp.status().is_success() {
            let user: serde_json::Value = resp.json().await
                .map_err(|e| IntegrationError::ApiError(e.to_string()))?;
            Ok(ConnectionStatus {
                connected: true,
                user: user["login"].as_str().map(String::from),
                scopes: vec!["repo".to_string()],
                error: None,
            })
        } else {
            Ok(ConnectionStatus {
                connected: false,
                user: None,
                scopes: vec![],
                error: Some(format!("HTTP {}", resp.status())),
            })
        }
    }

    async fn discover_targets(&self) -> Result<Vec<ScanTarget>, IntegrationError> {
        let mut targets = Vec::new();
        let dep_files = ["Cargo.toml", "package.json", "requirements.txt", "go.mod", "Gemfile"];

        let repos_url = if let Some(ref org) = self.org {
            format!("{}/orgs/{}/repos?per_page=100", self.base_url, org)
        } else {
            format!("{}/user/repos?per_page=100", self.base_url)
        };

        let resp = self.client.get(&repos_url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "QuantaWatch")
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(IntegrationError::ApiError(
                format!("Failed to list repos: HTTP {}", resp.status()),
            ));
        }

        let repos: Vec<serde_json::Value> = resp.json().await
            .map_err(|e| IntegrationError::ApiError(e.to_string()))?;

        for repo in &repos {
            let full_name = repo["full_name"].as_str().unwrap_or_default();
            let default_branch = repo["default_branch"].as_str().unwrap_or("main");

            for dep_file in &dep_files {
                let contents_url = format!(
                    "{}/repos/{}/contents/{}?ref={}",
                    self.base_url, full_name, dep_file, default_branch
                );

                let check = self.client.head(&contents_url)
                    .header("Authorization", format!("Bearer {}", self.token))
                    .header("Accept", "application/vnd.github+json")
                    .header("User-Agent", "QuantaWatch")
                    .send()
                    .await;

                if let Ok(resp) = check {
                    if resp.status().is_success() {
                        let mut metadata = std::collections::HashMap::new();
                        metadata.insert("repo".to_string(), full_name.to_string());
                        metadata.insert("branch".to_string(), default_branch.to_string());
                        metadata.insert("integration".to_string(), self.id.clone());
                        metadata.insert("download_url".to_string(), contents_url.clone());
                        metadata.insert("api_url".to_string(), contents_url.clone());

                        targets.push(ScanTarget {
                            id: uuid::Uuid::new_v4().to_string(),
                            target_type: TargetType::DependencyFile,
                            address: format!("{}/{}", full_name, dep_file),
                            metadata,
                        });
                    }
                }
            }
        }

        Ok(targets)
    }

    /// Opens a real pull request that commits a PQC remediation playbook
    /// (the concrete hybrid ML-KEM fix) on a new branch.
    async fn create_remediation(
        &self,
        finding: &Finding,
        opts: &RemediationOpts,
    ) -> Result<RemediationTicket, IntegrationError> {
        let repo = opts.project.clone().or_else(|| self.repo.clone()).ok_or_else(|| {
            IntegrationError::NotConfigured("GitHub remediation requires a 'repo' setting (owner/repo)".to_string())
        })?;

        // 1. Default branch + its head SHA.
        let repo_info: serde_json::Value = self.gh(reqwest::Method::GET, &format!("{}/repos/{}", self.base_url, repo))
            .send().await?.json().await.map_err(|e| IntegrationError::ApiError(e.to_string()))?;
        let base = repo_info["default_branch"].as_str().unwrap_or("main").to_string();

        let ref_info: serde_json::Value = self.gh(reqwest::Method::GET, &format!("{}/repos/{}/git/ref/heads/{}", self.base_url, repo, base))
            .send().await?.json().await.map_err(|e| IntegrationError::ApiError(e.to_string()))?;
        let sha = ref_info["object"]["sha"].as_str()
            .ok_or_else(|| IntegrationError::ApiError("could not resolve base branch SHA".to_string()))?
            .to_string();

        // 2. Create a remediation branch.
        let short = &finding.id.replace(|c: char| !c.is_alphanumeric(), "-")[..finding.id.len().min(12)];
        let branch = format!("quantawatch/pqc-{short}");
        let br = self.gh(reqwest::Method::POST, &format!("{}/repos/{}/git/refs", self.base_url, repo))
            .json(&serde_json::json!({ "ref": format!("refs/heads/{branch}"), "sha": sha }))
            .send().await?;
        if !br.status().is_success() && br.status() != reqwest::StatusCode::UNPROCESSABLE_ENTITY {
            return Err(IntegrationError::ApiError(format!("branch create failed: HTTP {}", br.status())));
        }

        // 3. Commit the remediation playbook file.
        let body_md = format!(
            "# Post-Quantum Remediation\n\n**Finding:** {}\n\n{}\n\n## Recommended fix\n\n{}\n\n```yaml\n# Enable hybrid post-quantum key establishment on TLS.\ntls:\n  key_exchange: [\"X25519MLKEM768\", \"X25519\"]  # hybrid ML-KEM-768\n  min_version: \"1.3\"\n```\n\n_Opened automatically by QuantaWatch._\n",
            finding.title, finding.description,
            finding.remediation.clone().unwrap_or_else(|| "Adopt hybrid ML-KEM key establishment.".to_string()),
        );
        let path = format!(".quantawatch/remediation-{short}.md");
        let put = self.gh(reqwest::Method::PUT, &format!("{}/repos/{}/contents/{}", self.base_url, repo, path))
            .json(&serde_json::json!({
                "message": format!("QuantaWatch: PQC remediation for {}", finding.title),
                "content": base64::engine::general_purpose::STANDARD.encode(body_md.as_bytes()),
                "branch": branch,
            }))
            .send().await?;
        if !put.status().is_success() {
            return Err(IntegrationError::ApiError(format!("file commit failed: HTTP {}", put.status())));
        }

        // 4. Open the pull request.
        let pr = self.gh(reqwest::Method::POST, &format!("{}/repos/{}/pulls", self.base_url, repo))
            .json(&serde_json::json!({
                "title": format!("[QuantaWatch] PQC remediation: {}", finding.title),
                "head": branch,
                "base": base,
                "body": body_md,
            }))
            .send().await?;
        if !pr.status().is_success() {
            return Err(IntegrationError::ApiError(format!("PR create failed: HTTP {}", pr.status())));
        }
        let pr_json: serde_json::Value = pr.json().await.map_err(|e| IntegrationError::ApiError(e.to_string()))?;

        Ok(RemediationTicket {
            id: uuid::Uuid::new_v4().to_string(),
            integration_id: self.id.clone(),
            external_id: format!("#{}", pr_json["number"].as_u64().unwrap_or(0)),
            external_url: pr_json["html_url"].as_str().unwrap_or("").to_string(),
            status: TicketStatus::Open,
            finding_id: finding.id.clone(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
    }

    /// Create a repo webhook that pushes pull_request events to `callback_url`.
    async fn register_webhook(&self, callback_url: &str, secret: &str) -> Result<String, IntegrationError> {
        let repo = self.repo.clone().ok_or_else(|| {
            IntegrationError::NotConfigured("GitHub webhook registration requires a 'repo' setting".to_string())
        })?;
        let resp = self.gh(reqwest::Method::POST, &format!("{}/repos/{}/hooks", self.base_url, repo))
            .json(&serde_json::json!({
                "name": "web",
                "active": true,
                "events": ["pull_request"],
                "config": { "url": callback_url, "content_type": "json", "secret": secret, "insecure_ssl": "0" },
            }))
            .send().await?;
        if resp.status().is_success() {
            let v: serde_json::Value = resp.json().await.map_err(|e| IntegrationError::ApiError(e.to_string()))?;
            Ok(format!("Registered GitHub hook #{} on {repo}", v["id"].as_u64().unwrap_or(0)))
        } else {
            Err(IntegrationError::ApiError(format!("hook registration failed: HTTP {}", resp.status())))
        }
    }

    /// Reconcile a PR's status: open → Open, merged → Resolved, closed → Closed.
    async fn remediation_status(&self, external_id: &str) -> Result<TicketStatus, IntegrationError> {
        let repo = match &self.repo {
            Some(r) => r.clone(),
            None => return Ok(TicketStatus::Unknown),
        };
        let num = external_id.trim_start_matches('#');
        let pr: serde_json::Value = self.gh(reqwest::Method::GET, &format!("{}/repos/{}/pulls/{}", self.base_url, repo, num))
            .send().await?.json().await.map_err(|e| IntegrationError::ApiError(e.to_string()))?;
        Ok(match (pr["state"].as_str(), pr["merged"].as_bool()) {
            (_, Some(true)) => TicketStatus::Resolved,
            (Some("closed"), _) => TicketStatus::Closed,
            (Some("open"), _) => TicketStatus::Open,
            _ => TicketStatus::Unknown,
        })
    }

    async fn fetch_content(&self, target: &ScanTarget) -> Result<Option<String>, IntegrationError> {
        // Prefer the stored contents API URL; otherwise reconstruct it from
        // repo + branch + filename.
        let url = if let Some(api_url) = target.metadata.get("api_url")
            .or_else(|| target.metadata.get("download_url"))
        {
            api_url.clone()
        } else {
            let repo = target.metadata.get("repo").ok_or_else(|| {
                IntegrationError::NotConfigured("target missing repo metadata".to_string())
            })?;
            let branch = target.metadata.get("branch").map(String::as_str).unwrap_or("main");
            let filename = target.address.rsplit('/').next().unwrap_or(&target.address);
            format!(
                "{}/repos/{}/contents/{}?ref={}",
                self.base_url, repo, filename, branch
            )
        };

        let resp = self.client.get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "QuantaWatch")
            .send()
            .await?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(IntegrationError::ApiError(
                format!("Failed to fetch content: HTTP {}", resp.status()),
            ));
        }

        let body: serde_json::Value = resp.json().await
            .map_err(|e| IntegrationError::ApiError(e.to_string()))?;

        let encoded = match body["content"].as_str() {
            Some(c) => c,
            None => return Ok(None),
        };

        // GitHub returns base64 with embedded newlines; strip all whitespace.
        let cleaned: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(cleaned.as_bytes())
            .map_err(|e| IntegrationError::ApiError(format!("base64 decode failed: {e}")))?;
        let text = String::from_utf8(decoded)
            .map_err(|e| IntegrationError::ApiError(format!("invalid utf-8: {e}")))?;

        Ok(Some(text))
    }
}
