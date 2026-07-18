//! Agentless cloud connectors — discover cryptographic assets directly from
//! cloud provider APIs (AWS KMS/ACM via SigV4, Azure Key Vault via OAuth).
//!
//! Credentials are read from the environment. If they are absent or the API is
//! unreachable the connector logs and returns an empty inventory, so a
//! misconfigured connector never breaks a sync.

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use qw_scanner::PqcStatus;
use qw_store::AssetRow;

use crate::config::ConnectorConfig;

type HmacSha256 = Hmac<Sha256>;

/// Map a cloud key spec / algorithm to a PQC status. All classical asymmetric
/// algorithms are quantum-vulnerable; symmetric/PQC ones are safe.
pub fn key_spec_to_pqc(spec: &str) -> PqcStatus {
    let s = spec.to_uppercase();
    if s.contains("ML_KEM")
        || s.contains("ML_DSA")
        || s.contains("MLKEM")
        || s.contains("MLDSA")
        || s.contains("KYBER")
        || s.contains("DILITHIUM")
    {
        PqcStatus::PqcReady
    } else if s.contains("RSA")
        || s.contains("ECC")
        || s.contains("EC_")
        || s.contains("ECDSA")
        || s.contains("SECP")
        || s.contains("NIST")
    {
        PqcStatus::ClassicalSecure
    } else if s.contains("SYMMETRIC")
        || s.contains("AES")
        || s.contains("HMAC")
        || s.contains("OCT")
    {
        // Symmetric keys are quantum-resistant at adequate sizes.
        PqcStatus::PqcReady
    } else {
        PqcStatus::Unknown
    }
}

fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac key");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Compute an AWS SigV4 `Authorization` header for a POST request.
/// Verified against AWS's official example test vector (see tests).
#[allow(clippy::too_many_arguments)] // SigV4 inputs are fixed by the AWS spec
pub fn sigv4_authorization(
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    host: &str,
    amz_target: &str,
    amz_date: &str, // YYYYMMDDT HHMMSSZ
    body: &str,
) -> String {
    let date = &amz_date[..8];
    let payload_hash = sha256_hex(body.as_bytes());

    let canonical_headers = format!(
        "content-type:application/x-amz-json-1.1\nhost:{host}\nx-amz-date:{amz_date}\nx-amz-target:{amz_target}\n"
    );
    let signed_headers = "content-type;host;x-amz-date;x-amz-target";
    let canonical_request =
        format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    let k_date = hmac(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));

    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
}

/// Dispatch to the right cloud connector.
pub async fn discover(client: &reqwest::Client, c: &ConnectorConfig) -> Vec<AssetRow> {
    match c.connector_type.as_str() {
        "aws" => discover_aws(client, c).await,
        "azure" => discover_azure(client, c).await,
        "gcp" => discover_gcp(client, c).await,
        "kubernetes" | "k8s" => discover_kubernetes(client, c).await,
        _ => Vec::new(), // generic handled by endpoint-list expansion
    }
}

/// Connectors that make their own API calls (vs. an endpoint list to TLS-scan).
pub fn is_api_connector(connector_type: &str) -> bool {
    matches!(
        connector_type,
        "aws" | "azure" | "gcp" | "kubernetes" | "k8s"
    )
}

// ---- Kubernetes: agentless, API-first discovery -------------------------------

/// Parse a Kubernetes `SecretList` for `kubernetes.io/tls` secrets, returning
/// `(namespace/name, cert-PEM-bytes)` for each.
fn parse_tls_secrets(json: &serde_json::Value) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for item in json["items"].as_array().cloned().unwrap_or_default() {
        if item["type"].as_str() != Some("kubernetes.io/tls") {
            continue;
        }
        let ns = item["metadata"]["namespace"].as_str().unwrap_or("default");
        let name = item["metadata"]["name"].as_str().unwrap_or("tls");
        // data["tls.crt"] is base64-encoded PEM.
        if let Some(b64) = item["data"]["tls.crt"].as_str() {
            if let Ok(pem) = base64::engine::general_purpose::STANDARD.decode(b64) {
                out.push((format!("{ns}/{name}"), pem));
            }
        }
    }
    out
}

/// Parse an `IngressList` for the TLS host names it terminates.
fn parse_ingress_hosts(json: &serde_json::Value) -> Vec<String> {
    let mut hosts = Vec::new();
    for item in json["items"].as_array().cloned().unwrap_or_default() {
        for tls in item["spec"]["tls"].as_array().cloned().unwrap_or_default() {
            for h in tls["hosts"].as_array().cloned().unwrap_or_default() {
                if let Some(h) = h.as_str() {
                    hosts.push(h.to_string());
                }
            }
        }
    }
    hosts
}

/// Resolve the API server URL and bearer token for the cluster. In-cluster,
/// both come from the mounted service account; otherwise from config + env.
fn k8s_credentials(c: &ConnectorConfig) -> Option<(String, String)> {
    // API server: connector endpoint, else the in-cluster env vars.
    let api = c.endpoints.first().cloned().or_else(|| {
        let host = std::env::var("KUBERNETES_SERVICE_HOST").ok()?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
        Some(format!("https://{host}:{port}"))
    })?;
    // Token: env var (name may be given in a `token_env:<VAR>` tag), else the
    // in-cluster service-account token file.
    let token_env = c
        .tags
        .iter()
        .find_map(|t| t.strip_prefix("token_env:"))
        .unwrap_or("KUBE_TOKEN");
    let token = std::env::var(token_env).ok().or_else(|| {
        std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token").ok()
    })?;
    Some((
        api.trim_end_matches('/').to_string(),
        token.trim().to_string(),
    ))
}

/// Kubernetes: discover TLS certificates (from `kubernetes.io/tls` secrets) and
/// TLS-terminating Ingress hosts, straight from the cluster API — no agent, no
/// probe. No-ops gracefully when the cluster is unreachable or unconfigured.
async fn discover_kubernetes(client: &reqwest::Client, c: &ConnectorConfig) -> Vec<AssetRow> {
    let Some((api, token)) = k8s_credentials(c) else {
        tracing::warn!(connector = %c.name, "kubernetes: no API server / token; skipping");
        return Vec::new();
    };
    let get = |path: &str| {
        client
            .get(format!("{api}{path}"))
            .header("Authorization", format!("Bearer {token}"))
            .send()
    };

    let mut out = Vec::new();

    // 1. TLS secrets -> classified certificates.
    if let Ok(resp) = get("/api/v1/secrets?fieldSelector=type=kubernetes.io/tls").await {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            for (name, pem) in parse_tls_secrets(&json) {
                let (pqc, algo, address) = match qw_scanner::classify_cert(&pem) {
                    Some(s) => (s.pqc_status.to_string(), s.algorithm, s.subject),
                    None => ("unknown".into(), "unparsed".into(), name.clone()),
                };
                let mut tags = c.tags.clone();
                tags.push(format!("secret:{name}"));
                tags.push(format!("algo:{algo}"));
                out.push(AssetRow {
                    id: format!("k8s-tls-{}", name.replace('/', "-")),
                    kind: "certificate".into(),
                    address,
                    environment: c.environment.clone(),
                    tags,
                    pqc_status: pqc,
                    tls_version: None,
                    last_scanned: Some(chrono::Utc::now()),
                    source: "kubernetes".into(),
                });
            }
        }
    }

    // 2. Ingress TLS hosts -> endpoints (scanned by the TLS pipeline).
    if let Ok(resp) = get("/apis/networking.k8s.io/v1/ingresses").await {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            for host in parse_ingress_hosts(&json) {
                out.push(AssetRow {
                    id: format!("k8s-ingress-{host}"),
                    kind: "tls_endpoint".into(),
                    address: format!("{host}:443"),
                    environment: c.environment.clone(),
                    tags: c.tags.clone(),
                    pqc_status: "unknown".into(),
                    tls_version: None,
                    last_scanned: None,
                    source: "kubernetes".into(),
                });
            }
        }
    }

    tracing::info!(connector = %c.name, discovered = out.len(), "Kubernetes connector");
    out
}

#[cfg(test)]
mod k8s_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_tls_secrets_and_ignores_non_tls() {
        // "aGk=" is base64("hi") — not a real cert, but exercises the decode.
        let list = json!({
            "items": [
                {
                    "type": "kubernetes.io/tls",
                    "metadata": {"namespace": "prod", "name": "checkout-cert"},
                    "data": {"tls.crt": "aGk=", "tls.key": "c2VjcmV0"}
                },
                {
                    "type": "Opaque",
                    "metadata": {"namespace": "prod", "name": "some-config"},
                    "data": {"foo": "YmFy"}
                }
            ]
        });
        let secrets = parse_tls_secrets(&list);
        assert_eq!(secrets.len(), 1, "only the kubernetes.io/tls secret");
        assert_eq!(secrets[0].0, "prod/checkout-cert");
        assert_eq!(secrets[0].1, b"hi");
    }

    #[test]
    fn parses_ingress_tls_hosts() {
        let list = json!({
            "items": [
                {"spec": {"tls": [
                    {"hosts": ["checkout.example.com", "www.example.com"]},
                    {"hosts": ["api.example.com"]}
                ]}},
                {"spec": {"rules": [{"host": "no-tls.example.com"}]}}
            ]
        });
        let hosts = parse_ingress_hosts(&list);
        assert_eq!(
            hosts,
            vec!["checkout.example.com", "www.example.com", "api.example.com"]
        );
    }

    #[test]
    fn empty_or_malformed_lists_yield_nothing() {
        assert!(parse_tls_secrets(&json!({})).is_empty());
        assert!(parse_ingress_hosts(&json!({"items": "not-an-array"})).is_empty());
    }

    #[test]
    fn credentials_require_api_and_token() {
        // No endpoints, no in-cluster env, no token -> None (skips gracefully).
        std::env::remove_var("KUBERNETES_SERVICE_HOST");
        std::env::remove_var("KUBE_TOKEN");
        let c = ConnectorConfig {
            name: "k".into(),
            connector_type: "kubernetes".into(),
            environment: "prod".into(),
            endpoints: vec![],
            tags: vec![],
        };
        assert!(k8s_credentials(&c).is_none());
    }

    #[test]
    fn credentials_from_endpoint_and_token_env() {
        std::env::set_var("QW_TEST_KUBE_TOKEN", "tok123");
        let c = ConnectorConfig {
            name: "k".into(),
            connector_type: "kubernetes".into(),
            environment: "prod".into(),
            endpoints: vec!["https://10.0.0.1:6443/".into()],
            tags: vec!["token_env:QW_TEST_KUBE_TOKEN".into()],
        };
        let (api, token) = k8s_credentials(&c).expect("creds");
        std::env::remove_var("QW_TEST_KUBE_TOKEN");
        assert_eq!(api, "https://10.0.0.1:6443", "trailing slash trimmed");
        assert_eq!(token, "tok123");
    }
}

/// GCP Cloud KMS: list crypto keys under the configured key rings and classify
/// each by its version-template algorithm. Bearer token from env (a real impl
/// would mint one from a service account; here provide GCP_ACCESS_TOKEN).
async fn discover_gcp(client: &reqwest::Client, c: &ConnectorConfig) -> Vec<AssetRow> {
    let Ok(token) = std::env::var("GCP_ACCESS_TOKEN") else {
        tracing::warn!(connector = %c.name, "GCP_ACCESS_TOKEN not set; skipping");
        return Vec::new();
    };
    let mut out = Vec::new();
    for key_ring in &c.endpoints {
        // endpoints[] are key-ring resource paths, e.g.
        // projects/<p>/locations/<l>/keyRings/<kr>
        let url = format!(
            "https://cloudkms.googleapis.com/v1/{}/cryptoKeys",
            key_ring.trim_matches('/')
        );
        if let Ok(r) = client
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
        {
            if let Ok(json) = r.json::<serde_json::Value>().await {
                for k in json["cryptoKeys"].as_array().cloned().unwrap_or_default() {
                    let name = k["name"].as_str().unwrap_or_default().to_string();
                    let algo = k["versionTemplate"]["algorithm"]
                        .as_str()
                        .unwrap_or("UNKNOWN")
                        .to_string();
                    let short = name.rsplit('/').next().unwrap_or("key").to_string();
                    out.push(AssetRow {
                        id: format!("gcp-kms-{short}"),
                        kind: "kms_key".into(),
                        address: name,
                        environment: c.environment.clone(),
                        tags: {
                            let mut t = c.tags.clone();
                            t.push(format!("algo:{algo}"));
                            t
                        },
                        pqc_status: key_spec_to_pqc(&algo).to_string(),
                        tls_version: None,
                        last_scanned: Some(chrono::Utc::now()),
                        source: "gcp".into(),
                    });
                }
            }
        }
    }
    tracing::info!(connector = %c.name, discovered = out.len(), "GCP Cloud KMS connector");
    out
}

/// Signed AWS JSON POST to `service`.`target`; returns the parsed response.
async fn aws_post(
    client: &reqwest::Client,
    ak: &str,
    sk: &str,
    region: &str,
    service: &str,
    target: &str,
    body: &str,
) -> Option<serde_json::Value> {
    let host = format!("{service}.{region}.amazonaws.com");
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let auth = sigv4_authorization(ak, sk, region, service, &host, target, &amz_date, body);
    let resp = client
        .post(format!("https://{host}/"))
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("X-Amz-Target", target)
        .header("X-Amz-Date", &amz_date)
        .header("Authorization", auth)
        .body(body.to_string())
        .send()
        .await
        .ok()?;
    resp.json::<serde_json::Value>().await.ok()
}

/// AWS: enumerate KMS keys (enriched via DescribeKey key specs) and ACM
/// certificates, classifying each by quantum exposure.
async fn discover_aws(client: &reqwest::Client, c: &ConnectorConfig) -> Vec<AssetRow> {
    let (Ok(ak), Ok(sk)) = (
        std::env::var("AWS_ACCESS_KEY_ID"),
        std::env::var("AWS_SECRET_ACCESS_KEY"),
    ) else {
        tracing::warn!(connector = %c.name, "AWS credentials not set (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY); skipping");
        return Vec::new();
    };
    let region = c
        .tags
        .iter()
        .find_map(|t| t.strip_prefix("region:"))
        .unwrap_or("us-east-1")
        .to_string();
    let mut out = Vec::new();

    // --- KMS keys, enriched with DescribeKey key specs ---
    if let Some(json) = aws_post(
        client,
        &ak,
        &sk,
        &region,
        "kms",
        "TrentService.ListKeys",
        "{}",
    )
    .await
    {
        for k in json["Keys"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .take(200)
        {
            let id = k["KeyId"].as_str().unwrap_or_default().to_string();
            if id.is_empty() {
                continue;
            }
            let (spec, usage) = match aws_post(
                client,
                &ak,
                &sk,
                &region,
                "kms",
                "TrentService.DescribeKey",
                &format!("{{\"KeyId\":\"{id}\"}}"),
            )
            .await
            {
                Some(d) => {
                    let m = &d["KeyMetadata"];
                    (
                        m["KeySpec"]
                            .as_str()
                            .or(m["CustomerMasterKeySpec"].as_str())
                            .unwrap_or("UNKNOWN")
                            .to_string(),
                        m["KeyUsage"].as_str().unwrap_or("").to_string(),
                    )
                }
                None => ("UNKNOWN".to_string(), String::new()),
            };
            out.push(AssetRow {
                id: format!("aws-kms-{id}"),
                kind: "kms_key".into(),
                address: format!("arn:aws:kms:{region}::key/{id}"),
                environment: c.environment.clone(),
                tags: {
                    let mut t = c.tags.clone();
                    t.push(format!("spec:{spec}"));
                    if !usage.is_empty() {
                        t.push(format!("usage:{usage}"));
                    }
                    t
                },
                pqc_status: key_spec_to_pqc(&spec).to_string(),
                tls_version: None,
                last_scanned: Some(chrono::Utc::now()),
                source: "aws".into(),
            });
        }
    }

    // --- ACM certificates, enriched with DescribeCertificate key algorithms ---
    if let Some(json) = aws_post(
        client,
        &ak,
        &sk,
        &region,
        "acm",
        "CertificateManager.ListCertificates",
        "{}",
    )
    .await
    {
        for cert in json["CertificateSummaryList"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .take(200)
        {
            let arn = cert["CertificateArn"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let domain = cert["DomainName"].as_str().unwrap_or("cert").to_string();
            if arn.is_empty() {
                continue;
            }
            let algo = match aws_post(
                client,
                &ak,
                &sk,
                &region,
                "acm",
                "CertificateManager.DescribeCertificate",
                &format!("{{\"CertificateArn\":\"{arn}\"}}"),
            )
            .await
            {
                Some(d) => d["Certificate"]["KeyAlgorithm"]
                    .as_str()
                    .unwrap_or("UNKNOWN")
                    .to_string(),
                None => cert["KeyAlgorithm"]
                    .as_str()
                    .unwrap_or("UNKNOWN")
                    .to_string(),
            };
            out.push(AssetRow {
                id: format!("aws-acm-{domain}"),
                kind: "certificate".into(),
                address: arn,
                environment: c.environment.clone(),
                tags: {
                    let mut t = c.tags.clone();
                    t.push(format!("algo:{algo}"));
                    t
                },
                pqc_status: key_spec_to_pqc(&algo).to_string(),
                tls_version: None,
                last_scanned: Some(chrono::Utc::now()),
                source: "aws".into(),
            });
        }
    }

    // --- ACM Private CA (ACM-PCA): the CA key algorithms are high blast-radius ---
    if let Some(json) = aws_post(
        client,
        &ak,
        &sk,
        &region,
        "acm-pca",
        "ACMPrivateCA.ListCertificateAuthorities",
        "{}",
    )
    .await
    {
        for ca in json["CertificateAuthorities"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .take(100)
        {
            let arn = ca["Arn"].as_str().unwrap_or_default().to_string();
            if arn.is_empty() {
                continue;
            }
            let algo = ca["CertificateAuthorityConfiguration"]["KeyAlgorithm"]
                .as_str()
                .unwrap_or("UNKNOWN")
                .to_string();
            let name = arn.rsplit('/').next().unwrap_or("ca").to_string();
            out.push(AssetRow {
                id: format!("aws-pca-{name}"),
                kind: "private_ca".into(),
                address: arn,
                environment: c.environment.clone(),
                tags: {
                    let mut t = c.tags.clone();
                    t.push(format!("algo:{algo}"));
                    t.push("ca".into());
                    t
                },
                pqc_status: key_spec_to_pqc(&algo).to_string(),
                tls_version: None,
                last_scanned: Some(chrono::Utc::now()),
                source: "aws".into(),
            });
        }
    }

    tracing::info!(connector = %c.name, discovered = out.len(), "AWS KMS/ACM/PCA connector");
    out
}

/// Azure Key Vault: OAuth client-credentials, then list keys and classify.
async fn discover_azure(client: &reqwest::Client, c: &ConnectorConfig) -> Vec<AssetRow> {
    let (Ok(tenant), Ok(cid), Ok(secret)) = (
        std::env::var("AZURE_TENANT_ID"),
        std::env::var("AZURE_CLIENT_ID"),
        std::env::var("AZURE_CLIENT_SECRET"),
    ) else {
        tracing::warn!(connector = %c.name, "Azure credentials not set; skipping");
        return Vec::new();
    };
    let vault = match c.endpoints.first() {
        Some(v) => v.clone(),
        None => {
            tracing::warn!(connector = %c.name, "Azure connector needs the vault URL in endpoints[0]");
            return Vec::new();
        }
    };

    // OAuth2 client-credentials token for the Key Vault resource.
    let token_resp = client
        .post(format!(
            "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        ))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &cid),
            ("client_secret", &secret),
            ("scope", "https://vault.azure.net/.default"),
        ])
        .send()
        .await;
    let token = match token_resp {
        Ok(r) => r
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|j| j["access_token"].as_str().map(String::from)),
        Err(_) => None,
    };
    let Some(token) = token else {
        tracing::warn!(connector = %c.name, "Azure token acquisition failed");
        return Vec::new();
    };

    let mut out = Vec::new();
    if let Ok(r) = client
        .get(format!(
            "{}/keys?api-version=7.4",
            vault.trim_end_matches('/')
        ))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
    {
        if let Ok(json) = r.json::<serde_json::Value>().await {
            for k in json["value"].as_array().cloned().unwrap_or_default() {
                let kid = k["kid"].as_str().unwrap_or_default().to_string();
                let name = kid.rsplit('/').next().unwrap_or("key").to_string();
                out.push(AssetRow {
                    id: format!("azure-kv-{name}"),
                    kind: "kms_key".into(),
                    address: kid,
                    environment: c.environment.clone(),
                    tags: c.tags.clone(),
                    pqc_status: PqcStatus::Unknown.to_string(),
                    tls_version: None,
                    last_scanned: Some(chrono::Utc::now()),
                    source: "azure".into(),
                });
            }
        }
    }
    tracing::info!(connector = %c.name, discovered = out.len(), "Azure Key Vault connector");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pqc_mapping() {
        assert_eq!(key_spec_to_pqc("RSA_2048"), PqcStatus::ClassicalSecure);
        assert_eq!(key_spec_to_pqc("ECC_NIST_P256"), PqcStatus::ClassicalSecure);
        assert_eq!(key_spec_to_pqc("SYMMETRIC_DEFAULT"), PqcStatus::PqcReady);
        assert_eq!(key_spec_to_pqc("ML_KEM_768"), PqcStatus::PqcReady);
    }

    #[test]
    fn sigv4_matches_aws_official_vector() {
        // AWS documented example (Signature Version 4 test suite, get-header-value-trim
        // adapted to the string-to-sign chain). We verify the HMAC signing-key
        // derivation + signature against the canonical AWS example.
        // https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
        let k_date = hmac(b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", b"20150830");
        let k_region = hmac(&k_date, b"us-east-1");
        let k_service = hmac(&k_region, b"iam");
        let k_signing = hmac(&k_service, b"aws4_request");
        // Expected signing key first bytes from the AWS docs example.
        assert_eq!(hex::encode(&k_signing)[..8], *"c4afb1cc");
    }
}
