use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "qw",
    about = "QuantaWatch CLI - Post-quantum security for AI agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify audit chain integrity
    Verify {
        /// Path to audit log file or directory
        #[arg(default_value = "./audit/audit.jsonl")]
        path: PathBuf,

        /// Path to gateway public key
        #[arg(long, default_value = "./keys/gateway_public.key")]
        public_key: PathBuf,
    },
    /// Inspect an audit log file (print entries as formatted JSON)
    Inspect {
        /// Path to audit log file
        #[arg(default_value = "./audit/audit.jsonl")]
        path: PathBuf,

        /// Show only the last N entries
        #[arg(short = 'n', long)]
        last: Option<usize>,

        /// Filter by session ID
        #[arg(long)]
        session: Option<String>,

        /// Filter by event type
        #[arg(long)]
        event_type: Option<String>,
    },
    /// Generate PQC key pair
    Keygen {
        /// Output directory for keys
        #[arg(short, long, default_value = "./keys")]
        output: PathBuf,
    },
    /// Scan a target for cryptographic assets and PQC readiness
    Scan {
        /// What to scan: tls, deps, code, or cert
        kind: String,
        /// Target: host[:port] for tls, file path for deps/cert, directory for code
        target: String,
    },
    /// Compute cryptographic posture score for a directory
    Posture {
        /// Directory to assess (scans dependency files and source code)
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Export a CycloneDX CBOM for a directory
    Cbom {
        #[command(subcommand)]
        action: CbomAction,
    },
    /// Hash a password (Argon2id) or generate an API key for the auth config
    HashPassword {
        /// The password to hash (omit when using --api-key)
        password: Option<String>,
        /// Generate a random API key and print it with its config hash
        #[arg(long)]
        api_key: bool,
        /// Minimum password length policy (SOC2 CC6.1). Default 12.
        #[arg(long, default_value_t = 12)]
        min_length: usize,
        /// Bypass the minimum-length policy (not recommended).
        #[arg(long)]
        allow_weak: bool,
    },
    /// Independently verify a QuantaWatch evidence pack's ML-DSA-65 signature
    VerifyEvidence {
        /// Path to the evidence pack JSON
        path: PathBuf,
    },
    /// Verify a CBOM's embedded ML-DSA-65 attestation quote
    VerifyAttestation {
        /// Path to the CBOM JSON (from /api/cbom or /api/cbom/download)
        path: PathBuf,
    },
    /// Sign a file with ML-DSA-65 (post-quantum). Signs the file's SHA3-256
    /// digest; writes a hex signature and prints the signer's public key.
    Sign {
        /// File to sign
        path: PathBuf,
        /// Directory holding the signing identity (gateway_seed.key)
        #[arg(long, default_value = "./keys")]
        key_dir: PathBuf,
        /// ENV var holding a hex 32-byte seed (overrides key_dir; use in CI)
        #[arg(long)]
        seed_env: Option<String>,
        /// Output path for the signature (defaults to <path>.sig)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Also write the signer's public key here (publish it as the trust anchor)
        #[arg(long)]
        pubkey_out: Option<PathBuf>,
    },
    /// Verify an ML-DSA-65 signature over a file, against a published public key.
    VerifyFile {
        /// File that was signed
        path: PathBuf,
        /// Signature file (hex). Defaults to <path>.sig
        #[arg(long)]
        signature: Option<PathBuf>,
        /// Public key file (hex or raw bytes) — the release trust anchor
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Show version and build info
    Version,
}

#[derive(Subcommand)]
enum CbomAction {
    /// Scan a directory and export a CBOM document
    Export {
        /// Directory to inventory
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Output file (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Inventory dependency manifests only, skipping the source-code
        /// scanner. Use this for a *self*-CBOM of a crypto project: the code
        /// scanner would otherwise match the project's own detection patterns
        /// and test fixtures as false positives.
        #[arg(long)]
        deps_only: bool,
        /// Recurse into subdirectories to find every manifest (skips
        /// target/, node_modules/, .git/).
        #[arg(long)]
        recursive: bool,
        /// Emit byte-reproducible output: stable ordering, content-derived
        /// identifiers, pinned timestamps, and normalized paths. Use this for a
        /// CBOM you commit, so CI can detect drift by diffing it.
        #[arg(long)]
        deterministic: bool,
    },
}

fn main() -> Result<()> {
    // ML-DSA-65 / ML-KEM-768 keygen and signing use large stack arrays that can
    // overflow the OS main-thread stack (~1 MB on Windows). RUST_MIN_STACK only
    // affects spawned threads, not `main`, so run the whole CLI on a thread with
    // a generous stack.
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(16 * 1024 * 1024)
                .build()?
                .block_on(async_main())
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("CLI thread panicked"))?
}

/// Load an audit export for verification: either a JSON bundle
/// `{"entries":[...],"checkpoints":[...]}` (from `GET /api/audit/export?format=bundle`)
/// or a JSONL file of raw `AuditEntry` records (checkpoints empty — each
/// per-writer chain still verifies, just without the global anchor).
fn load_audit_export(
    path: &std::path::Path,
) -> Result<(Vec<qw_audit::AuditEntry>, Vec<qw_audit::AuditCheckpoint>)> {
    let content = std::fs::read_to_string(path)?;
    if content.trim_start().starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(&content)?;
        let empty = serde_json::Value::Array(Vec::new());
        let entries = serde_json::from_value(v.get("entries").cloned().unwrap_or(empty.clone()))?;
        let checkpoints = serde_json::from_value(v.get("checkpoints").cloned().unwrap_or(empty))?;
        Ok((entries, checkpoints))
    } else {
        let entries = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<qw_audit::AuditEntry>(l).ok())
            .collect();
        Ok((entries, Vec::new()))
    }
}

async fn async_main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Verify { path, public_key } => {
            println!("QuantaWatch Audit Verifier");
            println!("========================");
            println!("Log:    {}", path.display());
            println!("Key:    {}", public_key.display());
            println!();

            let pk_bytes = std::fs::read(&public_key)?;
            let (entries, checkpoints) = load_audit_export(&path)?;
            let result = qw_audit::verify_sharded(&entries, &checkpoints, &pk_bytes);

            if result.valid {
                println!("VERIFIED");
                println!("  Entries checked:    {}", result.entries_checked);
                println!("  Writers checked:    {}", result.writers_checked);
                println!("  Checkpoints checked:{}", result.checkpoints_checked);
                println!("  Signatures valid:   {}", result.signatures_valid);
                println!("  Chain intact:       {}", result.chain_intact);
                println!("  Merkle roots valid: {}", result.merkle_roots_valid);
            } else {
                println!("VERIFICATION FAILED");
                println!("  Entries checked:  {}", result.entries_checked);
                println!("  Writers checked:  {}", result.writers_checked);
                println!("  Signatures valid: {}", result.signatures_valid);
                println!("  Chain intact:     {}", result.chain_intact);
                for error in &result.errors {
                    println!("  ERROR: {error}");
                }
                std::process::exit(1);
            }
        }
        Commands::Inspect {
            path,
            last,
            session,
            event_type,
        } => {
            println!("QuantaWatch Audit Inspector");
            println!("==========================");
            println!("Log: {}", path.display());
            println!();

            let content = std::fs::read_to_string(&path)?;
            let mut entries: Vec<serde_json::Value> = content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();

            // Apply filters
            if let Some(ref sid) = session {
                entries.retain(|e| {
                    e.get("session_id")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| s.contains(sid.as_str()))
                });
            }
            if let Some(ref et) = event_type {
                entries.retain(|e| {
                    e.get("event")
                        .and_then(|v| v.as_str())
                        .or_else(|| e.get("event_type").and_then(|v| v.as_str()))
                        .is_some_and(|s| s.eq_ignore_ascii_case(et))
                });
            }

            // Take last N
            if let Some(n) = last {
                let skip = entries.len().saturating_sub(n);
                entries = entries.into_iter().skip(skip).collect();
            }

            if entries.is_empty() {
                println!("No matching entries found.");
            } else {
                println!("Showing {} entries:\n", entries.len());
                for entry in &entries {
                    println!("{}", serde_json::to_string_pretty(entry)?);
                    println!("---");
                }
            }
        }
        Commands::Keygen { output } => {
            println!("Generating ML-DSA-65 key pair...");
            let identity = qw_crypto::GatewayIdentity::load_or_generate(&output)?;
            println!("Keys written to: {}", output.display());
            println!("Fingerprint: {}", identity.fingerprint);
        }
        Commands::Scan { kind, target } => {
            let results = run_scan(&kind, &target).await?;
            print_findings(&results);
        }
        Commands::Posture { path } => {
            let results = scan_directory(&path, false, false).await?;
            let summary = qw_cbom::PostureEngine::summarize(&results, &[]);
            print_posture(&summary);
        }
        Commands::Cbom { action } => match action {
            CbomAction::Export {
                path,
                output,
                deps_only,
                recursive,
                deterministic,
            } => {
                // Dedupe before scoring so the posture summary describes exactly
                // the components the document lists (a library used by ten
                // crates is one library, not ten).
                let results = qw_cbom::dedupe_scan_results(
                    &scan_directory(&path, deps_only, recursive).await?,
                );
                let summary = qw_cbom::PostureEngine::summarize(&results, &[]);
                let mut builder = qw_cbom::CbomBuilder::new();
                builder.ingest_scan_results(&results);
                let mut cbom = builder.build_with_posture("cli", summary);
                if deterministic {
                    qw_cbom::make_deterministic(&mut cbom);
                }
                let json = serde_json::to_string_pretty(&cbom)?;
                match output {
                    Some(out) => {
                        std::fs::write(&out, &json)?;
                        println!("CBOM written to {}", out.display());
                    }
                    None => println!("{json}"),
                }
            }
        },
        Commands::HashPassword {
            password,
            api_key,
            min_length,
            allow_weak,
        } => {
            if api_key {
                let key = format!("qw_{}", qw_crypto::random_token(24));
                let hash = qw_crypto::sha3_256_hex(key.as_bytes());
                println!("API key (give this to the client, store it nowhere else):");
                println!("  {key}");
                println!("\nConfig entry (quantawatch.yaml under auth.api_keys):");
                println!("  - name: my-key");
                println!("    key_hash: \"{hash}\"");
                println!("    role: operator");
            } else {
                let password = password
                    .ok_or_else(|| anyhow::anyhow!("provide a password, or use --api-key"))?;
                if !allow_weak && password.chars().count() < min_length {
                    return Err(anyhow::anyhow!(
                        "password is {} chars; policy requires at least {min_length} \
                         (override with --allow-weak, or set --min-length)",
                        password.chars().count()
                    ));
                }
                let hash =
                    qw_crypto::hash_password(&password).map_err(|e| anyhow::anyhow!("{e}"))?;
                println!("Config entry (quantawatch.yaml under auth.users):");
                println!("  - username: admin");
                println!("    password_hash: \"{hash}\"");
                println!("    role: admin");
            }
        }
        Commands::VerifyEvidence { path } => {
            println!("QuantaWatch Evidence Pack Verifier");
            println!("==================================");
            let content = std::fs::read_to_string(&path)?;
            let pack: serde_json::Value = serde_json::from_str(&content)?;
            let body = pack
                .get("evidencePack")
                .ok_or_else(|| anyhow::anyhow!("missing 'evidencePack'"))?;
            let sig = pack
                .get("signature")
                .ok_or_else(|| anyhow::anyhow!("missing 'signature'"))?;

            let claimed_digest = sig["digest"].as_str().unwrap_or_default();
            let pubkey = hex::decode(sig["publicKey"].as_str().unwrap_or_default())
                .map_err(|_| anyhow::anyhow!("bad publicKey hex"))?;
            let signature = hex::decode(sig["value"].as_str().unwrap_or_default())
                .map_err(|_| anyhow::anyhow!("bad signature hex"))?;

            // Recompute the digest over the canonical body exactly as the gateway did.
            let canonical = serde_json::to_vec(body)?;
            let digest = qw_crypto::sha3_256_hex(&canonical);
            let digest_ok = digest == claimed_digest;
            let sig_ok = qw_crypto::verify(&pubkey, digest.as_bytes(), &signature).unwrap_or(false);

            println!(
                "  Tenant:        {}",
                body["tenant"].as_str().unwrap_or("?")
            );
            println!(
                "  Generated:     {}",
                body["generatedAt"].as_str().unwrap_or("?")
            );
            println!(
                "  Signer (fp):   {}",
                body["gatewayFingerprint"].as_str().unwrap_or("?")
            );
            println!(
                "  Algorithm:     {}",
                sig["algorithm"].as_str().unwrap_or("?")
            );
            println!(
                "  Attack paths:  {} ({} critical)",
                body["attackPaths"]["total"].as_u64().unwrap_or(0),
                body["attackPaths"]["critical"].as_u64().unwrap_or(0)
            );
            println!(
                "  Audit chain:   valid={}",
                body["auditChain"]["valid"].as_bool().unwrap_or(false)
            );
            println!();
            println!(
                "  Digest match:  {}",
                if digest_ok { "OK" } else { "MISMATCH" }
            );
            println!(
                "  Signature:     {}",
                if sig_ok {
                    "VALID (ML-DSA-65)"
                } else {
                    "INVALID"
                }
            );
            println!();
            if digest_ok && sig_ok {
                println!("VERIFIED — this evidence pack is authentic and unmodified.");
            } else {
                println!(
                    "VERIFICATION FAILED — the pack has been tampered with or is not authentic."
                );
                std::process::exit(1);
            }
        }
        Commands::VerifyAttestation { path } => {
            println!("QuantaWatch CBOM Attestation Verifier");
            println!("=====================================");
            let content = std::fs::read_to_string(&path)?;
            let mut cbom: serde_json::Value = serde_json::from_str(&content)?;
            let att = cbom
                .as_object_mut()
                .and_then(|o| o.remove("x-quantawatch-attestation"))
                .ok_or_else(|| anyhow::anyhow!("CBOM has no attestation"))?;

            let claimed_digest = att["bomDigest"].as_str().unwrap_or_default();
            let nonce = att["nonce"].as_str().unwrap_or_default();
            let pubkey = hex::decode(att["publicKey"].as_str().unwrap_or_default())
                .map_err(|_| anyhow::anyhow!("bad publicKey hex"))?;
            let signature = hex::decode(att["signature"].as_str().unwrap_or_default())
                .map_err(|_| anyhow::anyhow!("bad signature hex"))?;

            // Recompute the BOM digest over the CBOM *without* the attestation
            // (which is exactly how the gateway computed it).
            let canonical = serde_json::to_vec(&cbom)?;
            let recomputed = qw_crypto::sha3_256_hex(&canonical);
            let digest_ok = recomputed == claimed_digest;

            // Reconstruct the signed quote payload: digest|nonce|name=value;...
            let measure_str = att["measurements"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|m| {
                    format!(
                        "{}={}",
                        m["name"].as_str().unwrap_or(""),
                        m["value"].as_str().unwrap_or("")
                    )
                })
                .collect::<Vec<_>>()
                .join(";");
            let quote = format!("{claimed_digest}|{nonce}|{measure_str}");
            let sig_ok = qw_crypto::verify(&pubkey, quote.as_bytes(), &signature).unwrap_or(false);

            // If the attestation carries a certificate chain (hardware-rooted
            // providers), verify it chains the quote-signing key up to a
            // self-signed root. Software attestations have no chain.
            let ak_hex = att["publicKey"].as_str().unwrap_or_default();
            let chain_result: Option<Result<String, String>> = att
                .get("certChain")
                .and_then(|c| c.as_array())
                .filter(|a| !a.is_empty())
                .map(|_| {
                    let chain: Vec<qw_cbom::AttestationCert> =
                        serde_json::from_value(att["certChain"].clone()).unwrap_or_default();
                    qw_cbom::verify_cert_chain(&chain, ak_hex)
                });
            let chain_ok = !matches!(chain_result, Some(Err(_)));

            println!(
                "  Type:          {}",
                att["attestationType"].as_str().unwrap_or("?")
            );
            println!(
                "  Algorithm:     {}",
                att["algorithm"].as_str().unwrap_or("?")
            );
            println!(
                "  Signer (fp):   {}",
                att["signerFingerprint"].as_str().unwrap_or("?")
            );
            println!("  Measurements:  {measure_str}");
            println!();
            println!(
                "  BOM digest:    {}",
                if digest_ok {
                    "OK (CBOM unmodified)"
                } else {
                    "MISMATCH"
                }
            );
            println!(
                "  Quote sig:     {}",
                if sig_ok {
                    "VALID (ML-DSA-65)"
                } else {
                    "INVALID"
                }
            );
            match &chain_result {
                None => println!("  Trust chain:   none (software self-attested)"),
                Some(Ok(root)) => println!(
                    "  Trust chain:   VALID — rooted at {}",
                    &root[..root.len().min(16)]
                ),
                Some(Err(e)) => println!("  Trust chain:   INVALID — {e}"),
            }
            println!();
            if digest_ok && sig_ok && chain_ok {
                let rooted = matches!(chain_result, Some(Ok(_)));
                if rooted {
                    println!(
                        "VERIFIED — the CBOM is authentically attested, unmodified, and rooted in a \
                         trusted attestation chain."
                    );
                } else {
                    println!("VERIFIED — the CBOM is authentically attested and unmodified.");
                }
            } else {
                println!("VERIFICATION FAILED.");
                std::process::exit(1);
            }
        }
        Commands::Sign {
            path,
            key_dir,
            seed_env,
            output,
            pubkey_out,
        } => {
            // Load the signing identity. Never silently generate one for signing:
            // a throwaway key produces a signature nobody can verify.
            let identity = match seed_env {
                Some(var) => {
                    // Strict: --seed-env means "use this seed". An unset or
                    // malformed var is an error, not a cue to mint a random key.
                    let seed_hex = std::env::var(&var)
                        .map_err(|_| anyhow::anyhow!("--seed-env {var} is not set"))?;
                    let raw = hex::decode(seed_hex.trim())
                        .map_err(|_| anyhow::anyhow!("${var} is not valid hex"))?;
                    let seed: [u8; 32] = raw
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("${var} must decode to 32 bytes"))?;
                    qw_crypto::GatewayIdentity::from_seed(&seed)
                        .map_err(|e| anyhow::anyhow!("{e}"))?
                }
                None => {
                    if !key_dir.join("gateway_seed.key").exists() {
                        anyhow::bail!(
                            "no signing key at {}/gateway_seed.key — run `qw keygen` or pass --seed-env",
                            key_dir.display()
                        );
                    }
                    qw_crypto::GatewayIdentity::load_or_generate(&key_dir)
                        .map_err(|e| anyhow::anyhow!("{e}"))?
                }
            };

            let bytes = std::fs::read(&path)?;
            let digest = qw_crypto::sha3_256(&bytes);
            let sig = identity
                .sign(&digest)
                .map_err(|e| anyhow::anyhow!("signing failed: {e}"))?;

            let sig_path = output.unwrap_or_else(|| path.with_extension("sig"));
            std::fs::write(&sig_path, hex::encode(&sig))?;

            let pubkey = identity.public_key_bytes();
            if let Some(pk_path) = pubkey_out {
                std::fs::write(&pk_path, hex::encode(&pubkey))?;
                println!("Public key written to {}", pk_path.display());
            }

            println!("Signed {} with ML-DSA-65 (FIPS 204).", path.display());
            println!("  Digest (SHA3-256): {}", hex::encode(digest));
            println!("  Signature:         {}", sig_path.display());
            println!("  Signer public key: {}", hex::encode(&pubkey));
            println!("  Signer fingerprint: {}", identity.fingerprint);
        }
        Commands::VerifyFile {
            path,
            signature,
            public_key,
        } => {
            println!("QuantaWatch File Signature Verifier");
            println!("===================================");

            let sig_path = signature.unwrap_or_else(|| path.with_extension("sig"));
            let sig = hex::decode(std::fs::read_to_string(&sig_path)?.trim())
                .map_err(|_| anyhow::anyhow!("signature file is not valid hex"))?;

            // Accept the public key as hex text or raw bytes.
            let pk_raw = std::fs::read(&public_key)?;
            let pubkey = match hex::decode(String::from_utf8_lossy(&pk_raw).trim()) {
                Ok(b) if b.len() == 1952 => b, // ML-DSA-65 verifying key length
                _ => pk_raw,
            };

            let bytes = std::fs::read(&path)?;
            let digest = qw_crypto::sha3_256(&bytes);
            let ok = qw_crypto::verify(&pubkey, &digest, &sig).unwrap_or(false);

            println!("  File:        {}", path.display());
            println!("  Signature:   {}", sig_path.display());
            println!("  Public key:  {}", public_key.display());
            println!("  Digest:      {}", hex::encode(digest));
            println!();
            if ok {
                println!("VERIFIED — the file is authentic and unmodified (ML-DSA-65).");
            } else {
                println!("VERIFICATION FAILED — wrong key, or the file/signature was modified.");
                std::process::exit(1);
            }
        }
        Commands::Version => {
            println!("QuantaWatch CLI v{}", env!("CARGO_PKG_VERSION"));
            println!("PQC: ML-DSA-65 (FIPS 204), ML-KEM-768 (FIPS 203)");
            println!("Hash: SHA3-256");
        }
    }

    Ok(())
}

/// Build a scanner registry with every scanner enabled.
fn all_scanners() -> qw_scanner::ScannerRegistry {
    let mut config = qw_scanner::ScannerConfig::default();
    config.code.enabled = true;
    qw_scanner::build_scanner_registry(&config)
}

/// Run a single scan of the given kind against the target.
async fn run_scan(kind: &str, target: &str) -> Result<Vec<qw_scanner::ScanResult>> {
    let registry = all_scanners();
    let scan_target = match kind {
        "tls" => qw_scanner::ScanTarget::tls(target),
        "deps" | "dependency" => qw_scanner::ScanTarget::dependency_file(target),
        "code" => qw_scanner::ScanTarget::code_directory(target),
        "cert" | "certificate" => qw_scanner::ScanTarget::certificate(target),
        other => anyhow::bail!("Unknown scan kind '{other}' (expected: tls, deps, code, cert)"),
    };
    Ok(registry.scan_all(&scan_target).await)
}

/// Scan a directory: every dependency manifest plus the source tree.
const MANIFESTS: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "requirements.txt",
    "go.mod",
    "pom.xml",
    "Gemfile",
    "composer.json",
];

/// Collect dependency-manifest paths under `dir`. When `recursive`, walk the
/// tree (bounded depth), skipping build/output/VCS directories that only
/// contain vendored or generated files.
fn collect_manifests(
    dir: &std::path::Path,
    recursive: bool,
    depth: usize,
    out: &mut Vec<std::path::PathBuf>,
) {
    for name in MANIFESTS {
        let p = dir.join(name);
        if p.is_file() {
            out.push(p);
        }
    }
    if !recursive || depth == 0 {
        return;
    }
    let skip = [
        "target",
        "node_modules",
        ".git",
        "dist",
        ".vite",
        "__pycache__",
    ];
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let base = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if skip.contains(&base) || base.starts_with('.') {
                    continue;
                }
                collect_manifests(&path, recursive, depth - 1, out);
            }
        }
    }
}

async fn scan_directory(
    dir: &std::path::Path,
    deps_only: bool,
    recursive: bool,
) -> Result<Vec<qw_scanner::ScanResult>> {
    let registry = all_scanners();
    let mut results = Vec::new();

    let mut manifests = Vec::new();
    collect_manifests(dir, recursive, 8, &mut manifests);
    for p in manifests {
        let t = qw_scanner::ScanTarget::dependency_file(&p.to_string_lossy());
        results.extend(registry.scan_all(&t).await);
    }

    // The code scanner matches crypto patterns in source. For a *self*-CBOM of
    // a crypto project it produces false positives (the project's own detection
    // regexes and test fixtures), so deps_only skips it.
    if !deps_only {
        let code_target = qw_scanner::ScanTarget::code_directory(&dir.to_string_lossy());
        results.extend(registry.scan_all(&code_target).await);
    }

    Ok(results)
}

fn print_findings(results: &[qw_scanner::ScanResult]) {
    let total: usize = results.iter().map(|r| r.findings.len()).sum();
    println!("QuantaWatch Scan Results");
    println!("========================");
    println!("Scanners run: {}", results.len());
    println!("Findings:     {total}\n");

    for result in results {
        if let Some(err) = &result.error {
            println!("[{}] ERROR: {err}", result.scanner_id);
            continue;
        }
        for f in &result.findings {
            let loc = f
                .asset
                .location
                .line
                .map(|l| format!("{}:{}", f.asset.location.path, l))
                .unwrap_or_else(|| f.asset.location.path.clone());
            println!("[{:?}] {} ({})", f.severity, f.title, f.pqc_status);
            println!("    {loc}");
        }
    }
}

fn print_posture(summary: &qw_cbom::PostureSummary) {
    println!("QuantaWatch Cryptographic Posture");
    println!("=================================");
    println!("Overall score: {:.1} / 100", summary.overall_score);
    println!("Total assets:  {}\n", summary.total_assets);

    println!("By category:");
    for cat in &summary.by_category {
        println!(
            "  {:<20} {:.1}  ({} assets)",
            cat.category, cat.score, cat.asset_count
        );
    }

    if !summary.by_status.is_empty() {
        println!("\nBy PQC status:");
        for (status, count) in &summary.by_status {
            println!("  {status:<18} {count}");
        }
    }
}
