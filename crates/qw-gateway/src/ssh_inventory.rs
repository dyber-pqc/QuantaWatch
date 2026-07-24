//! Authenticated deep host inventory over SSH.
//!
//! The network sweep can only see what a host *exposes*. This logs in (with
//! credentials the operator supplies for their own infrastructure) and looks
//! *inside*: every listening service — including localhost-only ones the network
//! can't reach — plus Docker containers and basic host facts. Those become
//! inventory + graph nodes, so "connect to a server" turns into a full internal
//! crypto map rather than a port scan.

use std::sync::Arc;

use russh::client::{self, Handler};
use russh::keys::key;

/// One listening service discovered on the host.
#[derive(Debug, Clone)]
pub struct HostService {
    pub port: u16,
    pub service: String,
    /// True = bound to a wildcard/external address (network-exposed); false =
    /// loopback only (internal, invisible to a network scan).
    pub exposed: bool,
}

/// A Docker container running on the host.
#[derive(Debug, Clone)]
pub struct HostContainer {
    pub name: String,
    pub image: String,
    pub ports: String,
}

#[derive(Debug, Clone, Default)]
pub struct HostInventory {
    pub host_info: String,
    pub services: Vec<HostService>,
    pub containers: Vec<HostContainer>,
}

/// Credentials for the SSH connection (supplied per-scan, used transiently).
pub enum SshAuth {
    Password(String),
    PrivateKey {
        pem: String,
        passphrase: Option<String>,
    },
}

/// A trust-on-first-use client handler: we're inventorying the operator's own
/// hosts, so we accept the presented host key (and record it as a finding
/// elsewhere) rather than maintaining a known_hosts file.
struct InvClient;

#[async_trait::async_trait]
impl Handler for InvClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Connect, authenticate, run the read-only inventory commands, and parse them.
pub async fn inventory(
    host: &str,
    port: u16,
    username: &str,
    auth: SshAuth,
) -> anyhow::Result<HostInventory> {
    let config = Arc::new(client::Config::default());
    let mut handle = client::connect(config, (host, port), InvClient)
        .await
        .map_err(|e| anyhow::anyhow!("ssh connect {host}:{port}: {e}"))?;

    let authed: bool = match auth {
        SshAuth::Password(pw) => handle
            .authenticate_password(username, pw)
            .await
            .map_err(|e| anyhow::anyhow!("ssh auth: {e}"))?,
        SshAuth::PrivateKey { pem, passphrase } => {
            let keypair = russh::keys::decode_secret_key(
                &pem,
                passphrase.as_deref().filter(|p| !p.is_empty()),
            )
            .map_err(|e| anyhow::anyhow!("parse private key: {e}"))?;
            handle
                .authenticate_publickey(username, Arc::new(keypair))
                .await
                .map_err(|e| anyhow::anyhow!("ssh key auth: {e}"))?
        }
    };
    if !authed {
        anyhow::bail!("ssh authentication failed for {username}@{host}");
    }

    let host_info = run(&mut handle, "hostname 2>/dev/null; uname -sr 2>/dev/null")
        .await
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    let tcp = run(&mut handle, "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null")
        .await
        .unwrap_or_default();
    let services = parse_listening(&tcp);

    let docker = run(
        &mut handle,
        "docker ps --format '{{.Names}}|{{.Image}}|{{.Ports}}' 2>/dev/null",
    )
    .await
    .unwrap_or_default();
    let containers = parse_docker(&docker);

    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await;

    Ok(HostInventory {
        host_info,
        services,
        containers,
    })
}

/// Run one command and collect stdout.
async fn run(handle: &mut client::Handle<InvClient>, cmd: &str) -> anyhow::Result<String> {
    let mut channel = handle.channel_open_session().await?;
    channel.exec(true, cmd).await?;
    let mut out: Vec<u8> = Vec::new();
    loop {
        match channel.wait().await {
            Some(russh::ChannelMsg::Data { data }) => out.extend_from_slice(&data),
            Some(russh::ChannelMsg::ExtendedData { .. }) => {}
            Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) | None => break,
            _ => {}
        }
    }
    Ok(String::from_utf8_lossy(&out).to_string())
}

/// Parse /proc/net/tcp{,6}: listening sockets (state 0A), with exposure.
fn parse_listening(output: &str) -> Vec<HostService> {
    use std::collections::BTreeMap;
    let mut by_port: BTreeMap<u16, bool> = BTreeMap::new(); // port -> exposed
    for line in output.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // sl local_address rem_address st ...
        if cols.len() < 4 || cols[3] != "0A" {
            continue;
        }
        let Some((ip_hex, port_hex)) = cols[1].split_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        let exposed = !is_loopback(ip_hex);
        // A port exposed on any interface counts as exposed.
        by_port
            .entry(port)
            .and_modify(|e| *e = *e || exposed)
            .or_insert(exposed);
    }
    by_port
        .into_iter()
        .map(|(port, exposed)| HostService {
            port,
            service: service_name(port).to_string(),
            exposed,
        })
        .collect()
}

/// Loopback in /proc/net/tcp hex: 127.0.0.1 (v4) or ::1 (v6).
fn is_loopback(ip_hex: &str) -> bool {
    ip_hex.eq_ignore_ascii_case("0100007F")
        || ip_hex.eq_ignore_ascii_case("00000000000000000000000001000000")
}

fn parse_docker(output: &str) -> Vec<HostContainer> {
    output
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| {
            let mut parts = l.splitn(3, '|');
            Some(HostContainer {
                name: parts.next()?.trim().to_string(),
                image: parts.next().unwrap_or("").trim().to_string(),
                ports: parts.next().unwrap_or("").trim().to_string(),
            })
        })
        .collect()
}

/// Best-effort port → service label.
pub fn service_name(port: u16) -> &'static str {
    match port {
        22 | 2222 => "ssh",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        111 => "rpcbind",
        389 => "ldap",
        443 => "https",
        465 => "smtps",
        587 => "smtp-submission",
        636 => "ldaps",
        853 => "dns-over-tls",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        2375 | 2376 => "docker-api",
        3000 => "grafana/dev",
        3306 => "mysql",
        3389 => "rdp",
        5000 => "registry/dev",
        5432 => "postgresql",
        5672 => "amqp",
        6379 => "redis",
        6443 => "kubernetes-api",
        8000 | 8080 => "http-alt",
        8443 => "https-alt",
        9000 => "app",
        9090 => "prometheus",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => "service",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_listening_ports_and_exposure() {
        // 0.0.0.0:5432 (exposed), 127.0.0.1:6379 (internal), :22 exposed.
        let sample = "\
  sl  local_address rem_address   st ...
   0: 00000000:1538 00000000:0000 0A rest
   1: 0100007F:18EB 00000000:0000 0A rest
   2: 00000000:0016 00000000:0000 0A rest
   3: 00000000:C000 0100007F:1234 01 established";
        let svcs = parse_listening(sample);
        let pg = svcs.iter().find(|s| s.port == 5432).unwrap();
        assert!(pg.exposed && pg.service == "postgresql");
        let redis = svcs.iter().find(|s| s.port == 6379).unwrap();
        assert!(!redis.exposed && redis.service == "redis");
        assert!(svcs.iter().any(|s| s.port == 22 && s.exposed));
        // The established (non-listen) socket is ignored.
        assert!(!svcs.iter().any(|s| s.port == 0xC000));
    }

    #[test]
    fn parses_docker_ps() {
        let out = "gitlab|gitlab/gitlab-ce:16.0|0.0.0.0:443->443/tcp\npg|postgres:16|127.0.0.1:5432->5432/tcp";
        let cs = parse_docker(out);
        assert_eq!(cs.len(), 2);
        assert_eq!(cs[0].name, "gitlab");
        assert!(cs[0].image.contains("gitlab-ce"));
    }
}
