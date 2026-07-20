//! Fine-grained, permission-based RBAC.
//!
//! Each admin route maps to a permission of the form `resource:action` (action
//! is `read` or `write`). The four built-in roles are permission bundles, and
//! `auth.roles` in config can define CUSTOM roles as explicit permission lists
//! (with `*` wildcards) for least-privilege access.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::http::Method;

/// Resources covered by the general read/write bundles. `config` is deliberately
/// excluded — it is admin-only (only the `*` bundle grants `config:*`).
pub const RBAC_RESOURCES: &[&str] = &[
    "scans",
    "findings",
    "posture",
    "cbom",
    "compliance",
    "soc2",
    "frameworks",
    "rbac",
    "governance",
    "slos",
    "alerts",
    "integrations",
    "remediation",
    "assets",
    "audit",
    "sessions",
    "threats",
    "agents",
    "attack_paths",
    "report",
    "evidence",
    "metrics",
    "tenants",
    "onboarding",
    "risk",
    "stats",
];

/// A resolved set of permission patterns. Patterns are `resource:action`, where
/// either side may be `*`; a bare `*` means everything.
#[derive(Debug, Clone, Default)]
pub struct PermissionSet {
    patterns: HashSet<String>,
}

impl PermissionSet {
    pub fn from_patterns<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            patterns: patterns.into_iter().map(Into::into).collect(),
        }
    }

    /// Does this set grant `needed` (a concrete `resource:action`)?
    pub fn allows(&self, needed: &str) -> bool {
        let (nres, nact) = split(needed);
        self.patterns.iter().any(|p| {
            let (pres, pact) = split(p);
            (pres == "*" || pres == nres) && (pact == "*" || pact == nact)
        })
    }

    /// The granted patterns, sorted (for display in `/api/auth/me`).
    pub fn sorted(&self) -> Vec<String> {
        let mut v: Vec<String> = self.patterns.iter().cloned().collect();
        v.sort();
        v
    }
}

fn split(perm: &str) -> (&str, &str) {
    match perm.split_once(':') {
        Some((r, a)) => (r, a),
        None => (perm, "*"), // bare "*"
    }
}

/// Permission bundle for a built-in role, or `None` if the name isn't built-in.
pub fn builtin_role_permissions(role_name: &str) -> Option<PermissionSet> {
    let reads = || RBAC_RESOURCES.iter().map(|r| format!("{r}:read"));
    let writes = || RBAC_RESOURCES.iter().map(|r| format!("{r}:write"));
    match role_name.to_lowercase().as_str() {
        // viewer and auditor are read-only over everything but config.
        "viewer" | "auditor" => Some(PermissionSet::from_patterns(reads())),
        // operator adds writes (still not config).
        "operator" => Some(PermissionSet::from_patterns(reads().chain(writes()))),
        // admin: everything, including config.
        "admin" => Some(PermissionSet::from_patterns(["*".to_string()])),
        _ => None,
    }
}

/// Build the full name -> permission-set table: the four built-ins plus any
/// custom roles from config (a custom role may override a built-in name).
pub fn resolve_roles(custom: &HashMap<String, Vec<String>>) -> HashMap<String, Arc<PermissionSet>> {
    let mut out: HashMap<String, Arc<PermissionSet>> = HashMap::new();
    for name in ["viewer", "auditor", "operator", "admin"] {
        if let Some(ps) = builtin_role_permissions(name) {
            out.insert(name.to_string(), Arc::new(ps));
        }
    }
    for (name, patterns) in custom {
        out.insert(
            name.to_lowercase(),
            Arc::new(PermissionSet::from_patterns(patterns.iter().cloned())),
        );
    }
    out
}

/// The permission a request requires. Unknown routes fall back to `config:*`
/// (admin-only) so a new, unmapped endpoint fails closed rather than open.
pub fn route_permission(method: &Method, path: &str) -> String {
    let write = !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    let act = |w: bool| if w { "write" } else { "read" };

    // Config is admin-only for read and write alike.
    if path.contains("/api/config") {
        return format!("config:{}", act(write));
    }
    // The audit surface (list, export, verify) is read-only even though verify
    // is a POST.
    if path.contains("/api/audit") {
        return "audit:read".to_string();
    }
    // Remediation actions can live under /findings/{id}/remediate and
    // /attack-paths/{id}/remediate.
    if path.contains("/remediate") {
        return "remediation:write".to_string();
    }
    if path.contains("/findings/") && path.contains("/plan") {
        return "remediation:read".to_string();
    }
    if path.contains("/api/remediations") {
        return format!("remediation:{}", act(write));
    }
    // Attack-path simulation is a read-only what-if (POST).
    if path.contains("/attack-paths/simulate") {
        return "attack_paths:read".to_string();
    }
    if path.contains("/api/findings") {
        return "findings:read".to_string();
    }
    if path.ends_with("/metrics") {
        return "metrics:read".to_string();
    }

    let resource = match segment_after_api(path) {
        "attack-paths" => "attack_paths",
        s if RBAC_RESOURCES.contains(&s) => s,
        _ => "config", // unknown -> admin-only
    };
    format!("{resource}:{}", act(write))
}

/// The first path segment after `/api/` (handles both `/api/x` and the nested
/// `/admin/api/x` used by the combined router).
fn segment_after_api(path: &str) -> &str {
    path.split("/api/")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_match() {
        let admin = builtin_role_permissions("admin").unwrap();
        assert!(admin.allows("config:write"));
        assert!(admin.allows("scans:write"));

        let viewer = builtin_role_permissions("viewer").unwrap();
        assert!(viewer.allows("scans:read"));
        assert!(!viewer.allows("scans:write"));
        assert!(!viewer.allows("config:read"));

        let operator = builtin_role_permissions("operator").unwrap();
        assert!(operator.allows("scans:write"));
        assert!(!operator.allows("config:write"));

        let custom = PermissionSet::from_patterns(["scans:*", "findings:read"]);
        assert!(custom.allows("scans:read"));
        assert!(custom.allows("scans:write"));
        assert!(custom.allows("findings:read"));
        assert!(!custom.allows("findings:write"));
    }

    #[test]
    fn routes_map_to_permissions() {
        let get = Method::GET;
        let post = Method::POST;
        assert_eq!(route_permission(&get, "/api/scans"), "scans:read");
        assert_eq!(route_permission(&post, "/api/scans"), "scans:write");
        assert_eq!(route_permission(&get, "/admin/api/scans/42"), "scans:read");
        assert_eq!(route_permission(&get, "/api/config"), "config:read");
        assert_eq!(route_permission(&post, "/api/config"), "config:write");
        assert_eq!(route_permission(&post, "/api/audit/verify"), "audit:read");
        assert_eq!(route_permission(&get, "/api/audit/export"), "audit:read");
        assert_eq!(
            route_permission(&post, "/api/findings/x/remediate"),
            "remediation:write"
        );
        assert_eq!(
            route_permission(&get, "/api/findings/x/plan"),
            "remediation:read"
        );
        assert_eq!(
            route_permission(&post, "/api/attack-paths/simulate"),
            "attack_paths:read"
        );
        assert_eq!(
            route_permission(&post, "/api/integrations/x/sync"),
            "integrations:write"
        );
        assert_eq!(route_permission(&get, "/metrics"), "metrics:read");
        // Unknown -> admin-only.
        assert_eq!(route_permission(&get, "/api/nope"), "config:read");
    }
}
