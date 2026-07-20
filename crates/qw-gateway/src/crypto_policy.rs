//! In-path PQC enforcement.
//!
//! Evaluates a request's upstream channel posture against the configured crypto
//! standard and decides whether to allow, flag, or block the flow. Blocking
//! happens in the live data path — the differentiator a passive scanner cannot
//! offer.

use qw_scanner::PqcStatus;

use crate::config::CryptoEnforcementConfig;

/// The decision for a single request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoVerdict {
    /// Channel meets the bar (or enforcement is off) — proceed silently.
    Allow,
    /// Below the bar in monitor mode — proceed, but flag it.
    Flag { channel: String, required: String },
    /// Below the bar in enforce mode — refuse the request.
    Block { channel: String, required: String },
}

/// Rank a posture so we can compare against the requirement. Higher = safer.
fn rank(status: &PqcStatus) -> u8 {
    match status {
        PqcStatus::PqcReady => 4,
        PqcStatus::Hybrid => 3,
        PqcStatus::ClassicalSecure => 2,
        PqcStatus::ClassicalWeak => 1,
        PqcStatus::Unknown => 0,
    }
}

/// The minimum rank a `require` setting demands.
fn required_rank(require: &str) -> u8 {
    match require.to_lowercase().as_str() {
        "pqc" | "pqc_ready" => 4,
        "hybrid" => 3,
        "classical_secure" | "classical" => 2,
        _ => 3, // default: hybrid
    }
}

/// Evaluate a flow. `channel` is the provider's scanned PQC status, or `None`
/// if it hasn't been fingerprinted yet.
pub fn evaluate(
    cfg: &CryptoEnforcementConfig,
    provider: &str,
    channel: Option<&PqcStatus>,
) -> CryptoVerdict {
    if !cfg.enabled || cfg.exempt_providers.iter().any(|p| p == provider) {
        return CryptoVerdict::Allow;
    }
    let enforce = cfg.mode.eq_ignore_ascii_case("enforce");
    let required = required_rank(&cfg.require);

    let (chan_rank, chan_label) = match channel {
        Some(s) => (rank(s), s.to_string()),
        None => (0, "unknown".to_string()),
    };

    // An un-scanned channel: only acts if block_unknown is set (enforce) — a
    // scan hasn't proven it unsafe, so we don't punish it by default.
    if channel.is_none() && !cfg.block_unknown {
        return CryptoVerdict::Allow;
    }

    if chan_rank >= required {
        return CryptoVerdict::Allow;
    }

    let payload = (chan_label, cfg.require.to_lowercase());
    if enforce {
        CryptoVerdict::Block {
            channel: payload.0,
            required: payload.1,
        }
    } else {
        CryptoVerdict::Flag {
            channel: payload.0,
            required: payload.1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enabled: bool, mode: &str, require: &str) -> CryptoEnforcementConfig {
        CryptoEnforcementConfig {
            enabled,
            mode: mode.into(),
            require: require.into(),
            exempt_providers: vec![],
            block_unknown: false,
        }
    }

    #[test]
    fn disabled_always_allows() {
        assert_eq!(
            evaluate(
                &cfg(false, "enforce", "pqc"),
                "openai",
                Some(&PqcStatus::ClassicalWeak)
            ),
            CryptoVerdict::Allow
        );
    }

    #[test]
    fn monitor_flags_classical() {
        let v = evaluate(
            &cfg(true, "monitor", "hybrid"),
            "openai",
            Some(&PqcStatus::ClassicalSecure),
        );
        assert!(matches!(v, CryptoVerdict::Flag { .. }));
    }

    #[test]
    fn enforce_blocks_below_bar_but_passes_pqc() {
        let c = cfg(true, "enforce", "hybrid");
        assert!(matches!(
            evaluate(&c, "openai", Some(&PqcStatus::ClassicalSecure)),
            CryptoVerdict::Block { .. }
        ));
        assert_eq!(
            evaluate(&c, "internal", Some(&PqcStatus::Hybrid)),
            CryptoVerdict::Allow
        );
        assert_eq!(
            evaluate(&c, "internal", Some(&PqcStatus::PqcReady)),
            CryptoVerdict::Allow
        );
    }

    #[test]
    fn exempt_provider_bypasses() {
        let mut c = cfg(true, "enforce", "pqc");
        c.exempt_providers = vec!["anthropic".into()];
        assert_eq!(
            evaluate(&c, "anthropic", Some(&PqcStatus::ClassicalSecure)),
            CryptoVerdict::Allow
        );
    }

    #[test]
    fn unknown_channel_respects_block_unknown() {
        let mut c = cfg(true, "enforce", "hybrid");
        assert_eq!(evaluate(&c, "new", None), CryptoVerdict::Allow);
        c.block_unknown = true;
        assert!(matches!(
            evaluate(&c, "new", None),
            CryptoVerdict::Block { .. }
        ));
    }
}
