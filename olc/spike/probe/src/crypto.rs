//! Crypto providers by name.

use std::sync::Arc;

use str0m::config::{CryptoProvider, DtlsVersion};

/// `dimpl`: str0m's own DTLS on aws-lc-rs. `boring`: BoringSSL for DTLS, aws-lc-rs for the rest.
pub fn provider(name: &str) -> Result<Arc<CryptoProvider>, String> {
    match name {
        "dimpl" => Ok(Arc::new(str0m_aws_lc_rs::default_provider())),
        #[cfg(feature = "boring")]
        "boring" => Ok(Arc::new(olc_spike_dtls_boring::provider())),
        other => Err(format!("unknown DTLS provider {other:?} (this build has: {})", names())),
    }
}

/// The provider names this build has.
pub fn names() -> &'static str {
    if cfg!(feature = "boring") {
        "dimpl, boring"
    } else {
        "dimpl"
    }
}

/// `12`, `13` or `auto`.
pub fn version(name: &str) -> Result<DtlsVersion, String> {
    match name {
        "12" => Ok(DtlsVersion::Dtls12),
        "13" => Ok(DtlsVersion::Dtls13),
        "auto" => Ok(DtlsVersion::Auto),
        other => Err(format!("unknown DTLS version {other:?}: 12, 13 or auto")),
    }
}

/// What the BoringSSL provider recorded about the handshakes since the last call, one JSON
/// object per handshake; empty without the `boring` feature.
pub fn handshakes_json() -> Vec<String> {
    #[cfg(feature = "boring")]
    {
        olc_spike_dtls_boring::take_handshakes()
            .into_iter()
            .map(|h| {
                serde_json::json!({
                    "active": h.active, "version": h.version, "cipher": h.cipher,
                    "group": h.group, "srtp": h.srtp, "ms": h.millis as u64,
                })
                .to_string()
            })
            .collect()
    }
    #[cfg(not(feature = "boring"))]
    {
        Vec::new()
    }
}
