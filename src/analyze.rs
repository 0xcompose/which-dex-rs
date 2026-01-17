use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::transports::http::reqwest::Url as AlloyUrl;
use serde::Serialize;
use thiserror::Error;
use tracing::debug;
use url::Url;

use crate::bytecode_fingerprint::{extract_eip1167_impl, is_eip1167_proxy, BytecodeFingerprint};
use crate::selector_fingerprint::selectors;
use crate::selector_fingerprint::{identify_protocols, DexProtocol};

#[derive(Debug, Error)]
pub enum AnalyzeError {
    #[error("invalid rpc url")]
    InvalidRpcUrl,

    #[error("invalid address (expected 20-byte 0x-prefixed hex)")]
    InvalidAddress,

    #[error("address has no deployed bytecode (EOA or not deployed)")]
    NoDeployedBytecode,

    #[error("rpc error: {0}")]
    Rpc(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolCandidate {
    pub protocol: String,
    pub confidence: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct FingerprintReport {
    pub hash_hex: String,
    pub original_size: usize,
    pub normalized_size: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BytecodeAnalysis {
    pub address: String,
    pub code_size: usize,

    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_candidates: Option<Vec<ProtocolCandidate>>,

    pub is_pool_likely: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<FingerprintReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalyzeReport {
    pub rpc_url: String,
    pub address: String,

    pub is_eip1167_proxy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implementation_address: Option<String>,

    pub analysis: BytecodeAnalysis,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_analysis: Option<BytecodeAnalysis>,
}

pub fn validate_rpc_url(rpc_url: &str) -> Result<(), AnalyzeError> {
    if rpc_url.trim().is_empty() {
        return Err(AnalyzeError::InvalidRpcUrl);
    }
    Url::parse(rpc_url).map_err(|_| AnalyzeError::InvalidRpcUrl)?;
    Ok(())
}

pub fn parse_address_hex(address: &str) -> Result<Address, AnalyzeError> {
    address
        .parse::<Address>()
        .map_err(|_| AnalyzeError::InvalidAddress)
}

pub fn dex_protocol_name(p: DexProtocol) -> &'static str {
    match p {
        DexProtocol::UniswapV2 => "UniswapV2",
        DexProtocol::UniswapV3 => "UniswapV3",
        DexProtocol::Solidly => "Solidly",
        DexProtocol::AlgebraLegacyV1 => "AlgebraLegacyV1",
        DexProtocol::AlgebraLegacyV1_9Plus => "AlgebraLegacyV1_9Plus",
        DexProtocol::AlgebraIntegral => "AlgebraIntegral",
        DexProtocol::Unknown => "Unknown",
    }
}

fn decide_protocol(bytecode: &[u8]) -> (DexProtocol, Option<Vec<ProtocolCandidate>>) {
    let mut matches = identify_protocols(bytecode);
    matches.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| dex_protocol_name(a.0).cmp(dex_protocol_name(b.0)))
    });

    debug!(matches = ?matches.iter().map(|(p,c)| (dex_protocol_name(*p), *c)).collect::<Vec<_>>(), "selector_fingerprint_matches");

    match matches.len() {
        1 => (matches[0].0, None),
        0 => (DexProtocol::Unknown, None),
        _ => {
            let candidates = matches
                .into_iter()
                .map(|(p, confidence)| ProtocolCandidate {
                    protocol: dex_protocol_name(p).to_string(),
                    confidence,
                })
                .collect();
            (DexProtocol::Unknown, Some(candidates))
        }
    }
}

pub fn analyze_bytecode(address: Address, bytecode: &[u8]) -> BytecodeAnalysis {
    let (protocol, candidates) = decide_protocol(bytecode);
    let is_pool_likely = protocol != DexProtocol::Unknown;

    let (fingerprint, fingerprint_error) = match BytecodeFingerprint::from_bytecode(bytecode) {
        Ok(fp) => (
            Some(FingerprintReport {
                hash_hex: fp.hash_hex(),
                original_size: fp.original_size(),
                normalized_size: fp.normalized_size(),
            }),
            None,
        ),
        Err(e) => (None, Some(e.to_string())),
    };

    BytecodeAnalysis {
        address: format!("{address:#x}"),
        code_size: bytecode.len(),
        protocol: dex_protocol_name(protocol).to_string(),
        protocol_candidates: candidates,
        is_pool_likely,
        fingerprint,
        fingerprint_error,
    }
}

pub fn proxy_implementation_address(bytecode: &[u8]) -> Option<Address> {
    if !is_eip1167_proxy(bytecode) {
        return None;
    }
    let impl_bytes = extract_eip1167_impl(bytecode)?;
    Some(Address::from(impl_bytes))
}

async fn fetch_code(rpc_url: &str, address: Address) -> Result<Vec<u8>, AnalyzeError> {
    let url: AlloyUrl = rpc_url.parse().map_err(|_| AnalyzeError::InvalidRpcUrl)?;
    let provider = ProviderBuilder::new().on_http(url);

    let bytes = provider
        .get_code_at(address)
        .await
        .map_err(|e| AnalyzeError::Rpc(e.to_string()))?;

    debug!(address = %format!("{address:#x}"), code_size = bytes.len(), "fetched_code");
    Ok(bytes.to_vec())
}

pub async fn analyze_address(
    rpc_url: &str,
    address: Address,
) -> Result<AnalyzeReport, AnalyzeError> {
    validate_rpc_url(rpc_url)?;

    let bytecode = fetch_code(rpc_url, address).await?;
    if bytecode.is_empty() {
        return Err(AnalyzeError::NoDeployedBytecode);
    }

    let proxy_impl = proxy_implementation_address(&bytecode);
    if let Some(impl_address) = proxy_impl {
        debug!(
            proxy = %format!("{address:#x}"),
            implementation = %format!("{impl_address:#x}"),
            "eip1167_proxy_resolved"
        );
        let impl_bytecode = fetch_code(rpc_url, impl_address).await?;
        if impl_bytecode.is_empty() {
            return Err(AnalyzeError::NoDeployedBytecode);
        }

        let analysis = analyze_bytecode(impl_address, &impl_bytecode);
        let proxy_analysis = analyze_bytecode(address, &bytecode);

        return Ok(AnalyzeReport {
            rpc_url: rpc_url.to_string(),
            address: format!("{address:#x}"),
            is_eip1167_proxy: true,
            implementation_address: Some(format!("{impl_address:#x}")),
            analysis,
            proxy_analysis: Some(proxy_analysis),
        });
    }

    debug!(
        token0 = selectors::TOKEN0.exists_in(&bytecode),
        token1 = selectors::TOKEN1.exists_in(&bytecode),
        globalState = selectors::GLOBAL_STATE.exists_in(&bytecode),
        plugin = selectors::PLUGIN.exists_in(&bytecode),
        fee = selectors::FEE.exists_in(&bytecode),
        slot0 = selectors::SLOT0.exists_in(&bytecode),
        safelyGetStateOfAMM = selectors::SAFELY_GET_STATE_OF_AMM.exists_in(&bytecode),
        "key_selector_presence"
    );

    Ok(AnalyzeReport {
        rpc_url: rpc_url.to_string(),
        address: format!("{address:#x}"),
        is_eip1167_proxy: false,
        implementation_address: None,
        analysis: analyze_bytecode(address, &bytecode),
        proxy_analysis: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_rpc_url() {
        assert!(validate_rpc_url("https://example.com").is_ok());
        assert!(validate_rpc_url("").is_err());
        assert!(validate_rpc_url("not-a-url").is_err());
    }

    #[test]
    fn test_parse_address_hex() {
        let addr = parse_address_hex("0x0000000000000000000000000000000000000001").unwrap();
        assert_eq!(
            format!("{addr:#x}"),
            "0x0000000000000000000000000000000000000001"
        );
        assert!(parse_address_hex("vitalik.eth").is_err());
        assert!(parse_address_hex("0x1234").is_err());
    }

    #[test]
    fn test_proxy_implementation_address() {
        // EIP-1167 runtime code with impl=0x95885af5492195f0754be71ad1545fe81364e531
        let proxy = hex::decode(
            "363d3d373d3d3d363d7395885af5492195f0754be71ad1545fe81364e5315af43d82803e903d91602b57fd5bf3",
        )
        .unwrap();

        let impl_addr = proxy_implementation_address(&proxy).unwrap();
        assert_eq!(
            format!("{impl_addr:#x}"),
            "0x95885af5492195f0754be71ad1545fe81364e531"
        );
    }
}
