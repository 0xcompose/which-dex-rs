//! Interface fingerprinting using function selectors
//!
//! This module identifies DEX protocols by checking which function selectors
//! are present in contract bytecode. Each protocol has a unique "selector signature".

use alloy::primitives::keccak256;

/// DEX protocol type identified by interface
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DexProtocol {
    /// Uniswap V2 or compatible fork
    UniswapV2,
    /// Uniswap V3
    UniswapV3,
    /// Solidly / Velodrome / Aerodrome
    Solidly,
    /// Algebra (legacy CLAMM, pre-plugin era; e.g., early Algebra v1.x)
    AlgebraLegacyV1,
    /// Algebra (legacy CLAMM with plugin(); broadly v1.9+ and similar deployments)
    AlgebraLegacyV1_9Plus,
    /// Algebra Integral (aka AMM v4 / "V4" in Algebra docs; plugin + getFee())
    AlgebraIntegral,
    /// Unknown protocol
    Unknown,
}

impl DexProtocol {
    /// Check if this is a V2-style constant product AMM
    pub fn is_v2_style(&self) -> bool {
        matches!(self, Self::UniswapV2 | Self::Solidly)
    }

    /// Check if this is a V3-style concentrated liquidity AMM
    pub fn is_v3_style(&self) -> bool {
        matches!(
            self,
            Self::UniswapV3
                | Self::AlgebraLegacyV1
                | Self::AlgebraLegacyV1_9Plus
                | Self::AlgebraIntegral
        )
    }
}

/// Function selector (first 4 bytes of keccak256(signature))
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Selector([u8; 4]);

impl Selector {
    /// Create selector from function signature string
    pub const fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    /// Create selector by hashing function signature
    pub fn from_signature(sig: &str) -> Self {
        let hash = keccak256(sig.as_bytes());
        Self([hash[0], hash[1], hash[2], hash[3]])
    }

    /// Get the selector bytes
    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Check if this selector exists in bytecode
    pub fn exists_in(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(4).any(|w| w == self.0)
    }
}

impl std::fmt::Display for Selector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

/// Well-known function selectors for DEX protocols
pub mod selectors {
    use super::Selector;

    // Common to all pools
    pub const TOKEN0: Selector = Selector::from_bytes([0x0d, 0xfe, 0x16, 0x81]); // token0()
    pub const TOKEN1: Selector = Selector::from_bytes([0xd2, 0x12, 0x20, 0xa7]); // token1()
    pub const FACTORY: Selector = Selector::from_bytes([0xc4, 0x5a, 0x01, 0x55]); // factory()

    // UniswapV2-style (many forks share the exact same interface)
    pub const GET_RESERVES: Selector = Selector::from_bytes([0x09, 0x02, 0xf1, 0xac]); // getReserves()
    pub const K_LAST: Selector = Selector::from_bytes([0x74, 0x64, 0xfc, 0x3d]); // kLast()
    pub const PRICE0_CUMULATIVE_LAST: Selector = Selector::from_bytes([0x59, 0x09, 0xc0, 0xd5]); // price0CumulativeLast()
    pub const PRICE1_CUMULATIVE_LAST: Selector = Selector::from_bytes([0x5a, 0x3d, 0x54, 0x93]); // price1CumulativeLast()

    // UniswapV3-style concentrated liquidity
    pub const SLOT0: Selector = Selector::from_bytes([0x38, 0x50, 0xc7, 0xbd]); // slot0()
    pub const FEE: Selector = Selector::from_bytes([0xdd, 0xca, 0x3f, 0x43]); // fee()
    pub const TICK_SPACING: Selector = Selector::from_bytes([0xd0, 0xc9, 0x3a, 0x7c]); // tickSpacing()
    pub const LIQUIDITY: Selector = Selector::from_bytes([0x1a, 0x68, 0x65, 0x02]); // liquidity()
    pub const TICKS: Selector = Selector::from_bytes([0xf3, 0x0d, 0xba, 0x93]); // ticks(int24)
    pub const POSITIONS: Selector = Selector::from_bytes([0x51, 0x4e, 0xa4, 0xbf]); // positions(bytes32)

    // Solidly / Velodrome / Aerodrome
    pub const STABLE: Selector = Selector::from_bytes([0x22, 0xbe, 0x3d, 0xe1]); // stable()
    pub const CLAIM_FEES: Selector = Selector::from_bytes([0xd2, 0x94, 0xf0, 0x93]); // claimFees()
    pub const CURRENT_CUMULATIVE_PRICES: Selector = Selector::from_bytes([0x1d, 0xf8, 0xc7, 0x17]); // currentCumulativePrices()

    // Algebra (all versions)
    pub const GLOBAL_STATE: Selector = Selector::from_bytes([0xe7, 0x6c, 0x01, 0xe4]); // globalState()
    pub const DATA_STORAGE_OPERATOR: Selector = Selector::from_bytes([0x29, 0x04, 0x7d, 0xfa]); // dataStorageOperator()
    pub const GET_INNER_CUMULATIVES: Selector = Selector::from_bytes([0x92, 0x0c, 0x34, 0xe5]); // getInnerCumulatives(int24,int24)

    // Algebra legacy v1.9+ (and also present in Integral)
    pub const PLUGIN: Selector = Selector::from_bytes([0xef, 0x01, 0xdf, 0x4f]); // plugin()
    pub const COMMUNITY_VAULT: Selector = Selector::from_bytes([0x53, 0xe9, 0x78, 0x68]); // communityVault()

    // Algebra Integral specific
    pub const GET_FEE: Selector = Selector::from_bytes([0xce, 0xd7, 0x27, 0x07]);
    // getFee()
}

/// Protocol fingerprint definition
struct ProtocolFingerprint {
    protocol: DexProtocol,
    /// Selectors that MUST be present
    required: &'static [Selector],
    /// Selectors that MUST NOT be present
    forbidden: &'static [Selector],
    /// Selectors that add confidence if present
    optional: &'static [Selector],
}

impl ProtocolFingerprint {
    fn matches(&self, bytecode: &[u8]) -> bool {
        let has_all_required = self.required.iter().all(|s| s.exists_in(bytecode));
        let has_no_forbidden = !self.forbidden.iter().any(|s| s.exists_in(bytecode));
        has_all_required && has_no_forbidden
    }

    fn confidence(&self, bytecode: &[u8]) -> u32 {
        if !self.matches(bytecode) {
            return 0;
        }

        let optional_matches = self
            .optional
            .iter()
            .filter(|s| s.exists_in(bytecode))
            .count();
        (self.required.len() + optional_matches) as u32
    }
}

/// All known protocol fingerprints, ordered by specificity (most specific first)
static FINGERPRINTS: &[ProtocolFingerprint] = &[
    // Algebra Integral (most specific Algebra version)
    ProtocolFingerprint {
        protocol: DexProtocol::AlgebraIntegral,
        required: &[
            selectors::TOKEN0,
            selectors::TOKEN1,
            selectors::GLOBAL_STATE,
            selectors::TICK_SPACING,
            selectors::LIQUIDITY,
            selectors::PLUGIN,
            selectors::GET_FEE,
        ],
        forbidden: &[selectors::SLOT0, selectors::DATA_STORAGE_OPERATOR],
        optional: &[selectors::COMMUNITY_VAULT],
    },
    // Algebra V1.9
    ProtocolFingerprint {
        protocol: DexProtocol::AlgebraLegacyV1_9Plus,
        required: &[
            selectors::TOKEN0,
            selectors::TOKEN1,
            selectors::GLOBAL_STATE,
            selectors::TICK_SPACING,
            selectors::LIQUIDITY,
            selectors::PLUGIN,
        ],
        forbidden: &[selectors::SLOT0, selectors::GET_FEE],
        optional: &[selectors::DATA_STORAGE_OPERATOR],
    },
    // Algebra legacy v1.x (pre-plugin)
    ProtocolFingerprint {
        protocol: DexProtocol::AlgebraLegacyV1,
        required: &[
            selectors::TOKEN0,
            selectors::TOKEN1,
            selectors::GLOBAL_STATE,
            selectors::TICK_SPACING,
            selectors::LIQUIDITY,
            selectors::DATA_STORAGE_OPERATOR,
        ],
        forbidden: &[selectors::SLOT0, selectors::PLUGIN],
        optional: &[selectors::GET_INNER_CUMULATIVES],
    },
    // Uniswap V3
    ProtocolFingerprint {
        protocol: DexProtocol::UniswapV3,
        required: &[
            selectors::TOKEN0,
            selectors::TOKEN1,
            selectors::SLOT0,
            selectors::FEE,
            selectors::TICK_SPACING,
            selectors::LIQUIDITY,
        ],
        forbidden: &[selectors::GLOBAL_STATE, selectors::STABLE],
        optional: &[selectors::TICKS, selectors::POSITIONS],
    },
    // Solidly / Velodrome / Aerodrome
    ProtocolFingerprint {
        protocol: DexProtocol::Solidly,
        required: &[
            selectors::TOKEN0,
            selectors::TOKEN1,
            selectors::GET_RESERVES,
            selectors::STABLE,
        ],
        forbidden: &[selectors::SLOT0, selectors::K_LAST],
        optional: &[selectors::CLAIM_FEES, selectors::CURRENT_CUMULATIVE_PRICES],
    },
    // Uniswap V2 (most generic V2; many forks share the exact same selectors)
    ProtocolFingerprint {
        protocol: DexProtocol::UniswapV2,
        required: &[
            selectors::TOKEN0,
            selectors::TOKEN1,
            selectors::GET_RESERVES,
            selectors::K_LAST,
        ],
        forbidden: &[selectors::SLOT0, selectors::STABLE, selectors::GLOBAL_STATE],
        optional: &[
            selectors::PRICE0_CUMULATIVE_LAST,
            selectors::PRICE1_CUMULATIVE_LAST,
            selectors::FACTORY,
        ],
    },
];

/// Identify DEX protocol from bytecode using selector analysis
pub fn identify_protocol(bytecode: &[u8]) -> DexProtocol {
    // Find the fingerprint with highest confidence
    let mut best_match = None;
    let mut best_confidence = 0u32;

    for fp in FINGERPRINTS {
        let confidence = fp.confidence(bytecode);
        if confidence > best_confidence {
            best_confidence = confidence;
            best_match = Some(fp.protocol);
        }
    }

    best_match.unwrap_or(DexProtocol::Unknown)
}

/// Get all matching protocols (for ambiguous cases)
pub fn identify_protocols(bytecode: &[u8]) -> Vec<(DexProtocol, u32)> {
    FINGERPRINTS
        .iter()
        .filter_map(|fp| {
            let confidence = fp.confidence(bytecode);
            if confidence > 0 {
                Some((fp.protocol, confidence))
            } else {
                None
            }
        })
        .collect()
}

/// Extract all function selectors from bytecode
pub fn extract_selectors(bytecode: &[u8]) -> Vec<Selector> {
    let mut selectors = Vec::new();
    let mut i = 0;

    while i < bytecode.len() {
        let op = bytecode[i];

        // PUSH4 (0x63) followed by 4 bytes - likely a selector
        if op == 0x63 && i + 4 < bytecode.len() {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&bytecode[i + 1..i + 5]);
            selectors.push(Selector::from_bytes(bytes));
            i += 5;
        } else if (0x60..=0x7f).contains(&op) {
            // Skip other PUSH opcodes
            i += (op - 0x5f) as usize + 1;
        } else {
            i += 1;
        }
    }

    selectors.sort_unstable_by_key(|s| s.0);
    selectors.dedup();
    selectors
}

/// Check if bytecode contains a specific function signature
pub fn has_function(bytecode: &[u8], signature: &str) -> bool {
    Selector::from_signature(signature).exists_in(bytecode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selector_from_signature() {
        // Known selectors
        assert_eq!(
            Selector::from_signature("token0()").0,
            [0x0d, 0xfe, 0x16, 0x81]
        );
        assert_eq!(
            Selector::from_signature("getReserves()").0,
            [0x09, 0x02, 0xf1, 0xac]
        );
        assert_eq!(
            Selector::from_signature("slot0()").0,
            [0x38, 0x50, 0xc7, 0xbd]
        );
        assert_eq!(
            Selector::from_signature("globalState()").0,
            [0xe7, 0x6c, 0x01, 0xe4]
        );
        assert_eq!(
            Selector::from_signature("stable()").0,
            [0x22, 0xbe, 0x3d, 0xe1]
        );
    }

    #[test]
    fn test_selector_exists_in() {
        let bytecode = vec![0x00, 0x0d, 0xfe, 0x16, 0x81, 0x00];
        assert!(selectors::TOKEN0.exists_in(&bytecode));
        assert!(!selectors::SLOT0.exists_in(&bytecode));
    }

    #[test]
    fn test_extract_selectors() {
        // PUSH4 0x0dfe1681 (token0)
        let bytecode = vec![0x63, 0x0d, 0xfe, 0x16, 0x81, 0x00];
        let extracted = extract_selectors(&bytecode);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0], selectors::TOKEN0);
    }

    #[test]
    fn test_has_function() {
        let bytecode = vec![0x00, 0x0d, 0xfe, 0x16, 0x81, 0x00];
        assert!(has_function(&bytecode, "token0()"));
        assert!(!has_function(&bytecode, "slot0()"));
    }

    #[test]
    fn test_dex_protocol_categories() {
        assert!(DexProtocol::UniswapV2.is_v2_style());
        assert!(DexProtocol::Solidly.is_v2_style());
        assert!(!DexProtocol::UniswapV3.is_v2_style());

        assert!(DexProtocol::UniswapV3.is_v3_style());
        assert!(DexProtocol::AlgebraLegacyV1.is_v3_style());
        assert!(!DexProtocol::UniswapV2.is_v3_style());
    }

    #[test]
    fn test_identify_algebra_with_fee_selector() {
        // Some Algebra deployments expose fee() in addition to globalState()/plugin().
        // Ensure we still classify them as Algebra (and not Unknown).
        let mut bytecode = Vec::new();
        bytecode.extend_from_slice(selectors::TOKEN0.as_bytes());
        bytecode.extend_from_slice(selectors::TOKEN1.as_bytes());
        bytecode.extend_from_slice(selectors::GLOBAL_STATE.as_bytes());
        bytecode.extend_from_slice(selectors::TICK_SPACING.as_bytes());
        bytecode.extend_from_slice(selectors::LIQUIDITY.as_bytes());
        bytecode.extend_from_slice(selectors::PLUGIN.as_bytes());
        bytecode.extend_from_slice(selectors::FEE.as_bytes());

        let protocol = identify_protocol(&bytecode);
        assert_eq!(protocol, DexProtocol::AlgebraLegacyV1_9Plus);
    }
}
