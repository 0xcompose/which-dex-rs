//! Integration tests for selector-based protocol identification
//!
//! These tests use real DEX pool bytecodes to verify protocol detection.

use which_dex::{identify_protocol, DexProtocol};

fn load_fixture(name: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/{}", name);
    let hex_content = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("Failed to read fixture: {}", path));
    hex::decode(hex_content.trim().trim_start_matches("0x"))
        .unwrap_or_else(|_| panic!("Invalid hex in fixture: {}", path))
}

#[test]
fn test_identify_uniswap_v2() {
    let bytecode = load_fixture("univ2_usdc_eth.hex");
    let protocol = identify_protocol(&bytecode);
    assert_eq!(protocol, DexProtocol::UniswapV2);
}

#[test]
fn test_identify_uniswap_v2_another_pool() {
    let bytecode = load_fixture("univ2_uni_eth.hex");
    let protocol = identify_protocol(&bytecode);
    assert_eq!(protocol, DexProtocol::UniswapV2);
}

#[test]
fn test_identify_uniswap_v3() {
    let bytecode = load_fixture("univ3_usdc_eth.hex");
    let protocol = identify_protocol(&bytecode);
    assert_eq!(protocol, DexProtocol::UniswapV3);
}

#[test]
fn test_identify_uniswap_v3_different_fee() {
    let bytecode = load_fixture("univ3_usdc_eth_005.hex");
    let protocol = identify_protocol(&bytecode);
    assert_eq!(protocol, DexProtocol::UniswapV3);
}

#[test]
fn test_identify_algebra() {
    let bytecode = load_fixture("algebra_matic_usdc.hex");
    let protocol = identify_protocol(&bytecode);

    // Should detect as one of the Algebra versions
    assert!(
        matches!(
            protocol,
            DexProtocol::AlgebraLegacyV1
                | DexProtocol::AlgebraLegacyV1_9Plus
                | DexProtocol::AlgebraIntegral
        ),
        "Expected Algebra variant, got {:?}",
        protocol
    );
}

#[test]
fn test_identify_solidly() {
    let bytecode = load_fixture("velo_impl.hex");
    let protocol = identify_protocol(&bytecode);
    assert_eq!(protocol, DexProtocol::Solidly);
}

#[test]
fn test_sushiswap_detected_as_v2_compatible() {
    // SushiSwap has same interface as UniV2, so detected as UniswapV2
    let bytecode = load_fixture("sushi_usdc_eth.hex");
    let protocol = identify_protocol(&bytecode);

    // SushiSwap uses same interface as UniV2
    assert_eq!(protocol, DexProtocol::UniswapV2);
}

#[test]
fn test_protocol_categories() {
    let v2 = load_fixture("univ2_usdc_eth.hex");
    let v3 = load_fixture("univ3_usdc_eth.hex");
    let solidly = load_fixture("velo_impl.hex");
    let algebra = load_fixture("algebra_matic_usdc.hex");

    assert!(identify_protocol(&v2).is_v2_style());
    assert!(identify_protocol(&solidly).is_v2_style());

    assert!(identify_protocol(&v3).is_v3_style());
    assert!(identify_protocol(&algebra).is_v3_style());
}

#[test]
fn test_identify_story_chain_storyhunt_pool() {
    let bytecode = load_fixture("story_storyhunt_pool.hex");
    let protocol = identify_protocol(&bytecode);
    assert_eq!(protocol, DexProtocol::UniswapV3);
}

#[test]
fn test_identify_story_chain_univ3_fork_pool() {
    let bytecode = load_fixture("story_univ3_fork_pool.hex");
    let protocol = identify_protocol(&bytecode);
    assert_eq!(protocol, DexProtocol::UniswapV3);
}
