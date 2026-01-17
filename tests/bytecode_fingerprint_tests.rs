//! Integration tests for bytecode fingerprinting
//!
//! These tests use real DEX pool bytecodes fetched from mainnet to verify
//! that TLSH fingerprinting correctly identifies protocol families.

use which_dex_rs::{BytecodeFingerprint, Similarity};

fn load_fixture(name: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/{}", name);
    let hex_content = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("Failed to read fixture: {}", path));
    hex::decode(hex_content.trim().trim_start_matches("0x"))
        .unwrap_or_else(|_| panic!("Invalid hex in fixture: {}", path))
}

/// Two Uniswap V2 pools should be identical after normalization
#[test]
fn test_univ2_pools_identical() {
    let usdc_eth = load_fixture("univ2_usdc_eth.hex");
    let uni_eth = load_fixture("univ2_uni_eth.hex");

    let fp1 = BytecodeFingerprint::from_bytecode(&usdc_eth).unwrap();
    let fp2 = BytecodeFingerprint::from_bytecode(&uni_eth).unwrap();

    let distance = fp1.distance(&fp2);
    let similarity = fp1.compare(&fp2);

    assert_eq!(
        distance, 0,
        "Two UniV2 pools should have identical fingerprints"
    );
    assert_eq!(similarity, Similarity::Identical);
    assert!(similarity.is_same_family());
}

/// Two Uniswap V3 pools should be identical after normalization
#[test]
fn test_univ3_pools_identical() {
    let pool_03 = load_fixture("univ3_usdc_eth.hex"); // 0.3% fee
    let pool_005 = load_fixture("univ3_usdc_eth_005.hex"); // 0.05% fee

    let fp1 = BytecodeFingerprint::from_bytecode(&pool_03).unwrap();
    let fp2 = BytecodeFingerprint::from_bytecode(&pool_005).unwrap();

    let distance = fp1.distance(&fp2);
    let similarity = fp1.compare(&fp2);

    assert_eq!(
        distance, 0,
        "Two UniV3 pools should have identical fingerprints"
    );
    assert_eq!(similarity, Similarity::Identical);
}

/// UniV2 and UniV3 should be clearly different
#[test]
fn test_univ2_vs_univ3_different() {
    let v2 = load_fixture("univ2_usdc_eth.hex");
    let v3 = load_fixture("univ3_usdc_eth.hex");

    let fp_v2 = BytecodeFingerprint::from_bytecode(&v2).unwrap();
    let fp_v3 = BytecodeFingerprint::from_bytecode(&v3).unwrap();

    let distance = fp_v2.distance(&fp_v3);
    let similarity = fp_v2.compare(&fp_v3);

    assert!(
        distance > 150,
        "UniV2 vs UniV3 should have high distance score, got {}",
        distance
    );
    assert_eq!(similarity, Similarity::Different);
    assert!(!similarity.is_same_family());
}

/// SushiSwap (UniV2 fork) should show similarity to UniV2
#[test]
fn test_univ2_vs_sushiswap_related() {
    let univ2 = load_fixture("univ2_usdc_eth.hex");
    let sushi = load_fixture("sushi_usdc_eth.hex");

    let fp_univ2 = BytecodeFingerprint::from_bytecode(&univ2).unwrap();
    let fp_sushi = BytecodeFingerprint::from_bytecode(&sushi).unwrap();

    let distance = fp_univ2.distance(&fp_sushi);

    // SushiSwap made modifications, so not identical but should show relation
    assert!(
        distance > 0 && distance < 200,
        "SushiSwap should show some similarity to UniV2, got distance {}",
        distance
    );
}

/// Algebra (UniV3 fork with dynamic fees) should show similarity to UniV3
#[test]
fn test_univ3_vs_algebra_related() {
    let univ3 = load_fixture("univ3_usdc_eth.hex");
    let algebra = load_fixture("algebra_matic_usdc.hex");

    let fp_univ3 = BytecodeFingerprint::from_bytecode(&univ3).unwrap();
    let fp_algebra = BytecodeFingerprint::from_bytecode(&algebra).unwrap();

    let distance = fp_univ3.distance(&fp_algebra);

    // Algebra is based on V3 but has significant changes
    assert!(
        distance > 50 && distance < 200,
        "Algebra should show moderate similarity to UniV3, got distance {}",
        distance
    );
}

/// Solidly (Velodrome) should be different from UniV2
#[test]
fn test_univ2_vs_solidly_different() {
    let univ2 = load_fixture("univ2_usdc_eth.hex");
    let solidly = load_fixture("velo_impl.hex");

    let fp_univ2 = BytecodeFingerprint::from_bytecode(&univ2).unwrap();
    let fp_solidly = BytecodeFingerprint::from_bytecode(&solidly).unwrap();

    let distance = fp_univ2.distance(&fp_solidly);
    let similarity = fp_univ2.compare(&fp_solidly);

    assert!(
        distance > 150,
        "Solidly should be different from UniV2, got distance {}",
        distance
    );
    assert_eq!(similarity, Similarity::Different);
}

/// Test that fingerprints capture bytecode size information
#[test]
fn test_fingerprint_sizes() {
    let v2 = load_fixture("univ2_usdc_eth.hex");
    let v3 = load_fixture("univ3_usdc_eth.hex");

    let fp_v2 = BytecodeFingerprint::from_bytecode(&v2).unwrap();
    let fp_v3 = BytecodeFingerprint::from_bytecode(&v3).unwrap();

    // V3 pools are significantly larger than V2
    assert!(fp_v3.original_size() > fp_v2.original_size());

    // UniV2 is ~11KB, UniV3 is ~22KB
    assert!(fp_v2.original_size() > 10000 && fp_v2.original_size() < 15000);
    assert!(fp_v3.original_size() > 20000 && fp_v3.original_size() < 25000);
}

/// Test that hash is deterministic
#[test]
fn test_fingerprint_deterministic() {
    let bytecode = load_fixture("univ2_usdc_eth.hex");

    let fp1 = BytecodeFingerprint::from_bytecode(&bytecode).unwrap();
    let fp2 = BytecodeFingerprint::from_bytecode(&bytecode).unwrap();

    assert_eq!(fp1.hash(), fp2.hash());
    assert_eq!(fp1.hash_hex(), fp2.hash_hex());
    assert_eq!(fp1.distance(&fp2), 0);
}

/// Story chain: two UniV3-fork pools should be at least in the same family after normalization
#[test]
fn test_story_chain_univ3_forks_same_family() {
    let a = load_fixture("story_storyhunt_pool.hex");
    let b = load_fixture("story_univ3_fork_pool.hex");

    let fp_a = BytecodeFingerprint::from_bytecode(&a).unwrap();
    let fp_b = BytecodeFingerprint::from_bytecode(&b).unwrap();

    let distance = fp_a.distance(&fp_b);
    let similarity = fp_a.compare(&fp_b);

    assert!(
        similarity.is_same_family(),
        "Expected same-family similarity, got {:?} (distance {})",
        similarity,
        distance
    );
}
