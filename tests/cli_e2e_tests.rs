//! End-to-end CLI tests (networked).
//!
//! These tests execute the compiled `which-dex-rs` binary and may require:
//! - Working public RPC endpoint(s)
//! - Network access
//! - Stable chain state (contract remains deployed)

use std::process::Command;

#[test]
fn test_e2e_fuse_algebra_pool_is_detected() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("which-dex"));

    cmd.args([
        "analyze",
        "--address",
        "0x8a869FBbA9dDA91867c787DBE57e9A10A72DeB39",
        "--rpc-url",
        "https://rpc.fuse.io",
        "--json",
    ]);

    let output = cmd.output().expect("run which-dex-rs");
    assert!(
        output.status.success(),
        "expected success, got status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        output.stderr.is_empty(),
        "expected no stderr output in --json mode, got stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // JSON is on stdout.
    let v: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is valid JSON");

    let protocol = v["analysis"]["protocol"]
        .as_str()
        .expect("analysis.protocol is string");

    assert!(
        matches!(
            protocol,
            "AlgebraLegacyV1" | "AlgebraLegacyV1_9Plus" | "AlgebraIntegral"
        ),
        "expected an Algebra protocol, got protocol={protocol}, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        v["analysis"]["is_pool_likely"].as_bool() == Some(true),
        "expected analysis.is_pool_likely=true, got {:?}",
        v["analysis"]["is_pool_likely"]
    );
}
