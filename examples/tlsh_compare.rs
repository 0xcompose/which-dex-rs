//! TLSH bytecode comparison example
//!
//! Usage:
//!   1. Get bytecode using cast: `cast code <address> --rpc-url <rpc>`
//!   2. Save to files or pass as args
//!   3. Run: `cargo run --example tlsh_compare -- <hex1> <hex2>`
//!
//! Or with files:
//!   `cargo run --example tlsh_compare -- --file code1.hex code2.hex`

use std::env;
use std::fs;
use which_dex_rs::{Fingerprint, Similarity};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <hex1> <hex2>", args[0]);
        eprintln!("   or: {} --file <file1> <file2>", args[0]);
        std::process::exit(1);
    }

    let (bytecode1, bytecode2) = if args[1] == "--file" {
        if args.len() < 4 {
            eprintln!("Need two file paths");
            std::process::exit(1);
        }
        let hex1 = fs::read_to_string(&args[2]).expect("Failed to read file 1");
        let hex2 = fs::read_to_string(&args[3]).expect("Failed to read file 2");
        (
            hex::decode(hex1.trim().trim_start_matches("0x")).expect("Invalid hex in file 1"),
            hex::decode(hex2.trim().trim_start_matches("0x")).expect("Invalid hex in file 2"),
        )
    } else {
        (
            hex::decode(args[1].trim_start_matches("0x")).expect("Invalid hex arg 1"),
            hex::decode(args[2].trim_start_matches("0x")).expect("Invalid hex arg 2"),
        )
    };

    println!("Bytecode 1: {} bytes", bytecode1.len());
    println!("Bytecode 2: {} bytes", bytecode2.len());

    let fp1 = Fingerprint::from_bytecode(&bytecode1).expect("Bytecode 1 too small for TLSH");
    let fp2 = Fingerprint::from_bytecode(&bytecode2).expect("Bytecode 2 too small for TLSH");

    println!("\nTLSH hash 1: {}", fp1.hash_hex());
    println!("TLSH hash 2: {}", fp2.hash_hex());

    let diff = fp1.diff(&fp2);
    let similarity = fp1.similarity(&fp2);

    println!("\nTLSH diff score: {}", diff);
    println!("\nInterpretation:");
    println!("  0       = identical");
    println!("  1-30    = very similar (same contract, different immutables)");
    println!("  31-100  = similar (same protocol family/fork)");
    println!("  101-150 = possibly related");
    println!("  150+    = different contracts");

    match similarity {
        Similarity::Identical => println!("\n✓ Contracts are identical (after normalization)"),
        Similarity::SameContract => {
            println!("\n✓ Very high similarity - same contract with different constructor args")
        }
        Similarity::SameFamily => println!("\n~ Same protocol family or fork"),
        Similarity::PossiblyRelated => println!("\n? Possibly related - needs verification"),
        Similarity::Different => println!("\n✗ Different contracts"),
    }
}
