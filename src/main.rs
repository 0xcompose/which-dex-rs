use which_dex_rs::Fingerprint;

fn main() {
    println!("which-dex-rs - DEX pool identifier");
    println!("Run tests: cargo test");

    // Example usage
    let example_bytecode = vec![0x60; 100]; // Dummy bytecode
    match Fingerprint::from_bytecode(&example_bytecode) {
        Ok(fp) => println!("Fingerprint hash: {}", fp.hash_hex()),
        Err(e) => println!("Error: {}", e),
    }
}
