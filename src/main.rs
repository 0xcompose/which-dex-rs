mod analyze;
mod bytecode_fingerprint;
mod selector_fingerprint;

use crate::analyze::{
    analyze_address, parse_address_hex, validate_rpc_url, AnalyzeError, AnalyzeReport,
};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "which-dex-rs", about = "DEX pool identifier", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Fetch bytecode via RPC and identify whether the address looks like a DEX pool + which protocol.
    Analyze {
        /// RPC URL (e.g. https://...)
        #[arg(long)]
        rpc_url: String,
        /// Contract address (0x-prefixed hex)
        #[arg(long)]
        address: String,
        /// Emit JSON to stdout (human-readable output goes to stderr)
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Analyze {
            rpc_url,
            address,
            json,
        } => run_analyze(&rpc_url, &address, json).await,
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run_analyze(rpc_url: &str, address: &str, json: bool) -> Result<(), AnalyzeError> {
    validate_rpc_url(rpc_url)?;
    let addr = parse_address_hex(address)?;

    let report = analyze_address(rpc_url, addr).await?;

    if json {
        println!(
            "{}",
            serde_json::to_string(&report).expect("serialize report")
        );
        eprint_human(&report);
    } else {
        print_human(&report);
    }

    Ok(())
}

fn print_human(report: &AnalyzeReport) {
    write_human(&mut std::io::stdout(), report);
}

fn eprint_human(report: &AnalyzeReport) {
    write_human(&mut std::io::stderr(), report);
}

fn write_human<W: std::io::Write>(out: &mut W, report: &AnalyzeReport) {
    let _ = writeln!(out, "rpc_url: {}", report.rpc_url);
    let _ = writeln!(out, "address: {}", report.address);

    if report.is_eip1167_proxy {
        let _ = writeln!(out, "eip1167_proxy: true");
        if let Some(impl_addr) = &report.implementation_address {
            let _ = writeln!(out, "implementation_address: {impl_addr}");
        }
    } else {
        let _ = writeln!(out, "eip1167_proxy: false");
    }

    let _ = writeln!(out, "");
    let _ = writeln!(out, "analysis_address: {}", report.analysis.address);
    let _ = writeln!(out, "code_size: {}", report.analysis.code_size);
    let _ = writeln!(out, "protocol: {}", report.analysis.protocol);
    let _ = writeln!(out, "is_pool_likely: {}", report.analysis.is_pool_likely);

    if report.analysis.protocol == "Unknown" {
        if let Some(cands) = &report.analysis.protocol_candidates {
            if !cands.is_empty() {
                let _ = writeln!(out, "protocol_candidates:");
                for c in cands {
                    let _ = writeln!(out, "  - {} (confidence {})", c.protocol, c.confidence);
                }
            }
        }
    }

    if let Some(fp) = &report.analysis.fingerprint {
        let _ = writeln!(out, "fingerprint_hash: {}", fp.hash_hex);
        let _ = writeln!(out, "fingerprint_original_size: {}", fp.original_size);
        let _ = writeln!(out, "fingerprint_normalized_size: {}", fp.normalized_size);
    } else if let Some(err) = &report.analysis.fingerprint_error {
        let _ = writeln!(out, "fingerprint_error: {err}");
    }

    if let Some(proxy) = &report.proxy_analysis {
        let _ = writeln!(out, "");
        let _ = writeln!(out, "proxy_bytecode_analysis:");
        let _ = writeln!(out, "  address: {}", proxy.address);
        let _ = writeln!(out, "  code_size: {}", proxy.code_size);
        let _ = writeln!(out, "  protocol: {}", proxy.protocol);
    }
}
