use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use which_dex::analyze::{analyze_address_with_cache, parse_address_hex, AnalyzeError};
use which_dex::cache::{parse_duration, CacheConfig};
use which_dex::validate_rpc_url;

#[derive(Debug, Parser)]
#[command(name = "which-dex", about = "DEX pool identifier", version)]
struct Args {
    /// Fetch bytecode via RPC and identify whether the address looks like a DEX pool + which protocol.
    /// Contract address (0x-prefixed hex)
    address: String,

    /// RPC URL (e.g. https://...)
    rpc_url: String,
    /// Emit JSON to stdout (human-readable output goes to stderr)
    // #[arg(long)]
    // json: bool,
    /// Enable verbose debug logs (tracing)
    #[arg(long)]
    verbose: bool,

    /// Disable disk bytecode cache (read + write)
    #[arg(long, default_value_t = false)]
    no_cache: bool,

    /// Override cache directory (default: $XDG_CACHE_HOME/which-dex or ~/.cache/which-dex)
    #[arg(long)]
    cache_dir: Option<String>,

    /// Override cache TTL (e.g. 30m, 12h, 7d)
    #[arg(long)]
    cache_ttl: Option<String>,

    /// Override cache max size (MB)
    #[arg(long)]
    cache_max_mb: Option<u64>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let result = run_analyze(
        &args.rpc_url,
        &args.address,
        // args.json,
        args.verbose,
        args.no_cache,
        args.cache_dir,
        args.cache_ttl,
        args.cache_max_mb,
    )
    .await;

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run_analyze(
    rpc_url: &str,
    address: &str,
    // json: bool,
    verbose: bool,
    no_cache: bool,
    cache_dir: Option<String>,
    cache_ttl: Option<String>,
    cache_max_mb: Option<u64>,
) -> Result<(), AnalyzeError> {
    init_tracing(verbose);
    validate_rpc_url(rpc_url)?;
    let addr = parse_address_hex(address)?;

    let mut cache_cfg = CacheConfig::default();
    if no_cache {
        cache_cfg.enabled = false;
    }
    if let Some(dir) = cache_dir {
        cache_cfg.dir = PathBuf::from(dir);
    }
    if let Some(ttl) = cache_ttl {
        cache_cfg.ttl = parse_duration(&ttl).map_err(AnalyzeError::InvalidCacheTtl)?;
    }
    if let Some(max_mb) = cache_max_mb {
        cache_cfg.max_bytes = max_mb.saturating_mul(1024).saturating_mul(1024);
    }

    let report = analyze_address_with_cache(rpc_url, addr, Some(cache_cfg)).await?;

    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize report")
    );
    // if json {
    // } else {
    //     print_human(&report);
    // }

    Ok(())
}

fn init_tracing(verbose: bool) {
    let level = if verbose { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
