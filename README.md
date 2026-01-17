# Which DEX

Command line tool to quickly identify/verify that an address is an AMM pool and which DEX protocol it implements (via bytecode inspection).

### Usage

Build and run:

```bash
cargo run -- analyze --rpc-url <RPC_URL> --address <0xADDRESS>
```

JSON output (JSON only, on **stdout**):

```bash
cargo run -- analyze --rpc-url <RPC_URL> --address <0xADDRESS> --json
```

Verbose logs (debug, via `tracing`):

```bash
cargo run -- analyze --rpc-url <RPC_URL> --address <0xADDRESS> --verbose
```

### Output rules

-   **Protocol (confirmed)**: if selector fingerprints match **exactly one** protocol, CLI prints a single `protocol` (e.g. `UniswapV2`) and does **not** print candidates.
-   **Protocol (uncertain/unknown)**: if **0** or **2+** protocols match, CLI prints `protocol: Unknown` and then prints `protocol_candidates` with confidences.
-   **EIP-1167 proxies**: if the given address is an EIP-1167 minimal proxy, CLI resolves the implementation **once** and analyzes **both** (implementation is the primary `analysis`).

## Supported Protocols

-   Uniswap V2
-   Uniswap V3
-   Algebra V1.2
-   Algebra V1.9
-   Algebra Integral?
-   Solidly forks (Velo/Aerodrome)

Actual versioning and supported version of Algebra should detailed later, since there are just too confusing versioning and actuality of each version

Protocols that have virtual pools like Uniswap V4, Balancer V3 and PancakeSwap Infinity are not planned to be supported, at least for now
