# Which DEX

Command line tool to quickly identify/verify that address is an AMM pool and which DEX it is

Usage Examples:

-   Identifying is account a DEX pool
-   Identifying which DEX protocol this pool implements
-   Possibly using bytecode matching to verify that pool implements protocol correctly and is not a scam

Potential Use cases:

-   Broad pools gathering and identification for quick market analysis
-   Single pool verification of relativeness to known major protocol (via having lists of protocol contract addresses from other source and identifying pool deployment validity)

## Supported Protocols

-   Uniswap V2
-   Uniswap V3
-   Algebra V1.2
-   Algebra V1.9
-   Algebra Integral?
-   Solidly forks (Velo/Aerodrome)

Actual versioning and supported version of Algebra should detailed later, since there are just too confusing versioning and actuality of each version

Protocols that have virtual pools like Uniswap V4, Balancer V3 and PancakeSwap Infinity are not planned to be supported, at least for now
