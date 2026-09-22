# Besa v1.1 benchmark

This benchmark measures the local, synchronous cryptographic and policy paths
used by exact-action verification. It is a reproducible engineering reference,
not an SLA and not a hosted-service latency claim.

## Reproduce

```bash
npm ci
npm run benchmark
```

The default run records 250 samples after 100 warmup iterations. Each sample
times ten operations and reports microseconds per operation. Increase the sample
count with `BESA_BENCHMARK_ITERATIONS` (accepted range: 100-100000).

```bash
BESA_BENCHMARK_ITERATIONS=1000 npm run benchmark
```

## Reference run

Recorded on 2026-09-22 with:

- Besa 1.1.0
- Node.js v24.20.0
- Windows `win32 10.0.26200 x64`
- Intel Core i3-1005G1 CPU at 1.20 GHz
- 250 measured samples, 100 warmups, 10 operations per sample

| Operation | Median (us) | p95 (us) | p99 (us) |
| --- | ---: | ---: | ---: |
| Canonicalize action | 5.67 | 10.64 | 20.88 |
| Hash action envelope | 21.56 | 40.42 | 56.18 |
| Verify action capability | 583.21 | 741.05 | 966.34 |
| Evaluate action policy | 51.85 | 81.98 | 128.17 |
| Verify delegation, capability, and evidence | 3116.46 | 6309.71 | 6698.38 |

## Method

`src/benchmark.ts` constructs one deterministic high-risk action, policy,
delegation, signed capability, signed evidence record, and trust anchor. Timings
use `process.hrtime.bigint()` after warmup. The full verification case validates
the delegation chain, exact-action capability, and linked result evidence.

Results vary with CPU, Node.js version, power state, and operating-system load.
They exclude HTTP parsing, network transit, persistent replay-store I/O, policy
loading, key generation, and application execution time.
