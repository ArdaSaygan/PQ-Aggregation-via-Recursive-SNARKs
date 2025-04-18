

# PQ-Aggregation-via-Recursive-SNARKs

> ⚠️ **Warning:** This is a research prototype. It has **not** been audited and may contain bugs or security vulnerabilities. **Do not use in production environments.**

This repository contains the implementation of an ongoing research project conducted at **TÜBİTAK National Research Institute of Electronics and Cryptology**. The project explores **post-quantum signature aggregation using recursive SNARKs**.

---

## Getting Started

To build and run the project, you must install Rust, Cargo, and the [RISC Zero](https://github.com/risc0/risc0) toolchain.

1. Follow the instructions on the [RISC Zero setup guide](https://github.com/risc0/risc0#getting-started).  
2. To resolve potential version issues, install version **1.2.5** of `risc0-r0vm`:

```zsh
cargo install --force --version 1.2.5 risc0-r0vm
```

---

## Benchmarks

To run a benchmark test, use the following command:

```zsh
NUM_VOTERS=<NUM_VOTERS> cargo run --release --bin merge<N> <output_file_path>
```

- `<NUM_VOTERS>`: Number of signatures to be aggregated  
- `<N>`: Number of partial proofs to merge (supported values: **2**, **4**, **8**)  
- `<output_file_path>`: Path to save benchmark output (e.g., `Benchmark/merge<N>_sig<NUM_VOTERS>`)

To create profiling

```zsh
ISC0_PPROF_OUT=./<profiling_file>.pb RUST_LOG=info RISC0_INFO=1 cargo run --release --bin merge<N> <output_file_path>
```

To view profiling

```zsh
go tool pprof -http=127.0.0.1:8000 <profiling_file>.pb
```










