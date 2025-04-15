#!/bin/bash

set -e  # exit on first error

for n in 128 256 512 1024 2048; do
  for m in 2 4 8; do
    echo "Running with NUM_VOTERS=$n and merge$m..."
    NUM_VOTERS=$n cargo run --release --bin merge$m "Benchmark/merge${m}_sig${n}.txt"
  done
done
