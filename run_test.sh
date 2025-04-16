#!/bin/bash

set -e  # exit on first error

for n in 128 256 512 1024 2048 4096 9192; do
  for m in 2 4 8; do
    echo "Running with NUM_VOTERS=$n and merge$m..."
    NUM_VOTERS=$n cargo run --release --bin merge$m "FinalBenchmark/merge${m}_sig${n}.txt"
  done
done
