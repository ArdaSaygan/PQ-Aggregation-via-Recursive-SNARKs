## PQ-Aggregation

#### Getting started
Install Rust, cargo and risc0 by following the instructions [here](https://github.com/risc0/risc0#getting-started). To resolve version issues, install risc0-r0vm 1.2.5. You can ensure the correct version by running 
```zsh
 cargo install --force --version 1.2.5 risc0-r0vm
```


#### Benchmarks
To run the test
```zsh
NUM_VOTERS=<NUM_VOTERS> cargo run --release --bin merge<N>
```
where N can be 2,4 or 8.

