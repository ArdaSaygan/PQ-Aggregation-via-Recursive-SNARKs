// build.rs
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let num_voters = env::var("NUM_VOTERS").unwrap_or_else(|_| "32".to_string());
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("num_voters.rs");
    fs::write(dest_path, format!("pub const NUM_VOTERS: usize = {};\n", num_voters)).unwrap();
}
