use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Tell Cargo to rerun this build script if NUM_VOTERS changes
    println!("cargo:rerun-if-env-changed=NUM_VOTERS");

    // Try to read NUM_VOTERS from the environment
    let num_voters = match env::var("NUM_VOTERS") {
        Ok(val) => val,
        Err(_) => {
            println!("cargo:warning=NUM_VOTERS not set, defaulting to 32");
            "32".to_string()
        }
    };

    // Write to OUT_DIR
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("num_voters.rs");
    fs::write(dest_path, format!("pub const NUM_VOTERS: usize = {};\n", num_voters)).unwrap();

}
