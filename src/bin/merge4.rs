use pq_data_types::NUM_VOTERS;
use hashsig::signature::SignatureScheme;
use pq_aggregation_methods_4::PQ_AGGREGATION_GUEST_4_ID;
use pq_data_types::SigScheme;
use pq_data_types::{Bitfield, PublicKeyList};
use rand::thread_rng;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::Instant;
// use tracing_subscriber::fmt;
// use tracing_subscriber::prelude::*;

// Helper function to log messages to both console and file
fn log_message(file: &mut std::fs::File, message: &str) {
    println!("{}", message);
    if let Err(e) = writeln!(file, "{}", message) {
        eprintln!("Error writing to log file: {}", e);
    }
}

pub fn main() {
    // Get command-line arguments
    let args: Vec<String> = env::args().collect();

    // Default log file name is "pq_aggregation_log.txt"
    // If a log file name is provided as an argument, use that instead
    let log_file_name = if args.len() > 1 {
        &args[1]
    } else {
        "pq_aggregation_log.txt"
    };

    // Create or open log file
    let mut log_file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(log_file_name)
        .expect("Failed to open log file");

    log_message(&mut log_file, "=== PQ Aggregation Test Started ===");

    // ---------

    // // Initialize a subscriber that prints logs at DEBUG level and above to the terminal.
    // tracing_subscriber::registry()
    //     .with(
    //         fmt::layer()
    //             .with_target(false) // Don’t print the module/target name if you prefer
    //             .with_level(true), // Print the log level next to the message
    //     )
    //     .with(tracing_subscriber::filter::LevelFilter::DEBUG)
    //     .init();

    // Define some parameters and constants
    let mut rng = thread_rng();
    let epoch: u32 = 2;
    let image_id: [u32; 8] = PQ_AGGREGATION_GUEST_4_ID;
    let message: [u8; 32] = {
        let mut arr: [u8; 32] = [0u8; 32]; // Initialize an array of size 32 with all zeros
        arr[0] = 1u8;
        arr[1] = 2u8;
        arr[2] = 3u8;
        arr
    };

    // Generate individual public and secret keys
    // let start = Instant::now();
    let (pub_key_1, sec_key_1) = SigScheme::gen(&mut rng);
    // let duration = start.elapsed();
    let (pub_key_2, sec_key_2) = SigScheme::gen(&mut rng);
    let (pub_key_3, _sec_key_3) = SigScheme::gen(&mut rng);
    let (pub_key_4, _sec_key_4) = SigScheme::gen(&mut rng);
    let (pub_key_5, _sec_key_5) = SigScheme::gen(&mut rng);
    let (pub_key_6, _sec_key_6) = SigScheme::gen(&mut rng);
    let (pub_key_7, _sec_key_7) = SigScheme::gen(&mut rng);
    let (pub_key_8, _sec_key_8) = SigScheme::gen(&mut rng);
    let (pub_key_9, _sec_key_9) = SigScheme::gen(&mut rng);
    let (pub_key_10, _sec_key_10) = SigScheme::gen(&mut rng);

    // Wrap the public keys in the PublicKeyList struct
    let mut key_arr = [None; NUM_VOTERS];
    key_arr[0] = Some(pub_key_1);
    key_arr[1] = Some(pub_key_2);
    key_arr[2] = Some(pub_key_3);
    key_arr[3] = Some(pub_key_4);
    key_arr[4] = Some(pub_key_5);
    key_arr[5] = Some(pub_key_6);
    key_arr[6] = Some(pub_key_7);
    key_arr[7] = Some(pub_key_8);
    key_arr[8] = Some(pub_key_9);
    key_arr[9] = Some(pub_key_10);

    let public_keys = PublicKeyList::from_array(key_arr);
    // log_message(
    //     &mut log_file,
    //     &format!(
    //         "Generated 10 key pairs, each {} seconds",
    //         duration.as_secs_f64()
    //     ),
    // );

    // create individual signatures
    // let start = Instant::now();
    let sig_1 = SigScheme::sign(&mut rng, &sec_key_1, epoch, &message).unwrap();
    // let duration = start.elapsed();
    let sig_2 = SigScheme::sign(&mut rng, &sec_key_2, epoch, &message).unwrap();

    // log_message(
    //     &mut log_file,
    //     &format!(
    //         "pk1-2 signed the message, each {} seconds",
    //         duration.as_secs_f64()
    //     ),
    // );

    // NOW AGGREGATE SIGNATURES
    // turn signatures to proofs
    let start = Instant::now();
    let acc00 =
        pq_aggregation::aggregate_signatures_4(sig_1, pub_key_1, 1, message, &public_keys, image_id);
    let duration_sig_to_proof1 = start.elapsed();
    log_message(
        &mut log_file,
        &format!(
            "Turned sig_1 to acc00, {} seconds",
            duration_sig_to_proof1.as_secs_f64()
        ),
    );

    let start = Instant::now();
    let acc01 =
        pq_aggregation::aggregate_signatures_4(sig_2, pub_key_2, 2, message, &public_keys, image_id);
    let duration_sig_to_proof2 = start.elapsed();
    log_message(
        &mut log_file,
        &format!(
            "Turned sig_2 to acc01, {} seconds",
            duration_sig_to_proof2.as_secs_f64()
        ),
    );

    // Merge accumulators
    let acc_1 = acc00.clone();
    let acc_2 = acc01.clone();
    let acc_3 = acc00.clone();
    let acc_4 = acc01.clone();
    // let acc_5 = acc00.clone();
    // let acc_6 = acc01.clone();
    // let acc_7 = acc00.clone();
    // let acc_8 = acc01.clone();
    let start = Instant::now();
    let acc10 = pq_aggregation::merge_accumulators_4(
        acc_1, acc_2, acc_3, acc_4, // acc_5, acc_6, acc_7, acc_8,
        image_id,
    );
    let duration_merge_proofs = start.elapsed();
    log_message(
        &mut log_file,
        &format!(
            "Merged acc00 + acc01 + acc00 + acc01 = acc10, {} seconds",
            duration_merge_proofs.as_secs_f64()
        ),
    );

    // log_message(&mut log_file, "Merged 4 proofs to 1 proof");

    // PROVER SENDS ACC to VERIFIER
    let start = Instant::now();
    acc10.verify(image_id).expect(
        "Code you have proven should successfully verify; did you specify the correct image ID?",
    );
    let (bitfield, _pklist_merkle_root, msg): (Bitfield, [u8; 32], [u8; 32]) =
        acc10.journal.decode().expect(
            "Journal output should deserialize into the same types (& order) that it was written",
        );
    let duration_verification = start.elapsed();
    log_message(
        &mut log_file,
        &format!(
            "Verified the final accumulator, acc10 in {} seconds",
            duration_verification.as_secs_f64()
        ),
    );

    log_message(&mut log_file, "=== PQ Aggregation Test Results ===");
    let no_agg_signatures = NUM_VOTERS;
    let merging_proofs: i32 = 4; // <<<< CHANGE THIS AS WELL
    let aggregation_time = (duration_sig_to_proof1 + duration_sig_to_proof2) / 2
        + duration_merge_proofs * no_agg_signatures.ilog2() / merging_proofs.ilog2();
    log_message(
        &mut log_file,
        &format!(
            "Number of Voters: {}, Merging {} proofs",
            NUM_VOTERS ,
            merging_proofs
        ),
    );
    log_message(
        &mut log_file,
        &format!(
            "Estimated time to aggregate all signatures: \n >>>> {} seconds (warning: fp error)",
            aggregation_time.as_secs_f64()
        ),
    );
    log_message(
        &mut log_file,
        &format!("Proof size: {} bytes", acc10.seal_size()),
    );
    // Sizes may be incorrect, and for pointer size! It may not the size of the real time heap data.
    log_message(&mut log_file, &format!("Bitfield: {:#010b}", bitfield.0[0]));
    log_message(&mut log_file, &format!("Message: {:?}", msg));

    log_message(&mut log_file, "=== PQ Aggregation Test Completed ===");
}
