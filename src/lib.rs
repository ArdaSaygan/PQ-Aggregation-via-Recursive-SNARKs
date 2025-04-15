#![doc = include_str!("../README.md")]

use std::usize;

// use core::panic;
use pq_aggregation_methods_2::PQ_AGGREGATION_GUEST_2_ELF;
use pq_aggregation_methods_4::PQ_AGGREGATION_GUEST_4_ELF;
use pq_aggregation_methods_8::PQ_AGGREGATION_GUEST_8_ELF;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt};

use pq_data_types::{Bitfield, MerkleProof, PublicKey, PublicKeyList, Signature};



pub fn aggregate_signatures_2(
    sig: Signature,
    pk: PublicKey,
    i: usize, // should be >= 1. 0 means no new signature is added
    message: [u8; 32],
    pk_list: &PublicKeyList,
    image_id: [u32; 8],
) -> Receipt {
    assert!(
        i > 0,
        "i should be >= 1, i = 0 means no new signature is added"
    );
    let bitfield1 = Bitfield::new(); // initialize bitfield with zeros
    let bitfield2 = Bitfield::new();
    // let bitfield3 = Bitfield::new();
    // let bitfield4 = Bitfield::new();
    // let bitfield5 = Bitfield::new();
    // let bitfield6 = Bitfield::new();
    // let bitfield7 = Bitfield::new();
    // let bitfield8 = Bitfield::new();
    let env = ExecutorEnv::builder()
        //.add_assumption()
        //.add_assumption()
        .write(&(
            Some(sig),
            Some(pk),
            i,
            pk_list.get_root().unwrap(),
            pk_list.prove(i - 1),
            bitfield1,
            bitfield2,
            // bitfield3,
            // bitfield4,
            // bitfield5,
            // bitfield6,
            // bitfield7,
            // bitfield8,
            message,
            image_id,
        ))
        .unwrap()
        .build()
        .unwrap();

    // new accumulator
    default_prover()
        .prove_with_opts(env, PQ_AGGREGATION_GUEST_2_ELF, &ProverOpts::composite())
        .unwrap()
        .receipt
}

pub fn merge_accumulators_2(
    acc1: Receipt,
    acc2: Receipt,
    // acc3: Receipt,
    // acc4: Receipt,
    // acc5: Receipt,
    // acc6: Receipt,
    // acc7: Receipt,
    // acc8: Receipt,
    image_id: [u32; 8],
) -> Receipt {
    let (bitfield1, pklist_merkle_root1, message1): (Bitfield, [u8; 32], [u8; 32]) =
        acc1.journal.decode().expect(
            "Journal output should deserialize into the same types (& order) that it was written",
        );
    let (bitfield2, pklist_merkle_root2, message2): (Bitfield, [u8; 32], [u8; 32]) =
        acc2.journal.decode().expect(
            "Journal output should deserialize into the same types (& order) that it was written",
        );
    // let (bitfield3, pklist_merkle_root3, message3): (Bitfield, [u8; 32], [u8; 32]) =
    //     acc3.journal.decode().expect(
    //         "Journal output should deserialize into the same types (& order) that it was written",
    //     );
    // let (bitfield4, pklist_merkle_root4, message4): (Bitfield, [u8; 32], [u8; 32]) =
    //     acc4.journal.decode().expect(
    //         "Journal output should deserialize into the same types (& order) that it was written",
    //     );
    // let (bitfield5, pklist_merkle_root5, message5): (Bitfield, [u8; 32], [u8; 32]) =
    //     acc5.journal.decode().expect(
    //         "Journal output should deserialize into the same types (& order) that it was written",
    //     );

    // let (bitfield6, pklist_merkle_root6, message6): (Bitfield, [u8; 32], [u8; 32]) =
    //     acc6.journal.decode().expect(
    //         "Journal output should deserialize into the same types (& order) that it was written",
    //     );
    // let (bitfield7, pklist_merkle_root7, message7): (Bitfield, [u8; 32], [u8; 32]) =
    //     acc7.journal.decode().expect(
    //         "Journal output should deserialize into the same types (& order) that it was written",
    //     );
    // let (bitfield8, pklist_merkle_root8, message8): (Bitfield, [u8; 32], [u8; 32]) =
    //     acc8.journal.decode().expect(
    //         "Journal output should deserialize into the same types (& order) that it was written",
    //     );

    // all accumulators should be the same Pk list and Message
    if !(
        pklist_merkle_root1 == pklist_merkle_root2
            // && pklist_merkle_root1 == pklist_merkle_root3
            // && pklist_merkle_root1 == pklist_merkle_root4
        // && pklist_merkle_root1 == pklist_merkle_root5
        // && pklist_merkle_root1 == pklist_merkle_root6
        // && pklist_merkle_root1 == pklist_merkle_root7
        // && pklist_merkle_root1 == pklist_merkle_root8
    ) && (
        message1 == message2 
        // && message1 == message3 && message1 == message4
        // && message1 == message5
        // && message1 == message6
        // && message1 == message7
        // && message1 == message8
    ) {
        panic!("Two accumulators are not for the same Pk list or Message")
    }

    let i: usize = 0; // i = 0 means no new signature is added
    let env = ExecutorEnv::builder()
        .add_assumption(acc1)
        .add_assumption(acc2)
        // .add_assumption(acc3)
        // .add_assumption(acc4)
        // .add_assumption(acc5)
        // .add_assumption(acc6)
        // .add_assumption(acc7)
        // .add_assumption(acc8)
        .write(&(
            // Use default for sig, pk, and merkle_proof or Optinze them
            None::<Signature>,
            None::<PublicKey>,
            i,
            pklist_merkle_root1,
            None::<MerkleProof>,
            bitfield1,
            bitfield2,
            // bitfield3,
            // bitfield4,
            // bitfield5,
            // bitfield6,
            // bitfield7,
            // bitfield8,
            message1,
            image_id,
        ))
        .unwrap()
        .build()
        .unwrap();

    // new accumulator
    default_prover()
        .prove_with_opts(env, PQ_AGGREGATION_GUEST_2_ELF, &ProverOpts::composite())
        .unwrap()
        .receipt
}

pub fn aggregate_signatures_4(
    sig: Signature,
    pk: PublicKey,
    i: usize, // should be >= 1. 0 means no new signature is added
    message: [u8; 32],
    pk_list: &PublicKeyList,
    image_id: [u32; 8],
) -> Receipt {
    assert!(
        i > 0,
        "i should be >= 1, i = 0 means no new signature is added"
    );
    let bitfield1 = Bitfield::new(); // initialize bitfield with zeros
    let bitfield2 = Bitfield::new();
    let bitfield3 = Bitfield::new();
    let bitfield4 = Bitfield::new();
    // let bitfield5 = Bitfield::new();
    // let bitfield6 = Bitfield::new();
    // let bitfield7 = Bitfield::new();
    // let bitfield8 = Bitfield::new();
    let env = ExecutorEnv::builder()
        //.add_assumption()
        //.add_assumption()
        .write(&(
            Some(sig),
            Some(pk),
            i,
            pk_list.get_root().unwrap(),
            pk_list.prove(i - 1),
            bitfield1,
            bitfield2,
            bitfield3,
            bitfield4,
            // bitfield5,
            // bitfield6,
            // bitfield7,
            // bitfield8,
            message,
            image_id,
        ))
        .unwrap()
        .build()
        .unwrap();

    // new accumulator
    default_prover()
        .prove_with_opts(env, PQ_AGGREGATION_GUEST_4_ELF, &ProverOpts::composite())
        .unwrap()
        .receipt
}

pub fn merge_accumulators_4(
    acc1: Receipt,
    acc2: Receipt,
    acc3: Receipt,
    acc4: Receipt,
    // acc5: Receipt,
    // acc6: Receipt,
    // acc7: Receipt,
    // acc8: Receipt,
    image_id: [u32; 8],
) -> Receipt {
    let (bitfield1, pklist_merkle_root1, message1): (Bitfield, [u8; 32], [u8; 32]) =
        acc1.journal.decode().expect(
            "Journal output should deserialize into the same types (& order) that it was written",
        );
    let (bitfield2, pklist_merkle_root2, message2): (Bitfield, [u8; 32], [u8; 32]) =
        acc2.journal.decode().expect(
            "Journal output should deserialize into the same types (& order) that it was written",
        );
    let (bitfield3, pklist_merkle_root3, message3): (Bitfield, [u8; 32], [u8; 32]) =
        acc3.journal.decode().expect(
            "Journal output should deserialize into the same types (& order) that it was written",
        );
    let (bitfield4, pklist_merkle_root4, message4): (Bitfield, [u8; 32], [u8; 32]) =
        acc4.journal.decode().expect(
            "Journal output should deserialize into the same types (& order) that it was written",
        );
    // let (bitfield5, pklist_merkle_root5, message5): (Bitfield, [u8; 32], [u8; 32]) =
    //     acc5.journal.decode().expect(
    //         "Journal output should deserialize into the same types (& order) that it was written",
    //     );

    // let (bitfield6, pklist_merkle_root6, message6): (Bitfield, [u8; 32], [u8; 32]) =
    //     acc6.journal.decode().expect(
    //         "Journal output should deserialize into the same types (& order) that it was written",
    //     );
    // let (bitfield7, pklist_merkle_root7, message7): (Bitfield, [u8; 32], [u8; 32]) =
    //     acc7.journal.decode().expect(
    //         "Journal output should deserialize into the same types (& order) that it was written",
    //     );
    // let (bitfield8, pklist_merkle_root8, message8): (Bitfield, [u8; 32], [u8; 32]) =
    //     acc8.journal.decode().expect(
    //         "Journal output should deserialize into the same types (& order) that it was written",
    //     );

    // all accumulators should be the same Pk list and Message
    if !(
        pklist_merkle_root1 == pklist_merkle_root2
            && pklist_merkle_root1 == pklist_merkle_root3
            && pklist_merkle_root1 == pklist_merkle_root4
        // && pklist_merkle_root1 == pklist_merkle_root5
        // && pklist_merkle_root1 == pklist_merkle_root6
        // && pklist_merkle_root1 == pklist_merkle_root7
        // && pklist_merkle_root1 == pklist_merkle_root8
    ) && (
        message1 == message2 && message1 == message3 && message1 == message4
        // && message1 == message5
        // && message1 == message6
        // && message1 == message7
        // && message1 == message8
    ) {
        panic!("Two accumulators are not for the same Pk list or Message")
    }

    let i: usize = 0; // i = 0 means no new signature is added
    let env = ExecutorEnv::builder()
        .add_assumption(acc1)
        .add_assumption(acc2)
        .add_assumption(acc3)
        .add_assumption(acc4)
        // .add_assumption(acc5)
        // .add_assumption(acc6)
        // .add_assumption(acc7)
        // .add_assumption(acc8)
        .write(&(
            // Use default for sig, pk, and merkle_proof or Optinze them
            None::<Signature>,
            None::<PublicKey>,
            i,
            pklist_merkle_root1,
            None::<MerkleProof>,
            bitfield1,
            bitfield2,
            bitfield3,
            bitfield4,
            // bitfield5,
            // bitfield6,
            // bitfield7,
            // bitfield8,
            message1,
            image_id,
        ))
        .unwrap()
        .build()
        .unwrap();

    // new accumulator
    default_prover()
        .prove_with_opts(env, PQ_AGGREGATION_GUEST_4_ELF, &ProverOpts::composite())
        .unwrap()
        .receipt
}


pub fn aggregate_signatures_8(
    sig: Signature,
    pk: PublicKey,
    i: usize, // should be >= 1. 0 means no new signature is added
    message: [u8; 32],
    pk_list: &PublicKeyList,
    image_id: [u32; 8],
) -> Receipt {
    assert!(
        i > 0,
        "i should be >= 1, i = 0 means no new signature is added"
    );
    let bitfield1 = Bitfield::new(); // initialize bitfield with zeros
    let bitfield2 = Bitfield::new();
    let bitfield3 = Bitfield::new();
    let bitfield4 = Bitfield::new();
    let bitfield5 = Bitfield::new();
    let bitfield6 = Bitfield::new();
    let bitfield7 = Bitfield::new();
    let bitfield8 = Bitfield::new();
    let env = ExecutorEnv::builder()
        //.add_assumption()
        //.add_assumption()
        .write(&(
            Some(sig),
            Some(pk),
            i,
            pk_list.get_root().unwrap(),
            pk_list.prove(i - 1),
            bitfield1,
            bitfield2,
            bitfield3,
            bitfield4,
            bitfield5,
            bitfield6,
            bitfield7,
            bitfield8,
            message,
            image_id,
        ))
        .unwrap()
        .build()
        .unwrap();

    // new accumulator
    default_prover()
        .prove_with_opts(env, PQ_AGGREGATION_GUEST_8_ELF, &ProverOpts::composite())
        .unwrap()
        .receipt
}

pub fn merge_accumulators_8(
    acc1: Receipt,
    acc2: Receipt,
    acc3: Receipt,
    acc4: Receipt,
    acc5: Receipt,
    acc6: Receipt,
    acc7: Receipt,
    acc8: Receipt,
    image_id: [u32; 8],
) -> Receipt {
    let (bitfield1, pklist_merkle_root1, message1): (Bitfield, [u8; 32], [u8; 32]) =
        acc1.journal.decode().expect(
            "Journal output should deserialize into the same types (& order) that it was written",
        );
    let (bitfield2, pklist_merkle_root2, message2): (Bitfield, [u8; 32], [u8; 32]) =
        acc2.journal.decode().expect(
            "Journal output should deserialize into the same types (& order) that it was written",
        );
    let (bitfield3, pklist_merkle_root3, message3): (Bitfield, [u8; 32], [u8; 32]) =
        acc3.journal.decode().expect(
            "Journal output should deserialize into the same types (& order) that it was written",
        );
    let (bitfield4, pklist_merkle_root4, message4): (Bitfield, [u8; 32], [u8; 32]) =
        acc4.journal.decode().expect(
            "Journal output should deserialize into the same types (& order) that it was written",
        );
    let (bitfield5, pklist_merkle_root5, message5): (Bitfield, [u8; 32], [u8; 32]) =
        acc5.journal.decode().expect(
            "Journal output should deserialize into the same types (& order) that it was written",
        );

    let (bitfield6, pklist_merkle_root6, message6): (Bitfield, [u8; 32], [u8; 32]) =
        acc6.journal.decode().expect(
            "Journal output should deserialize into the same types (& order) that it was written",
        );
    let (bitfield7, pklist_merkle_root7, message7): (Bitfield, [u8; 32], [u8; 32]) =
        acc7.journal.decode().expect(
            "Journal output should deserialize into the same types (& order) that it was written",
        );
    let (bitfield8, pklist_merkle_root8, message8): (Bitfield, [u8; 32], [u8; 32]) =
        acc8.journal.decode().expect(
            "Journal output should deserialize into the same types (& order) that it was written",
        );

    // all accumulators should be the same Pk list and Message
    if !(
        pklist_merkle_root1 == pklist_merkle_root2
            && pklist_merkle_root1 == pklist_merkle_root3
            && pklist_merkle_root1 == pklist_merkle_root4
        && pklist_merkle_root1 == pklist_merkle_root5
        && pklist_merkle_root1 == pklist_merkle_root6
        && pklist_merkle_root1 == pklist_merkle_root7
        && pklist_merkle_root1 == pklist_merkle_root8
    ) && (
        message1 == message2 && message1 == message3 && message1 == message4
        && message1 == message5
        && message1 == message6
        && message1 == message7
        && message1 == message8
    ) {
        panic!("Two accumulators are not for the same Pk list or Message")
    }

    let i: usize = 0; // i = 0 means no new signature is added
    let env = ExecutorEnv::builder()
        .add_assumption(acc1)
        .add_assumption(acc2)
        .add_assumption(acc3)
        .add_assumption(acc4)
        .add_assumption(acc5)
        .add_assumption(acc6)
        .add_assumption(acc7)
        .add_assumption(acc8)
        .write(&(
            // Use default for sig, pk, and merkle_proof or Optinze them
            None::<Signature>,
            None::<PublicKey>,
            i,
            pklist_merkle_root1,
            None::<MerkleProof>,
            bitfield1,
            bitfield2,
            bitfield3,
            bitfield4,
            bitfield5,
            bitfield6,
            bitfield7,
            bitfield8,
            message1,
            image_id,
        ))
        .unwrap()
        .build()
        .unwrap();

    // new accumulator
    default_prover()
        .prove_with_opts(env, PQ_AGGREGATION_GUEST_8_ELF, &ProverOpts::composite())
        .unwrap()
        .receipt
}
