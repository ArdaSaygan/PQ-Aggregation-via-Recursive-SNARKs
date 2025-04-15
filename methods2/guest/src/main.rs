#![no_main]
#![no_std]

use hashsig::signature::SignatureScheme;
use pq_data_types::{Bitfield, MerkleProof, PublicKey, PublicKeyList, SigScheme, Signature};
use risc0_zkvm::guest::env;
use risc0_zkvm::serde;

risc0_zkvm::guest::entry!(main);

// Guest program that verifies
// - given bitfield and proof is correct
// - given signature is valid
// then it returns a new bitfield

fn main() {
    let (
        sig,
        pk,
        i, // i = 0 means no new signature is added
        pklist_merkle_root,
        merkle_proof,
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
    ): (
        Option<Signature>,
        Option<PublicKey>,
        usize,
        [u8; 32],
        Option<MerkleProof>,
        Bitfield,
        Bitfield,
        // Bitfield,
        // Bitfield,
        // Bitfield,
        // Bitfield,
        // Bitfield,
        // Bitfield,
        [u8; 32],
        [u32; 8],
    ) = env::read();

    // VERIFY SIGNATURE
    if i != 0 {
        assert!(sig.is_some(), "Signature should be present");
        assert!(pk.is_some(), "Public key should be present");
        assert!(merkle_proof.is_some(), "Merkle proof should be present");
        let sig = sig.unwrap();
        let pk = pk.unwrap();
        let merkle_proof = merkle_proof.unwrap();

        // i==0  means no new signature is added
        let sig_valid = SigScheme::verify(&pk, 2, &message, &sig);
        if !(sig_valid) {
            panic!("Invalid (signature, public key, message)");
        }

        // Verify if pk is in the list
        if !PublicKeyList::verify(&pklist_merkle_root, &merkle_proof, &pk) {
            panic!("Invalid (public key, pklist_merkle_root, merkle_proof)");
        }
    }

    // VERIFY ACCUMULATORs
    // Verify that the accumulator is correct
    // If bitfield == 0, this means no one yet contributed, hence accumulator is empty
    let zero_bitfield = Bitfield::new();

    if bitfield1 != zero_bitfield {
        let _ = env::verify(
            image_id,
            &serde::to_vec(&(&bitfield1, pklist_merkle_root, message)).unwrap(),
        );
    }
    if bitfield2 != zero_bitfield {
        let _ = env::verify(
            image_id,
            &serde::to_vec(&(&bitfield2, pklist_merkle_root, message)).unwrap(),
        );
    }
    // if bitfield3 != zero_bitfield {
    //     let _ = env::verify(
    //         image_id,
    //         &serde::to_vec(&(&bitfield3, pklist_merkle_root, message)).unwrap(),
    //     );
    // }
    // if bitfield4 != zero_bitfield {
    //     let _ = env::verify(
    //         image_id,
    //         &serde::to_vec(&(&bitfield4, pklist_merkle_root, message)).unwrap(),
    //     );
    // }
    // if bitfield5 != zero_bitfield {
    //     let _ = env::verify(
    //         image_id,
    //         &serde::to_vec(&(&bitfield5, pklist_merkle_root, message)).unwrap(),
    //     );
    // }
    // if bitfield6 != zero_bitfield {
    //     let _ = env::verify(
    //         image_id,
    //         &serde::to_vec(&(&bitfield6, pklist_merkle_root, message)).unwrap(),
    //     );
    // }
    // if bitfield7 != zero_bitfield {
    //     let _ = env::verify(
    //         image_id,
    //         &serde::to_vec(&(&bitfield7, pklist_merkle_root, message)).unwrap(),
    //     );
    // }
    // if bitfield8 != zero_bitfield {
    //     let _ = env::verify(
    //         image_id,
    //         &serde::to_vec(&(&bitfield8, pklist_merkle_root, message)).unwrap(),
    //     );
    // }
    // MERGE the BITFIELDS
    let mut one_bitfield = Bitfield::new();
    one_bitfield.set_bit(i - 1);
    let bitfield = bitfield1
        | bitfield2
        // | bitfield3
        // | bitfield4
        // | bitfield5
        // | bitfield6
        // | bitfield7
        // | bitfield8
        | one_bitfield;

    // Commit the new bitfield
    env::commit(&(bitfield, pklist_merkle_root, message));
}
