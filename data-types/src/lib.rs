use merkle_light::{hash::Algorithm, merkle::MerkleTree, proof::Proof};
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::clone::Clone;
use std::ops::BitOr;

use hashsig::inc_encoding::basic_winternitz::WinternitzEncoding;
use hashsig::signature::generalized_xmss::{
    GeneralizedXMSSPublicKey, GeneralizedXMSSSignature, GeneralizedXMSSSignatureScheme,
};
use hashsig::symmetric::{
    message_hash::sha::ShaMessageHash, prf::sha::ShaPRF, tweak_hash::sha::ShaTweakHash,
};

// Copied from https://github.com/b-wagn/hash-sig/blob/main/src/signature/generalized_xmss/instantiations_sha.rs#L2
const LOG_LIFETIME: usize = 16;
const PARAMETER_LEN: usize = 18;
const MESSAGE_HASH_LEN: usize = 24; // Outputs of the hash functions in bytes, according to XMSS with SHA-256/192
const RAND_LEN: usize = 20;
const CHUNK_SIZE: usize = 4; // which means w = 2^4 = 16
const NUM_CHUNKS: usize = MESSAGE_HASH_LEN * 8 / CHUNK_SIZE;
type MH = ShaMessageHash<PARAMETER_LEN, RAND_LEN, NUM_CHUNKS, CHUNK_SIZE>;
const HASH_LEN: usize = 24; // Outputs of the hash functions in bytes, according to XMSS with SHA-256/192
type TH = ShaTweakHash<PARAMETER_LEN, HASH_LEN>;
type PRF = ShaPRF<HASH_LEN>;
type IE = WinternitzEncoding<MH, 3>;
/// Instantiation with Lifetime 2^16, Winternitz encoding, chunk size = 4
pub type SigScheme = GeneralizedXMSSSignatureScheme<PRF, IE, TH, LOG_LIFETIME>;
pub type Signature = GeneralizedXMSSSignature<IE, TH>;
pub type PublicKey = GeneralizedXMSSPublicKey<TH>;

pub type MerkleProof = merkle_light::proof::Proof<[u8; 32]>;

pub const NUM_VOTERS: usize = 32; // in bytes,
#[derive(Clone)]
pub struct PublicKeyList {
    keys: Vec<Option<PublicKey>>,
    merkle: Option<MerkleTree<[u8; 32], Alg>>,
}

impl PublicKeyList {
    pub fn new() -> Self {
        let mut l = PublicKeyList {
            keys: vec![None; NUM_VOTERS],
            merkle: None,
        };
        l.create_merkle_tree();
        l
    }
    pub fn from_array(arr: [Option<PublicKey>; NUM_VOTERS]) -> Self {
        let mut l = PublicKeyList {
            keys: arr.to_vec(),
            merkle: None,
        };
        l.create_merkle_tree();
        l
    }
    pub fn get(&self, i: usize) -> Option<PublicKey> {
        if i < NUM_VOTERS {
            if self.keys[i].is_none() {
                return None;
            }
            return Some(self.keys[i].as_ref().unwrap().clone());
        }
        None
    }

    // create merkle tree from the keys
    fn create_merkle_tree(&mut self) {
        let mut leafs: Vec<[u8; 32]> = Vec::new();
        for i in 0..NUM_VOTERS {
            if self.keys[i].is_none() {
                leafs.push([0u8; 32]);
                continue;
            }
            let pk = self.keys[i].as_ref().unwrap();
            let h = pk.hash_256();
            leafs.push(h);
        }
        self.merkle = Some(MerkleTree::from_iter(leafs));
    }

    pub fn get_root(&self) -> Option<[u8; 32]> {
        if self.merkle.is_none() {
            return None;
        }
        let root = self.merkle.as_ref().unwrap().root();
        Some(root)
    }

    // prove that public key at index i is in the list
    pub fn prove(&self, i: usize) -> Option<Proof<[u8; 32]>> {
        if i < NUM_VOTERS {
            if self.keys[i].is_none() {
                return None;
            }
            let proof = self.merkle.as_ref().unwrap().gen_proof(i);
            return Some(proof);
        }
        None
    }

    // verify a merkle inclusion proof
    // TODO: add a check for the public key
    pub fn verify(merkle_root: &[u8; 32], proof: &Proof<[u8; 32]>, pk: &PublicKey) -> bool {
        let mut a = Alg::default();
        let leaf = a.leaf(pk.hash_256());
        if proof.item() == leaf && proof.root() == *merkle_root && proof.validate::<Alg>() {
            return true;
        }
        false
    }
}

pub trait PublicKeyHasher {
    fn hash_256(&self) -> [u8; 32];
}

impl PublicKeyHasher for PublicKey {
    fn hash_256(&self) -> [u8; 32] {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(&self.root);
        hasher.update(&self.parameter);
        hasher.finalize().into()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct Bitfield(pub Vec<u8>);
impl Bitfield {
    pub fn new() -> Self {
        Bitfield(vec![0; NUM_VOTERS])
    }

    /// Sets the ith bit to 1
    pub fn set_bit(&mut self, i: usize) {
        let byte_index = i / 8;
        let bit_index = i % 8;

        if byte_index < NUM_VOTERS {
            self.0[byte_index] |= 1 << bit_index;
        }
    }
}
impl BitOr for Bitfield {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        let mut result = self;
        for i in 0..NUM_VOTERS {
            result.0[i] |= rhs.0[i];
        }
        result
    }
}

// This is a custom hash algorithm for the Merkle tree
// It uses SHA3-256 as the underlying hash function
use sha3::Sha3_256;
use std::hash::Hasher;

#[derive(Clone, Debug)]
pub struct Alg(Sha3_256);

impl Alg {
    pub fn new() -> Alg {
        Alg(Sha3_256::new())
    }
}

impl Default for Alg {
    fn default() -> Alg {
        Alg::new()
    }
}

impl Hasher for Alg {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.update(msg);
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

impl Algorithm<[u8; 32]> for Alg {
    #[inline]
    fn hash(&mut self) -> [u8; 32] {
        // let mut h = [0u8; 32];
        // self.0.result(&mut h);
        // h
        self.0.clone().finalize().into()
    }

    #[inline]
    fn reset(&mut self) {
        self.0.reset();
    }
}
