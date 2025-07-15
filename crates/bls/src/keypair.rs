// use blst::min_pk::SecretKey;
// use sha2::{Digest, Sha256};

/// We use BLS signature
/// Spec: https://github.com/ethereum/consensus-specs/blob/927073b0aafc958aef4689010fb4f97d22813015/specs/phase0/beacon-chain.md#bls-signatures
///
/// References:
/// - https://github.com/supranational/blst/tree/master/bindings/rust
/// - https://github.com/ChainSafe/bls-keygen
/// - https://github.com/ChainSafe/bls/blob/648c9a07c404d57e375ae91f71016505c9ef249c/src/herumi/secretKey.ts#L2
///
pub fn generate_keypair_from_seed(seed: &str) {
    // // Hash seed into 32 bytes
    // let hash = Sha256::digest(seed.as_bytes());
    // let ikm = hash.as_slice();

    // // Generate secret key from seed
    // let sk = SecretKey::key_gen(ikm, &[]).expect("Failed to generate secret key");
    // let pk = sk.sk_to_pk();

    // // println!("Private key (hex): {}", encode(sk.to_bytes()));
    // // println!("Public key  (hex): {}", encode(pk.to_bytes()));
}
