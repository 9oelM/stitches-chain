use sha2::{Digest, Sha256};

// DOMAIN_RANDAO = 0x02000000 per Ethereum spec
// https://github.com/ethereum/consensus-specs/blob/927073b0aafc958aef4689010fb4f97d22813015/specs/phase0/beacon-chain.md#randao
// def process_randao(state: BeaconState, body: BeaconBlockBody) -> None:
//     epoch = get_current_epoch(state)
//     # Verify RANDAO reveal
//     proposer = state.validators[get_beacon_proposer_index(state)]
//     signing_root = compute_signing_root(epoch, get_domain(state, DOMAIN_RANDAO))
//     assert bls.Verify(proposer.pubkey, signing_root, body.randao_reveal)
//     # Mix in RANDAO reveal
//     mix = xor(get_randao_mix(state, epoch), hash(body.randao_reveal))
//     state.randao_mixes[epoch % EPOCHS_PER_HISTORICAL_VECTOR] = mix

// def get_current_epoch(state: BeaconState) -> Epoch:
//     """
//     Return the current epoch.
//     """
//     return compute_epoch_at_slot(state.slot)

// def compute_epoch_at_slot(slot: Slot) -> Epoch:
//     """
//     Return the epoch number at ``slot``.
//     """
//     return Epoch(slot // SLOTS_PER_EPOCH)

// def get_beacon_proposer_index(state: BeaconState) -> ValidatorIndex:
//     """
//     Return the beacon proposer index at the current slot.
//     """
//     epoch = get_current_epoch(state)
//     seed = hash(get_seed(state, epoch, DOMAIN_BEACON_PROPOSER) + uint_to_bytes(state.slot))
//     indices = get_active_validator_indices(state, epoch)
//     return compute_proposer_index(state, indices, seed)

const DOMAIN_RANDAO: [u8; 4] = [0x02, 0x00, 0x00, 0x00];

pub struct Randao {

}


// Domain separation is needed for these reasons:
// To prevent cross-domain replay attacks (e.g., using an attestation signature in a RANDAO context).
// To ensure consistent structure for BLS signing input.
fn compute_domain(domain_type: [u8; 4]) -> [u8; 32] {
    // In Ethereum, domain = domain_type + fork_version + padding
    // We'll use simplified: domain_type + 28 zeros
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_type);
    domain
}

/// Converts an epoch to bytes32 for signing
fn compute_epoch_message(epoch: u64) -> [u8; 32] {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&epoch.to_le_bytes());

    // Hash to 32 bytes (for domain separation etc.)
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Generate randao_reveal = BLS_sign(private_key, epoch, DOMAIN_RANDAO)
fn generate_randao_reveal(privkey: &PrivateKey, epoch: u64) -> Signature {
    let message = compute_epoch_message(epoch);
    let domain = compute_domain(DOMAIN_RANDAO);
    let signing_root = compute_signing_root(&message, &domain);

    privkey.sign(signing_root.as_ref())
}

/// Concatenate and hash message + domain
fn compute_signing_root(message: &[u8; 32], domain: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.update(domain);
    hasher.finalize().into()
}

// Example usage
fn main() {
    // Example private key
    let privkey = PrivateKey::generate(&mut rand::thread_rng());

    let current_epoch: u64 = 12345;
    let randao_reveal = generate_randao_reveal(&privkey, current_epoch);

    println!("randao_reveal: {:?}", randao_reveal.as_bytes());
}
