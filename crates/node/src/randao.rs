use primitive_types::U256;

/// # RANDAO
///
/// Read https://eth2book.info/capella/part2/building_blocks/randomness/#the-randao
/// for complete understanding.
///
/// Using RANDAO, we want to assign validators to certain tasks like block proposal in a random and unpredictable way.
/// This is crucial because knowing who will be assigned to a task in advance could lead to manipulation or collusion.
/// For example, one could bribe the validator assigned to a task in advance, or run DDoS attack it.
///
/// For every block included in the chain, the block proposer will give a verifiable random value called `randao_reveal`.
/// The chain's global RANDAO value is mixed with the `randao_reveal` value of each block.
///
/// Refer to [the pseudocode](https://eth2book.info/capella/part2/building_blocks/randomness/#updating-the-randao) to see how RANDAO is processed.
///
/// Refer to an example of [how RANDAO is used in practice in Lodestar](https://github.com/ChainSafe/lodestar/blob/64823d476aed916b437cf38895f1321f1f8b32a2/packages/state-transition/src/block/processRandao.ts#L13-L13).
pub struct Randao {
    current_mix: U256,
}

fn xor_32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

// impl Randao {
//     /// Create a new RANDAO instance with an initial mix value
//     pub fn new(initial_mix: U256) -> Self {
//         Randao {
//             current_mix: initial_mix,
//         }
//     }

//     /// Get the current RANDAO mix value
//     pub fn get_current_mix(&self) -> U256 {
//         self.current_mix
//     }

//     /// Mix in a new RANDAO reveal with the current mix
//     /// This is a simplified version of Ethereum's mixing function
//     pub fn mix(&mut self, reveal: U256) {
//         let mut hasher = Sha256::new();

//         // Convert current mix to bytes
//         let mix_bytes = self.current_mix.to_big_endian();
//         // Convert reveal to bytes
//         let reveal_bytes = reveal.to_big_endian();

//         // Hash both values together
//         hasher.update(&mix_bytes);
//         hasher.update(&reveal_bytes);

//         // Update the current mix with the new hash
//         let result = hasher.finalize();
//         self.current_mix = U256::from_big_endian(&result);
//     }

//     /// Generate a random validator index based on the current mix
//     /// Returns a number between 0 and validator_count - 1
//     pub fn get_validator_index(&self, validator_count: u64) -> u64 {
//         if validator_count == 0 {
//             return 0;
//         }

//         // Use the current mix to generate a random index
//         let big_index = self.current_mix % U256::from(validator_count);

//         // Convert to u64 (safe because we took modulo with validator_count)
//         big_index.as_u64()
//     }
// }
