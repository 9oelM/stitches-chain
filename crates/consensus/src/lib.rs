pub mod beacon_state;
pub mod block;
pub mod block_body;
pub mod block_header;
pub mod checkpoint;
pub mod cli;
pub mod epoch;
pub mod hash_32;
pub mod randao;
pub mod slot;
pub mod validator;
// use primitive_types::U256;
// use crate::randao::Randao;
// use crate::validator::ValidatorId;
// use crate::block::Block;

// fn main() {
//     //     // Initialize RANDAO with some initial mix value
//     //     let mut randao = Randao::new(U256::from(1234));

//     //     // Create a block with validator ID 1
//     //     let validator_id: ValidatorId = 1;
//     //     let mut block = Block::new(1, U256::zero(), validator_id);

//     //     // Simulate a validator providing a RANDAO reveal
//     //     // In practice, this would be generated using BLS signatures
//     //     let reveal = U256::from(5678);
//     //     block.set_randao_reveal(reveal);

//     //     // Mix the reveal into RANDAO
//     //     randao.mix(reveal);

//     //     // Use RANDAO to select a validator
//     //     let total_validators = 100;
//     //     let selected_validator = randao.get_validator_index(total_validators);

//     //     println!("Selected validator index: {}", selected_validator);
//     //     println!("Current RANDAO mix: {:?}", randao.get_current_mix());
// }
