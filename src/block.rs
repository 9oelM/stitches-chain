use primitive_types::U256;
use sha2::{Sha256, Digest};

use crate::validator::ValidatorId;

#[derive(Debug, Clone)]
pub struct Block {
  height: u64,
  parent_hash: U256,
  proposer: ValidatorId,
  votes: Vec<ValidatorId>,
}

impl Block {
  pub fn new(height: u64, parent_hash: U256, proposer: ValidatorId) -> Self {
    Block {
      height,
      parent_hash,
      proposer,
      votes: Vec::new(),
    }
  }

  pub fn add_vote(&mut self, validator_id: ValidatorId) {
    self.votes.push(validator_id);
  }

  /// Generate a hash of the block using SHA-256.
  /// In reality, Beacon chain uses Keccak-256 over RLP (execution block header).
  pub fn hash(&self) -> U256 {
    let mut hasher = Sha256::new();
    let serialized_block_bytes: Vec<u8> = self.into();
    hasher.update(&serialized_block_bytes);
    let hash = hasher.finalize();
    let hash_256 = U256::from_big_endian(&hash);

    hash_256
  }
}

impl From<&Block> for Vec<u8> {
  /// Serialize the block into bytes, so it can be hashed.
  /// Just put them in bytes in order.
  fn from(block: &Block) -> Self {
    let serialized_height = block.height.to_be_bytes();
    let serialized_parent_hash = block.parent_hash.to_big_endian();
    let serialized_proposer = block.proposer.to_be_bytes();
    let serialized_votes = block.votes.iter()
      .map(|v| v.to_be_bytes())
      .collect::<Vec<_>>().concat();

    let mut serialized = Vec::new();
    serialized.extend_from_slice(&serialized_height);
    serialized.extend_from_slice(&serialized_parent_hash);
    serialized.extend_from_slice(&serialized_proposer);
    serialized.extend_from_slice(&serialized_votes);
    
    serialized
  }
}