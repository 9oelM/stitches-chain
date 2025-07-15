use primitive_types::U256;
use sha2::{Digest, Sha256};

use crate::validator::ValidatorId;

/// Represents a block in the blockchain.
///
/// A block is a collection of transactions and metadata that is added to the blockchain.
/// 
/// [In Ethereum, a block contains more properties](https://ethereum.org/en/developers/docs/blocks/), such as:
/// `state_root`, or `body`.
#[derive(Debug, Clone)]
pub struct Block {
  /// Block height. Means how many blocks are in the chain before this one.
  height: u64,
  /// Hash of the parent block.
  /// This is used to link blocks together in a chain.
  /// 
  /// For example, if we have two blocks:
  /// 
  /// ```
  /// Block 1
  ///   |
  ///   v
  /// Block 2
  /// ```
  /// 
  /// `Block 2` has `Block 1` as its parent.
  /// 
  /// It's represented by a number of 256 bits.
  parent_hash: U256,
  /// The ID of the validator who proposed this block.
  /// This is used to identify the validator who is responsible for this block.
  proposer: ValidatorId,
  /// List of validator IDs who voted for this block.
  votes: Vec<ValidatorId>,
  /// The RANDAO reveal value for this block.
  /// This is a verifiable random value provided by the block proposer.
  /// See [randao](crate::randao::Randao) for more.
  randao_reveal: U256,
}

impl Block {
  /// Create a new block with the given height, parent hash, and proposer.
  /// By default, the block has no votes and a zero randao_reveal.
  pub fn new(height: u64, parent_hash: U256, proposer: ValidatorId) -> Self {
    Block {
      height,
      parent_hash,
      proposer,
      votes: Vec::new(),
      randao_reveal: U256::zero(),
    }
  }

  pub fn add_vote(&mut self, validator_id: ValidatorId) {
    self.votes.push(validator_id);
  }

  /// Set the RANDAO reveal value for this block
  pub fn set_randao_reveal(&mut self, reveal: U256) {
    self.randao_reveal = reveal;
  }

  /// Generate a hash of the block using SHA-256.
  /// In Ethereum, Beacon chain uses Keccak-256 over RLP (execution block header).
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
  /// Just put them in bytes, in order.
  fn from(block: &Block) -> Self {
    let serialized_height = block.height.to_be_bytes();
    let serialized_parent_hash = block.parent_hash.to_big_endian();
    let serialized_proposer = block.proposer.to_be_bytes();
    let serialized_randao = block.randao_reveal.to_big_endian();
    let serialized_votes = block.votes.iter()
      .map(|v| v.to_be_bytes())
      .collect::<Vec<_>>().concat();

    let mut serialized = Vec::new();
    serialized.extend_from_slice(&serialized_height);
    serialized.extend_from_slice(&serialized_parent_hash);
    serialized.extend_from_slice(&serialized_proposer);
    serialized.extend_from_slice(&serialized_randao);
    serialized.extend_from_slice(&serialized_votes);
    
    serialized
  }
}
