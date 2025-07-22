use crate::{block_header::BlockHeader, checkpoint::Checkpoint, validator::Validator};

pub struct BeaconState {
  pub slot: u64,
  pub latest_block_header: BlockHeader,
  pub block_roots: Vec<[u8; 32]>,
  pub state_roots: Vec<[u8; 32]>,
  pub randao_mixes: Vec<[u8; 32]>, // one per epoch
  pub validators: Vec<Validator>,
  pub balances: Vec<u64>,
  pub finalized_checkpoint: Checkpoint,
  pub current_justified_checkpoint: Checkpoint,
  pub previous_justified_checkpoint: Checkpoint,
}
