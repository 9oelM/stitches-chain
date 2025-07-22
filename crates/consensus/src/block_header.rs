#[derive(Clone, Debug)]
pub struct BlockHeader {
  pub slot: u64,
  pub proposer_index: u64,
  pub parent_root: [u8; 32],
  pub state_root: [u8; 32],
  pub body_root: [u8; 32],
}
