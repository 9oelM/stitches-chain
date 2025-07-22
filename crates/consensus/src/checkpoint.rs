#[derive(Clone, Debug)]
pub struct Checkpoint {
    pub epoch: u64,
    pub root: [u8; 32],
}
