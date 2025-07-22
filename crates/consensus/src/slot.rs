#[derive(Clone, Debug)]
pub struct Slot {
    pub value: u64,
}

impl Slot {
    pub fn new(value: u64) -> Self {
        Self { value }
    }
}
