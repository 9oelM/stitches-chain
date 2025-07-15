pub type ValidatorId = u128;

#[derive(Debug, Clone)]
pub struct Validator {
  id: ValidatorId,
  stake: u64,
}
