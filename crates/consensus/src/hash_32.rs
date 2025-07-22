pub enum Hash32Error {
  InvalidLength
}

pub struct Hash32 {
  value: [u8; 32]
}

impl From<[u8; 32]> for Hash32 {
    fn from(value: [u8; 32]) -> Self {
        Self {
          value
        }
    }
}

impl TryFrom<Vec<u8>> for Hash32 {
  type Error = Hash32Error;

  fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
    if value.len() != 32 {
      return Err(Hash32Error::InvalidLength);
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&value[0..32]);

    Ok(Self {
      value: hash
    })
  }
}

impl TryFrom<&[u8]> for Hash32 {
  type Error = Hash32Error;

  fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
    if value.len() != 32 {
      return Err(Hash32Error::InvalidLength);
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&value[0..32]);

    Ok(Self {
      value: hash
    })
  }
}

impl From<Hash32> for [u8; 32] {
  fn from(value: Hash32) -> Self {
    value.value
  }
}

impl From<Hash32> for Vec<u8> {
  fn from(value: Hash32) -> Self {
    value.value.to_vec()
  }
}

impl From<&Hash32> for [u8; 32] {
  fn from(value: &Hash32) -> Self {
    value.value
  }
}

impl From<&Hash32> for Vec<u8> {
  fn from(value: &Hash32) -> Self {
    value.value.to_vec()
  }
}

impl Hash32 {
  pub fn to_vec(&self) -> Vec<u8> {
    self.value.to_vec()
  }

  pub fn to_bytes(&self) -> [u8; 32] {
    self.value
  }

  pub fn as_slice(&self) -> &[u8] {
    &self.value
  }
}

