use serde::{Deserialize, Serialize};
use sha2::Digest;

#[derive(Debug, Clone)]
pub struct Sha256Literal {}

// Note: deliberately left empty
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sha2ChecksumParams {}

/// Used for checksum verification.
///
/// Creates a hash of the encrypted data to verify integrity.
///
/// Helps detect if the encrypted data has been tampered with or corrupted.
#[derive(Debug, Clone)]
pub struct Sha2Checksum {
    pub params: Sha2ChecksumParams,
    pub message: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sha2ChecksumSerde {
    pub function: Sha256Literal,
    pub params: Sha2ChecksumParams,
    #[serde(with = "hex")]
    pub message: Vec<u8>,
}

impl Serialize for Sha256Literal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str("sha256")
    }
}

impl<'de> Deserialize<'de> for Sha256Literal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s != "sha256" {
            return Err(serde::de::Error::custom(format!(
                "Expected 'sha256', got '{s}'"
            )));
        }
        Ok(Sha256Literal {})
    }
}

impl Sha2Checksum {
    /// Create a new SHA256 checksum from the second half of the derived key and encrypted message
    pub fn create(key_second_half: &[u8], encrypted_message: &[u8]) -> Self {
        let mut hasher = sha2::Sha256::new();
        hasher.update(key_second_half);
        hasher.update(encrypted_message);
        let checksum_message = hasher.finalize().to_vec();

        Self {
            params: Sha2ChecksumParams {},
            message: checksum_message,
        }
    }

    /// Verify the checksum against the provided key and encrypted message
    pub fn verify(&self, key_second_half: &[u8], encrypted_message: &[u8]) -> bool {
        let mut hasher = sha2::Sha256::new();
        hasher.update(key_second_half);
        hasher.update(encrypted_message);
        let computed_checksum = hasher.finalize().to_vec();

        computed_checksum == self.message
    }
}

impl Serialize for Sha2Checksum {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serialize_struct = Sha2ChecksumSerde {
            function: Sha256Literal {},
            params: self.params.clone(),
            message: self.message.clone(),
        };
        serialize_struct.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Sha2Checksum {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let serialized: Sha2ChecksumSerde = Sha2ChecksumSerde::deserialize(deserializer)?;
        Ok(Sha2Checksum {
            params: serialized.params,
            message: serialized.message,
        })
    }
}
