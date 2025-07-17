use serde::{Deserialize, Serialize};

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
