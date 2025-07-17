use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct Aes128Literal;

impl Serialize for Aes128Literal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str("aes-128-ctr")
    }
}

impl<'de> Deserialize<'de> for Aes128Literal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s != "aes-128-ctr" {
            return Err(serde::de::Error::custom(format!(
                "Expected 'aes128-ctr', got '{s}'"
            )));
        }
        Ok(Aes128Literal {})
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aes128CtrCipherParams {
    /// Initialization Vector (IV) for AES-128-CTR mode
    ///
    /// Must be 16 bytes (128 bits) and unique for each encryption
    #[serde(with = "hex")]
    pub iv: [u8; 16],
}

/// Takes the derived key from PBKDF2 or Scrypt to encrypts/decrypt the private key
#[derive(Debug, Clone)]
pub struct Aes128CtrCipher {
    pub params: Aes128CtrCipherParams,
    pub message: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aes128CtrCipherSerde {
    pub params: Aes128CtrCipherParams,
    #[serde(with = "hex")]
    pub message: Vec<u8>,
    pub function: Aes128Literal,
}

impl Serialize for Aes128CtrCipher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serialize_struct = Aes128CtrCipherSerde {
            params: self.params.clone(),
            message: self.message.clone(),
            function: Aes128Literal {},
        };
        serialize_struct.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Aes128CtrCipher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let serialized = Aes128CtrCipherSerde::deserialize(deserializer)?;
        Ok(Aes128CtrCipher {
            params: serialized.params,
            message: serialized.message,
        })
    }
}
