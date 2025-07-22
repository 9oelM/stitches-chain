//! AES-128 is used to lock and unlock your private key with a password.
//! 
//! Think of this like a digital safe - when you store your private key, 
//! it gets scrambled (encrypted) so no one can read it. When you need 
//! to use your key, you provide your password to unscramble (decrypt) it back. 

use aes::{
    Aes128,
    cipher::{KeyIvInit, StreamCipher, generic_array::GenericArray},
};
use ctr::Ctr128BE;
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aes128CtrCipherParams {
    /// Initialization Vector (IV) for AES-128-CTR mode
    ///
    /// When you encrypt the same private key with the same password, you don't want it to look identical each time.
    /// The IV adds randomness so that even identical data gets scrambled differently.
    ///
    /// Must be 16 bytes (128 bits) and unique for each encryption
    #[serde(with = "hex")]
    pub iv: [u8; 16],
}

/// Takes the derived key from PBKDF2 or Scrypt to encrypts/decrypt the private key
#[derive(Debug, Clone)]
pub struct Aes128CtrCipher {
    pub params: Aes128CtrCipherParams,
    /// The message is the encrypted BLS private key.
    /// 
    /// The encryption process scrambles it: `private key + password + IV = message`, which is stored in the keystore.
    /// To get the private key back, you reverse the process: `password + IV + message = private key`
    pub message: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aes128CtrCipherSerde {
    pub params: Aes128CtrCipherParams,
    #[serde(with = "hex")]
    pub message: Vec<u8>,
    // Always stays the constant as a aes-128-ctr, so just put it into serde struct,
    // not the original struct, to reduce noise in the code.
    pub function: Aes128Literal,
}

#[derive(Debug, Clone)]
pub struct Aes128Literal;

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

impl Aes128CtrCipher {
    /// Encrypt data using AES-128-CTR with the provided key and optional IV
    pub fn encrypt(data: &[u8], encryption_key: &[u8], iv: Option<[u8; 16]>) -> Self {
        let aes_iv = iv.unwrap_or_else(|| rand::rng().random::<[u8; 16]>());
        
        let encryption_key_array = GenericArray::from_slice(&encryption_key[..16]);
        let nonce = GenericArray::from_slice(&aes_iv);

        let mut cipher = Ctr128BE::<Aes128>::new(encryption_key_array, nonce);
        let mut encrypted_data = data.to_vec();
        cipher.apply_keystream(&mut encrypted_data);

        Self {
            params: Aes128CtrCipherParams { iv: aes_iv },
            message: encrypted_data,
        }
    }

    /// Decrypt the encrypted message using the provided key
    pub fn decrypt(&self, decryption_key: &[u8]) -> Vec<u8> {
        let decryption_key_array = GenericArray::from_slice(&decryption_key[..16]);
        let nonce = GenericArray::from_slice(&self.params.iv);

        let mut cipher = Ctr128BE::<Aes128>::new(decryption_key_array, nonce);
        let mut decrypted_data = self.message.clone();
        cipher.apply_keystream(&mut decrypted_data);

        decrypted_data
    }
}
