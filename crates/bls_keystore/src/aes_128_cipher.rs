use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aes128CtrCipherParams {
    /// Initialization Vector (IV) for AES-128-CTR mode
    ///
    /// Must be 16 bytes (128 bits) and unique for each encryption
    #[serde(with = "hex")]
    pub iv: [u8; 16],
}

/// Takes the derived key from PBKDF2 or Scrypt to encrypts/decrypt the private key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aes128CtrCipher {
    pub params: Aes128CtrCipherParams,
    #[serde(with = "hex")]
    pub message: Vec<u8>,
}
