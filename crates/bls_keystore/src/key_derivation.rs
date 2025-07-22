use thiserror::Error;

use crate::{keystore::KdfLiteral, scrypt::ScryptKdfToDerivedKeyError};

#[derive(Debug, Error)]
pub enum KeyDerivationError {
    #[error(transparent)]
    Scrypt(ScryptKdfToDerivedKeyError),
    #[error("")]
    Pbkdf2(),
    // TODO: should we just remove dklen from the params and hardcode it as 32?
    #[error("ERC-2335 requires dklen to be 32 bytes, but got {dklen} bytes")]
    InvalidDklen { dklen: u8 },
}

/// Trait that describes the uniform beahavior of key derivation functions such as PBKDF2 and Scrypt.
pub trait KeyDerivationFunction {
    /// Derive a 32-byte key from a password and salt (16 bytes for AES + 16 bytes for checksum)
    fn derive_key(&self, password: &[u8]) -> Result<[u8; 32], KeyDerivationError>;

    /// Get the function identifier for serialization
    fn kdf(&self) -> KdfLiteral;

    /// Get the salt used for key derivation
    fn salt(&self) -> Vec<u8>;
}
