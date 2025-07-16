use thiserror::Error;

use crate::{keystore::CryptoFunction, scrypt::ScryptKdfToDerivedKeyError};

#[derive(Debug, Error)]
pub enum KeyDerivationError {
    #[error(transparent)]
    Scrypt(ScryptKdfToDerivedKeyError),
    #[error("")]
    Pbkdf2(),
}

pub trait KeyDerivationMethod {
    /// Derive a key from a password and salt
    fn derive_key(&self, password: &[u8]) -> Result<Vec<u8>, KeyDerivationError>;

    /// Get the function identifier for serialization
    fn crypto_function(&self) -> CryptoFunction;

    fn salt(&self) -> Vec<u8>;
}
