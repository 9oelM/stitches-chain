use pbkdf2::pbkdf2_hmac;
use sha2;
use thiserror::Error;

use crate::{
    key_derivation::{KeyDerivationError, KeyDerivationMethod},
    keystore::CryptoFunction,
};

pub enum PseudoRandomFunction {
    Sha256,
    Sha512,
}

#[derive(Debug, Error)]
pub enum CreatePbkdfParamsError {
    #[error("The PBKDF2 parameters chosen are not secure: c must be >= 2^18, but got c={c}")]
    InsecureParameters { c: u32 },
}

/// Key derivation function.
///
/// Derives a key from a password
pub struct Pbkdf2Kdf {
    params: Pbkdf2KdfParams,
}

pub struct Pbkdf2KdfParams {
    /// Output of the derived key in bytes.
    ///
    /// For example, dklen = 16 means that the derived key will be 16 bytes long.
    ///
    /// For AES-128-CTR, dklen must be 16 (bytes).
    dklen: u8,
    c: u32,
    /// Spec does not specify the length of the salt, so we use a Vec<u8>
    salt: Vec<u8>,
    /// Pseudo-random function to use
    prf: PseudoRandomFunction,
}

impl Pbkdf2Kdf {
    fn new(params: Pbkdf2KdfParams) -> Self {
        Self { params }
    }
}

impl KeyDerivationMethod for Pbkdf2Kdf {
    /// Derives a key from the given password and salt using PBKDF2.
    fn derive_key(&self, password: &[u8]) -> Result<Vec<u8>, KeyDerivationError> {
        let mut output = vec![0u8; self.params.dklen as usize];

        match self.params.prf {
            PseudoRandomFunction::Sha256 => {
                pbkdf2_hmac::<sha2::Sha256>(
                    password,
                    &self.params.salt,
                    self.params.c,
                    &mut output,
                );
            }
            PseudoRandomFunction::Sha512 => {
                pbkdf2_hmac::<sha2::Sha512>(
                    password,
                    &self.params.salt,
                    self.params.c,
                    &mut output,
                );
            }
        }

        Ok(output)
    }

    fn crypto_function(&self) -> CryptoFunction {
        CryptoFunction::Pbkdf2
    }

    fn salt(&self) -> Vec<u8> {
        self.params.salt.clone()
    }
}

impl TryFrom<Pbkdf2KdfParams> for Pbkdf2Kdf {
    type Error = CreatePbkdfParamsError;

    /// Refer to https://github.com/ethereum/staking-deposit-cli/blob/948d3fc358fdae54ff47dd8045206276b0b6b914/staking_deposit/utils/crypto.py#L41C27-L41C71
    /// for parameter validation
    fn try_from(params: Pbkdf2KdfParams) -> Result<Self, Self::Error> {
        if let PseudoRandomFunction::Sha256 = params.prf {
            if params.c < (2_u32.pow(18)) {
                return Err(CreatePbkdfParamsError::InsecureParameters { c: params.c });
            }
        }

        Ok(Self::new(Pbkdf2KdfParams {
            dklen: params.dklen,
            c: params.c,
            salt: params.salt,
            prf: params.prf,
        }))
    }
}
