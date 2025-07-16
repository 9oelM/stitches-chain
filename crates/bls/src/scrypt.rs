use thiserror::Error;

use crate::{
    key_derivation::{KeyDerivationError, KeyDerivationMethod},
    keystore::CryptoFunction,
};

#[derive(Debug, Error)]
pub enum CreateScryptKdfParamsError {
    #[error("Insecure scrypt parameters: n * r * p must be at least 2^20")]
    InsecureParameters,
    #[error(
        "Invalid scrypt parameters: n ({n}) must be less than 2^(128 * {r} / 8). Got n={n}, r={r}, 2^(128 * {r} / 8)={upperbound}"
    )]
    InvalidNSize { n: u32, r: u32, upperbound: u64 },
    #[error("Invalid scrypt parameters: n ({n}) must be less than 2**8 - 1")]
    InvalidNSize2 { n: u32 },
    #[error("Invalid scrypt parameters: n ({n}) must be a power of 2")]
    InvalidNPower { n: u32 },
}

#[derive(Debug, Error)]
pub enum ScryptKdfToDerivedKeyError {
    #[error(transparent)]
    InvalidParams(#[from] scrypt::errors::InvalidParams),
    #[error(transparent)]
    InvalidOutputLen(#[from] scrypt::errors::InvalidOutputLen),
}

/// Unprocessed parameters for the Scrypt key derivation function (KDF).
pub struct ScryptKdfParamsBuilder {
    /// CPU/Memory cost parameter.
    ///
    /// Must be a power of 2.
    ///
    /// Higher values increase memory usage and CPU time.
    ///
    /// Example value: 2**18 = 262144
    n: u32,
    /// Block size.
    ///
    /// Affects how memory is accessed.
    ///
    /// Larger values increase memory usage.
    ///
    /// Example value: 8
    r: u32,
    /// Parallelization factor.
    ///
    /// Number of parallel processing threads.
    ///
    /// Each thread uses 128 * r bytes of memory.
    ///
    /// Example value: 1
    p: u32,
    /// Output of the derived key in bytes.
    ///
    /// For example, dklen = 16 means that the derived key will be 16 bytes long.
    ///
    /// For AES-128-CTR, dklen must be 16 (bytes).
    dklen: u8,
    /// Spec does not specify the length of the salt, so we use a `Vec<u8>`
    salt: Vec<u8>,
}

/// Parameters for the Scrypt key derivation function (KDF).
pub struct ScryptKdfParams {
    /// Log2 of CPU/Memory cost parameter 'n'.
    log2_n: u8,
    /// Block size.
    ///
    /// Affects how memory is accessed.
    ///
    /// Larger values increase memory usage.
    ///
    /// Example value: 8
    r: u32,
    /// Parallelization factor.
    ///
    /// Number of parallel processing threads.
    ///
    /// Each thread uses 128 * r bytes of memory.
    ///
    /// Example value: 1
    p: u32,
    /// Output of the derived key in bytes.
    ///
    /// For example, dklen = 16 means that the derived key will be 16 bytes long.
    ///
    /// For AES-128-CTR, dklen must be 16 (bytes).
    dklen: u8,
    /// Spec does not specify the length of the salt, so we use a `Vec<u8>`
    salt: Vec<u8>,
}

/// Similar to PBKDF2, but uses Scrypt algorithm.
///
/// More resistant to hardware attacks than PBKDF2.
pub struct ScryptKdf {
    params: ScryptKdfParams,
}

impl ScryptKdf {
    fn new(params: ScryptKdfParams) -> Self {
        ScryptKdf { params }
    }
}

impl KeyDerivationMethod for ScryptKdf {
    fn derive_key(&self, password: &[u8]) -> Result<Vec<u8>, KeyDerivationError> {
        let mut derived_key = vec![0u8; self.params.dklen as usize];

        let scrypt_params = scrypt::Params::new(
            self.params.log2_n,
            self.params.r,
            self.params.p,
            self.params.dklen.into(),
        )
        .map_err(|e| KeyDerivationError::Scrypt(ScryptKdfToDerivedKeyError::InvalidParams(e)))?;
        scrypt::scrypt(
            password,
            &self.params.salt,
            &scrypt_params,
            derived_key.as_mut_slice(),
        )
        .map_err(|e| KeyDerivationError::Scrypt(ScryptKdfToDerivedKeyError::InvalidOutputLen(e)))?;
        Ok(derived_key)
    }

    fn crypto_function(&self) -> CryptoFunction {
        CryptoFunction::Scrypt
    }

    fn salt(&self) -> Vec<u8> {
        self.params.salt.clone()
    }
}

impl TryFrom<ScryptKdfParamsBuilder> for ScryptKdf {
    type Error = CreateScryptKdfParamsError;

    /// Refer to https://github.com/ethereum/staking-deposit-cli/blob/948d3fc358fdae54ff47dd8045206276b0b6b914/staking_deposit/utils/crypto.py#L21-L26
    /// for parameter validation
    fn try_from(params: ScryptKdfParamsBuilder) -> Result<Self, Self::Error> {
        if params.n * params.r * params.p < 2u32.pow(20) {
            return Err(CreateScryptKdfParamsError::InsecureParameters);
        }

        let upperbound = 2u32.pow(128 * params.r / 8);

        if params.n >= upperbound {
            return Err(CreateScryptKdfParamsError::InvalidNSize {
                n: params.n,
                r: params.r,
                upperbound: upperbound as u64,
            });
        }

        // because ilog2 returns the base 2 logarithm of the number, rounded down.
        // ensure that n is a power of 2 before calling ilog2
        if !params.n.is_power_of_two() {
            return Err(CreateScryptKdfParamsError::InvalidNPower { n: params.n });
        }

        let log2_n: u8 = params
            .n
            .ilog2()
            .try_into()
            .map_err(|_| CreateScryptKdfParamsError::InvalidNSize2 { n: params.n })?;

        Ok(Self::new(ScryptKdfParams {
            log2_n,
            r: params.r,
            p: params.p,
            dklen: params.dklen,
            salt: params.salt,
        }))
    }
}
