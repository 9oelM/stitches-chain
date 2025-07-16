//! BLS12-381 Keystore Implementation (ERC-2335)
//!
//! 1. Password + Salt ──► PBKDF2/Scrypt ──► Derived Key (16 bytes)
//! 2. Private Key + Derived Key ──► AES-128-CTR ──► Encrypted Key
//! 3. Encrypted Key + Derived Key ──► SHA-256 ──► Checksum

use thiserror::Error;
use uuid::Uuid;

use crate::derivation_path::DerivationPath;

// TODO: more precise types
const HMAC_SHA256: &str = "hmac-sha256";

/// String identifier that tells the client code or parser
/// which algorithm to use for KDF, cipher, and checksum
/// operations when decrypting or verifying the keystore.
pub enum CryptoFunction {
    Pbkdf2,
    Scrypt,
    Sha256,
    Aes128Ctr,
}

/// Key derivation functions (KDF).
pub enum KdfModule {
    Pbkdf2(Pbkdf2Kdf),
    Scrypt(ScryptKdf),
}

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

/// Spec:
/// - [ERC-2335: BLS12-381 Keystore](https://eips.ethereum.org/EIPS/eip-2335)
///
/// This spec isn't in the 'final' state yet, but it's already become the de facto
/// standard for BLS keystores, as we can see in the
/// [Ethereum Foundation's official staking-deposit-cli](https://github.com/ethereum/staking-deposit-cli/tree/master/staking_deposit/key_handling).
///
/// This struct describes a keystore containing an encrypted BLS private key.
/// The actual algorithm has nothing to do with BLS.
///
/// References:
/// - https://github.com/ChainSafe/bls-keystore
/// - https://github.com/ethereum/staking-deposit-cli/tree/master/staking_deposit/key_handling
/// - https://github.com/Layr-Labs/bn254-bls-keystore-rs
/// - https://github.com/roynalnaruto/eth-keystore-rs/blob/85ea8cd5b4dbfcdb3af50e1835540fee83d3b966/src/keystore.rs (Old keystore format)
/// - https://github.com/RustCrypto/password-hashes (Password hashing algorithms, like PBKDF2, Scrypt)
///
pub struct KeyStore {
    /// Version of the keystore format. Currently, [the spec](https://eips.ethereum.org/EIPS/eip-2335) defines only one version, which is 4.
    /// Left as u8 for backward compatibility.
    version: u8,
    /// The uuid field is a 128-bit (16-byte) identifier as specified by RFC 4122
    uuid: Uuid,
    description: Option<String>,
    /// Path defined by https://eips.ethereum.org/EIPS/eip-2334.
    ///
    /// The path field in an EIP-2335 keystore is a [BIP-32](https://en.bitcoin.it/wiki/BIP_0032)-style derivation path string
    /// that indicates how this key was derived from a master seed in a hierarchical
    /// deterministic (HD) key tree.
    ///
    /// It records where in the tree this key lives.
    /// If you use an HD wallet (like from a mnemonic phrase) you can deterministically
    /// derive a huge number of private keys from one master seed.
    ///
    /// The path records exactly how to re-derive this key if needed.
    /// If you lose the raw private key but have the seed and the path, you can recreate
    /// the exact same private/public keypair.
    path: DerivationPath,
    /// The spec does not specify the length of the public key.
    /// We leave it as a Vec<u8> to allow for flexibility.
    /// For example, it can be 48 bytes for BLS12-381 (compressed form).
    pubkey: Vec<u8>,
    /// Cryptographic functions used for key derivation, encryption, and checksum.
    crypto: KeyStoreCrypto,
}

pub struct KeyStoreCrypto {
    kdf: KdfModule,
    checksum: Sha2Checksum,
    cipher: Aes128CtrCipher,
}

pub struct Pbkdf2KdfParams {
    dklen: u8,
    c: u32,
    /// Spec does not specify the length of the salt, so we use a Vec<u8>
    salt: Vec<u8>,
}

/// Key derivation function.
///
/// Derives a key from a password
pub struct Pbkdf2Kdf {
    params: Pbkdf2KdfParams,
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

// Note: deliberately left empty
struct Sha2ChecksumParams {}

/// Used for checksum verification.
///
/// Creates a hash of the encrypted data to verify integrity.
///
/// Helps detect if the encrypted data has been tampered with or corrupted.
struct Sha2Checksum {
    params: Sha2ChecksumParams,
}

pub struct Aes128CtrCipherParams {
    /// Initialization Vector (IV) for AES-128-CTR mode
    ///
    /// Must be 16 bytes (128 bits) and unique for each encryption
    iv: [u8; 16],
}

/// Takes the derived key from PBKDF2 or Scrypt to encrypts/decrypt the private key
pub struct Aes128CtrCipher {
    params: Aes128CtrCipherParams,
    message: String,
}

impl ScryptKdf {
    fn new(params: ScryptKdfParams) -> Self {
        ScryptKdf { params }
    }

    pub fn to_derived_key(&self, password: &[u8]) -> Result<Vec<u8>, ScryptKdfToDerivedKeyError> {
        // Use the Scrypt algorithm to derive a key from the password
        // This is a placeholder implementation; actual Scrypt derivation logic should be used
        let mut derived_key = vec![0u8; self.params.dklen as usize];

        let scrypt_params = scrypt::Params::new(
            self.params.log2_n,
            self.params.r,
            self.params.p,
            self.params.dklen.into(),
        )?;
        scrypt::scrypt(
            password,
            &self.params.salt,
            &scrypt_params,
            derived_key.as_mut_slice(),
        )?;
        Ok(derived_key)
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

/// Serialize the function to a string according to the spec
impl From<CryptoFunction> for &str {
    fn from(func: CryptoFunction) -> Self {
        match func {
            CryptoFunction::Pbkdf2 => "pbkdf2",
            CryptoFunction::Sha256 => "sha256",
            CryptoFunction::Aes128Ctr => "aes-128-ctr",
            CryptoFunction::Scrypt => "scrypt",
        }
    }
}

/// Testing vectors came from https://github.com/ethereum/staking-deposit-cli/tree/948d3fc358fdae54ff47dd8045206276b0b6b914/tests/test_key_handling/test_key_derivation
#[cfg(test)]
mod tests {}
