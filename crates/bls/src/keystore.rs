//! BLS12-381 Keystore Implementation (ERC-2335)
//!
//! 1. Password + Salt ──► PBKDF2/Scrypt ──► Derived Key (16 bytes)
//! 2. Private Key + Derived Key ──► AES-128-CTR ──► Encrypted Key
//! 3. Encrypted Key + Derived Key ──► SHA-256 ──► Checksum

use aes::{
    Aes128,
    cipher::{KeyIvInit, StreamCipher, generic_array::GenericArray},
};
use blst::min_pk::SecretKey;
use ctr::Ctr128BE;
use rand::Rng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    derivation_path::DerivationPath,
    key_derivation::{KeyDerivationError, KeyDerivationMethod},
    pbkdf::Pbkdf2Kdf,
    scrypt::ScryptKdf,
};

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
pub enum Kdf {
    Pbkdf2(Pbkdf2Kdf),
    Scrypt(ScryptKdf),
}

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error(transparent)]
    KeyDerivationError(KeyDerivationError),
    #[error("blst error encountered while converting secret key: {e}")]
    SecretKeyConversionBlstError { e: u32 },
    #[error("invalid AES IV length, expected 16 bytes")]
    InvalidAesIvLength,
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
pub struct KeyStore<KDF: KeyDerivationMethod> {
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
    crypto: KeyStoreCrypto<KDF>,
}

pub struct KeyStoreCrypto<KDF> {
    kdf: KDF,
    checksum: Sha2Checksum,
    cipher: Aes128CtrCipher,
}

impl<KDF: KeyDerivationMethod> KeyStore<KDF> {
    /// Encrypt a BLS secret key in an ERC-2335 keystore format.
    pub fn encrypt(
        secret_key: &[u8],
        password: &[u8],
        path: DerivationPath,
        description: Option<String>,
        aes_iv: Option<Vec<u8>>,
        kdf: KDF,
    ) -> Result<Self, EncryptError> {
        let uuid = Uuid::new_v4();
        let aes_iv: [u8; 16] = match aes_iv {
            Some(iv) => iv
                .try_into()
                .map_err(|_| EncryptError::InvalidAesIvLength)?, // Handle invalid AES IV length
            None => rand::rng().random::<[u8; 16]>(),
        };
        let decryption_key = kdf
            .derive_key(password)
            .map_err(EncryptError::KeyDerivationError)?; // Handle key derivation error
        let key = GenericArray::from_slice(&decryption_key[..16]);
        let nonce = GenericArray::from_slice(&aes_iv);

        let mut cipher = Ctr128BE::<Aes128>::new(key, nonce);
        let mut cipher_message = secret_key.to_vec();
        cipher.apply_keystream(&mut cipher_message);

        let mut hasher = Sha256::new();
        hasher.update(&decryption_key[16..32]);
        hasher.update(&cipher_message);

        let checksum_message = hasher.finalize().to_vec();
        let sk = SecretKey::from_bytes(secret_key).map_err(|blst_error| {
            EncryptError::SecretKeyConversionBlstError {
                e: blst_error as u32,
            }
        })?; // Handle secret key conversion error
        let pubkey = sk.sk_to_pk().to_bytes();

        let keystore_crypto = KeyStoreCrypto {
            kdf,
            checksum: Sha2Checksum {
                message: checksum_message,
                params: Sha2ChecksumParams {},
            },
            cipher: Aes128CtrCipher {
                params: Aes128CtrCipherParams { iv: aes_iv },
                message: cipher_message,
            },
        };

        Ok(KeyStore {
            version: 4,
            uuid,
            description,
            path,
            pubkey: pubkey.to_vec(),
            crypto: keystore_crypto,
        })
    }
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
    message: Vec<u8>,
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
    /// Encrypted message
    message: Vec<u8>,
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
