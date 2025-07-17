//! BLS12-381 Keystore Implementation (ERC-2335)
//!
//! 1. Password + Salt ──► PBKDF2/Scrypt ──► Derived Key (32 bytes)
//! 2. Private Key + First 16 bytes of Derived Key ──► AES-128-CTR ──► Encrypted Key
//! 3. Encrypted Key + Last 16 bytes of Derived Key ──► SHA-256 ──► Checksum

use aes::{
    Aes128,
    cipher::{KeyIvInit, StreamCipher, generic_array::GenericArray},
};
use blst::min_pk::SecretKey;
use ctr::Ctr128BE;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    derivation_path::DerivationPath,
    key_derivation::{KeyDerivationError, KeyDerivationMethod},
    pbkdf::Pbkdf2Kdf,
    scrypt::ScryptKdf,
};

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

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error(transparent)]
    KeyDerivationError(KeyDerivationError),
    #[error("checksum verification failed")]
    ChecksumMismatch,
    #[error("invalid secret key length, expected 32 bytes but got {actual}")]
    InvalidSecretKeyLength { actual: usize },
    #[error("invalid checksum length, expected 32 bytes but got {actual}")]
    InvalidChecksumLength { actual: usize },
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
#[derive(Serialize, Deserialize)]
pub struct KeyStore<KDF: KeyDerivationMethod> {
    /// Version of the keystore format. Currently, [the spec](https://eips.ethereum.org/EIPS/eip-2335) defines only one version, which is 4.
    /// Left as u8 for backward compatibility.
    pub version: u8,
    /// The uuid field is a 128-bit (16-byte) identifier as specified by RFC 4122
    pub uuid: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
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
    pub path: DerivationPath,
    /// The spec does not specify the length of the public key.
    /// We leave it as a Vec<u8> to allow for flexibility.
    /// For example, it can be 48 bytes for BLS12-381 (compressed form).
    #[serde(with = "hex")]
    pub pubkey: Vec<u8>,
    /// Cryptographic functions used for key derivation, encryption, and checksum.
    pub crypto: KeyStoreCrypto<KDF>,
}

#[derive(Serialize, Deserialize)]
pub struct KeyStoreCrypto<KDF> {
    pub kdf: KDF,
    pub checksum: Sha2Checksum,
    pub cipher: Aes128CtrCipher,
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
                .map_err(|_| EncryptError::InvalidAesIvLength)?,
            None => rand::rng().random::<[u8; 16]>(),
        };
        let decryption_key = kdf
            .derive_key(password)
            .map_err(EncryptError::KeyDerivationError)?;
        let key = GenericArray::from_slice(&decryption_key[..16]);
        let nonce = GenericArray::from_slice(&aes_iv);

        let mut cipher = Ctr128BE::<Aes128>::new(key, nonce);
        let mut cipher_message = secret_key.to_vec();
        cipher.apply_keystream(&mut cipher_message);

        let mut hasher = sha2::Sha256::new();
        hasher.update(&decryption_key[16..32]);
        hasher.update(&cipher_message);

        let checksum_message = hasher.finalize().to_vec();
        let sk = SecretKey::from_bytes(secret_key).map_err(|blst_error| {
            EncryptError::SecretKeyConversionBlstError {
                e: blst_error as u32,
            }
        })?;
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

    /// Decrypt a BLS secret key from an ERC-2335 keystore format.
    pub fn decrypt(&self, password: &[u8]) -> Result<[u8; 32], DecryptError> {
        // Derive the decryption key using the same KDF and password
        let decryption_key = self
            .crypto
            .kdf
            .derive_key(password)
            .map_err(DecryptError::KeyDerivationError)?;

        // Verify checksum before decryption
        let mut hasher = sha2::Sha256::new();
        hasher.update(&decryption_key[16..32]);
        hasher.update(&self.crypto.cipher.message);
        let computed_checksum: [u8; 32] = hasher.finalize().into();
        let supplied_checksum: [u8; 32] = self
            .crypto
            .checksum
            .message
            .clone()
            .try_into()
            .map_err(|v: Vec<u8>| DecryptError::InvalidChecksumLength { actual: v.len() })?;

        if computed_checksum != supplied_checksum {
            return Err(DecryptError::ChecksumMismatch);
        }

        // Decrypt the secret key using AES-128-CTR
        let key = GenericArray::from_slice(&decryption_key[..16]);
        let nonce = GenericArray::from_slice(&self.crypto.cipher.params.iv);

        let mut cipher = Ctr128BE::<Aes128>::new(key, nonce);
        let mut decrypted_key = self.crypto.cipher.message.clone();
        cipher.apply_keystream(&mut decrypted_key);

        // Validate the decrypted key length (BLS private keys should be 32 bytes)
        let decrypted_key: [u8; 32] = decrypted_key
            .try_into()
            .map_err(|v: Vec<u8>| DecryptError::InvalidSecretKeyLength { actual: v.len() })?;

        Ok(decrypted_key)
    }
}

#[derive(Debug, Clone)]
pub struct Sha256Literal {}

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

/// Testing vectors came from https://github.com/ethereum/staking-deposit-cli/tree/948d3fc358fdae54ff47dd8045206276b0b6b914/tests/test_key_handling/test_key_derivation
#[cfg(test)]
mod tests {
    use super::*;
    use crate::pbkdf::{Pbkdf2Kdf, Pbkdf2KdfParamsBuilder, PseudoRandomFunction};
    use hex;
    use serde_json;
    use std::str::FromStr;

    #[test]
    fn test_keystore_pbkdf2_serialization() {
        // Create a keystore with PBKDF2 using test vector parameters
        let secret_key =
            hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        let password = &[
            0x74, 0x65, 0x73, 0x74, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0xf0, 0x9f,
            0x94, 0x91,
        ];
        let salt = hex::decode("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
            .unwrap();
        let iv = hex::decode("264daa3f303d7259501c93d997d84fe6").unwrap();
        let path = DerivationPath::from_str("m/12381/60/0/0").unwrap();

        let pbkdf2_params = Pbkdf2KdfParamsBuilder {
            c: 262144,
            salt,
            prf: PseudoRandomFunction::Sha256,
        };
        let kdf = Pbkdf2Kdf::try_from(pbkdf2_params).unwrap();

        let keystore = KeyStore::encrypt(
            &secret_key,
            password,
            path,
            Some("This is a test keystore that uses PBKDF2 to secure the secret.".to_string()),
            Some(iv),
            kdf,
        )
        .unwrap();

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&keystore).unwrap();

        // Parse back to verify structure
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Verify the JSON structure matches ERC-2335 format
        assert_eq!(parsed["version"], 4);
        assert_eq!(parsed["path"], "m/12381/60/0/0");
        assert_eq!(
            parsed["pubkey"],
            "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07"
        );

        // Verify crypto structure
        assert_eq!(parsed["crypto"]["kdf"]["function"], "pbkdf2");
        assert_eq!(parsed["crypto"]["kdf"]["params"]["dklen"], 32);
        assert_eq!(parsed["crypto"]["kdf"]["params"]["c"], 262144);
        assert_eq!(parsed["crypto"]["kdf"]["params"]["prf"], "hmac-sha256");
        assert_eq!(
            parsed["crypto"]["kdf"]["params"]["salt"],
            "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
        );
        assert_eq!(parsed["crypto"]["kdf"]["message"], "");

        assert_eq!(parsed["crypto"]["checksum"]["function"], "sha256");
        assert_eq!(parsed["crypto"]["cipher"]["function"], "aes-128-ctr");
        assert_eq!(
            parsed["crypto"]["cipher"]["params"]["iv"],
            "264daa3f303d7259501c93d997d84fe6"
        );

        // Test deserialization roundtrip
        let deserialized_keystore: KeyStore<Pbkdf2Kdf> = serde_json::from_str(&json).unwrap();

        // Verify the deserialized keystore can decrypt correctly
        let decrypted_key = deserialized_keystore.decrypt(password).unwrap();
        assert_eq!(decrypted_key.to_vec(), secret_key);
    }

    #[test]
    fn test_keystore_deserialization_from_test_vectors() {
        // Test deserialization from the actual PBKDF2 test vector
        let pbkdf2_json = r#"{
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 262144,
                        "prf": "hmac-sha256",
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
                }
            },
            "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "path": "m/12381/60/0/0",
            "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
            "version": 4
        }"#;

        let keystore: KeyStore<Pbkdf2Kdf> = serde_json::from_str(pbkdf2_json).unwrap();

        // Verify the keystore was deserialized correctly
        assert_eq!(keystore.version, 4);
        assert_eq!(keystore.path.to_string(), "m/12381/60/0/0");
        assert_eq!(
            keystore.description,
            Some("This is a test keystore that uses PBKDF2 to secure the secret.".to_string())
        );

        // Test decryption with the correct password
        let password = &[
            0x74, 0x65, 0x73, 0x74, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0xf0, 0x9f,
            0x94, 0x91,
        ];
        let decrypted_key = keystore.decrypt(password).unwrap();
        let expected_key =
            hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        assert_eq!(decrypted_key.to_vec(), expected_key);
    }
}
