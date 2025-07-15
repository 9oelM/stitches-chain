use thiserror::Error;
use uuid::Uuid;

// TODO: more precise types
const HMAC_SHA256: &str = "hmac-sha256";

/// String identifier that tells the client code or parser
/// which algorithm to use for KDF, cipher, and checksum
/// operations when decrypting or verifying the keystore.
pub enum CryptoFunction {
    Pbkdf2,
    Sha256,
    Aes128Ctr,
    Scrypt,
}

pub enum KdfModule {
    Pbkdf2(Pbkdf2KdfModule),
    Scrypt(ScryptKdfModule),
}

#[derive(Debug, Error)]
pub enum CreateScryptKdfModuleParamsError {
    #[error("Insecure scrypt parameters: n * r * p must be at least 2^20")]
    InsecureParameters,
    #[error(
        "Invalid scrypt parameters: n ({n}) must be less than 2^(128 * {r} / 8). Got n={n}, r={r}, 2^(128 * {r} / 8)={upperbound}"
    )]
    InvalidN { n: u32, r: u32, upperbound: u64 },
}

/// Spec:
/// - [ERC-2335: BLS12-381 Keystore](https://eips.ethereum.org/EIPS/eip-2335)
///
/// References:
/// - https://github.com/ChainSafe/bls-keystore
/// - https://github.com/ethereum/staking-deposit-cli/tree/master/staking_deposit/key_handling
/// - https://github.com/roynalnaruto/eth-keystore-rs/blob/85ea8cd5b4dbfcdb3af50e1835540fee83d3b966/src/keystore.rs (Old keystore format)
/// - https://github.com/RustCrypto/password-hashes (Password hashing algorithms, like PBKDF2, Scrypt)
///
/// A keystore containing an encrypted BLS private key
pub struct KeyStore {
    /// Version of the keystore format. Currently, [the spec](https://eips.ethereum.org/EIPS/eip-2335) defines only one version, which is 4.
    /// Left as u32 for backward compatibility.
    version: u32,
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
    path: String,
    /// The spec does not specify the length of the public key.
    /// We leave it as a Vec<u8> to allow for flexibility.
    /// For example, it can be 48 bytes for BLS12-381 (compressed form).
    pubkey: Vec<u8>,
    crypto: KeyStoreCrypto,
}

pub struct KeyStoreCrypto {
    kdf: KdfModule,
    checksum: Sha2ChecksumModule,
    cipher: Aes128CtrCipherModule,
}

pub struct Pbkdf2KdfModuleParams {
    dklen: u8,
    c: u32,
    /// Spec does not specify the length of the salt, so we use a Vec<u8>
    salt: Vec<u8>,
}

pub struct Pbkdf2KdfModule {
    params: Pbkdf2KdfModuleParams,
}

pub struct ScryptKdfModuleParams {
    n: u32,
    r: u32,
    p: u32,
    dklen: u8,
    /// Spec does not specify the length of the salt, so we use a Vec<u8>
    salt: Vec<u8>,
}

pub struct ScryptKdfModule {
    params: ScryptKdfModuleParams,
}

// Note: deliberately left empty
struct Sha2ChecksumModuleParams {}

struct Sha2ChecksumModule {
    params: Sha2ChecksumModuleParams,
}

pub struct Aes128CtrCipherModuleParams {
    iv: String,
}

pub struct Aes128CtrCipherModule {
    params: Aes128CtrCipherModuleParams,
    message: String,
}

impl ScryptKdfModule {
    fn new(params: ScryptKdfModuleParams) -> Self {
        ScryptKdfModule { params }
    }
}
impl TryFrom<ScryptKdfModuleParams> for ScryptKdfModule {
    type Error = CreateScryptKdfModuleParamsError;

    /// Refer to https://github.com/ethereum/staking-deposit-cli/blob/948d3fc358fdae54ff47dd8045206276b0b6b914/staking_deposit/utils/crypto.py#L21-L26
    /// for parameter validation
    fn try_from(params: ScryptKdfModuleParams) -> Result<Self, Self::Error> {
        if params.n * params.r * params.p < 2u32.pow(20) {
            return Err(CreateScryptKdfModuleParamsError::InsecureParameters);
        }

        let upperbound = 2u32.pow(128 * params.r / 8);

        if params.n >= upperbound {
            return Err(CreateScryptKdfModuleParamsError::InvalidN {
                n: params.n,
                r: params.r,
                upperbound: upperbound as u64,
            });
        }
        Ok(Self::new(params))
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
