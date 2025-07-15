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

/// Spec:
/// - [ERC-2335: BLS12-381 Keystore](https://eips.ethereum.org/EIPS/eip-2335)
///
/// References:
/// - https://github.com/ChainSafe/bls-keystore
///
/// A keystore containing an encrypted BLS private key
pub struct KeyStore {
    /// Version of the keystore format. Currently, the spec defines only one version, which is 4.
    /// Left as u32 for backward compatibility.
    version: u32,
    /// The uuid field is a 128-bit (16-byte) identifier as specified by RFC 4122
    uuid: Uuid,
    description: Option<String>,
    /// Path defined by https://eips.ethereum.org/EIPS/eip-2334.
    ///
    /// The path field in an EIP-2335 keystore is a BIP-32-style derivation path string
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
    dklen: u32,
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
    dklen: u32,
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
