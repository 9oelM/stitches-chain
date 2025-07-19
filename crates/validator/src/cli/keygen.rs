use std::{path::PathBuf, str::FromStr};

use bls_keystore::derivation_path::DerivationPath;
use blst::min_pk::{PublicKey, SecretKey};
use clap::{Args, ValueEnum};
use rand::RngCore;

#[derive(ValueEnum, Debug, Clone)]
pub enum PseudoRandomFunction {
    Sha256,
    Sha512,
}

/// Default values are from https://github.com/ethereum/staking-deposit-cli/blob/948d3fc358fdae54ff47dd8045206276b0b6b914/staking_deposit/key_handling/keystore.py#L168-L209
#[derive(Args)]
pub struct Pbkdf2KeygenArgs {
    /// Password to encrypt the keystore
    #[arg(short, long)]
    pub password: String,
    /// Output file path for the keystore JSON
    #[arg(short, long)]
    pub keystore_path: PathBuf,
    /// Validator account index
    #[arg(long, default_value = "0")]
    pub account_index: u32,
    /// Description of the keystore. Example: "test validator key"
    #[arg(long, default_value = "32")]
    pub description: String,
    /// Number of iterations to use in the PBKDF2 algorithm.
    /// Needs to be >= 2^18 for security.
    /// Example: 262144 (= 2^18)
    #[arg(long, default_value = "262144")]
    pub param_c: u32,
    /// Pseudo-random function to use
    #[arg(long, default_value = "sha256")]
    pub param_prf: PseudoRandomFunction,
}

/// Default values are from https://github.com/ethereum/staking-deposit-cli/blob/948d3fc358fdae54ff47dd8045206276b0b6b914/staking_deposit/key_handling/keystore.py#L168-L209
#[derive(Args)]
pub struct ScryptKeygenArgs {
    /// Password to encrypt the keystore
    #[arg(short, long)]
    pub password: String,
    /// Output file path for the keystore JSON
    #[arg(short, long)]
    pub keystore_path: PathBuf,
    /// Validator account index
    #[arg(long, default_value = "0")]
    pub account_index: u32,
    /// CPU/Memory cost parameter.
    ///
    /// Must be a power of 2.
    ///
    /// Higher values increase memory usage and CPU time.
    ///
    /// Example value: 2**18 = 262144
    #[arg(long, default_value = "262144")]
    pub param_n: u32,
    /// Block size.
    ///
    /// Affects how memory is accessed.
    ///
    /// Larger values increase memory usage.
    ///
    /// Example value: 8
    #[arg(long, default_value = "8")]
    pub param_r: u32,
    /// Parallelization factor.
    ///
    /// Number of parallel processing threads.
    ///
    /// Each thread uses 128 * r bytes of memory.
    ///
    /// Example value: 1
    #[arg(long, default_value = "1")]
    pub param_p: u32,
}

pub struct BlsAccount {
    pub sk: SecretKey,
    pub pk: PublicKey,
    pub path: DerivationPath,
}

impl BlsAccount {
    pub fn new(account: u32) -> Self {
        let mut ikm = [0u8; 32];
        rand::rng().fill_bytes(&mut ikm);

        let sk = SecretKey::key_gen(&ikm, &[]).expect("Failed to generate secret key");
        let pk = sk.sk_to_pk();

        // Use EIP-2334 path for validator signing key
        let path = DerivationPath::new_signing(account);

        Self { sk, pk, path }
    }
}

impl FromStr for PseudoRandomFunction {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sha256" | "hmac-sha256" => Ok(PseudoRandomFunction::Sha256),
            "sha512" | "hmac-sha512" => Ok(PseudoRandomFunction::Sha512),
            _ => Err(format!("Invalid PRF: {s}. Use 'sha256' or 'sha512'")),
        }
    }
}

/// We dont want to make `bls_keystore::pbkdf::PseudoRandomFunction` derive `ValueEnum`
/// for separation of concerns.
impl From<PseudoRandomFunction> for bls_keystore::pbkdf::PseudoRandomFunction {
    fn from(prf: PseudoRandomFunction) -> Self {
        match prf {
            PseudoRandomFunction::Sha256 => bls_keystore::pbkdf::PseudoRandomFunction::Sha256,
            PseudoRandomFunction::Sha512 => bls_keystore::pbkdf::PseudoRandomFunction::Sha512,
        }
    }
}
