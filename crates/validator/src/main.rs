use std::path::PathBuf;

use bls_keystore::derivation_path::DerivationPath;
use blst::min_pk::SecretKey;
use clap::{Parser, Subcommand};
use hex::encode;
use rand::RngCore;

#[derive(Parser)]
#[command(name = "Stitches Validator Client")]
#[command(about = "CLI tool for validator client operations", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new BLS private/public key pair and store in a keystore file
    Keygen {
        /// Password to encrypt the keystore
        #[arg(short, long)]
        password: String,
        /// Output file path for the keystore JSON
        #[arg(short, long)]
        out: PathBuf,
        /// Validator account index (default: 0)
        #[arg(long, default_value_t = 0)]
        account: u32,
    },
    // Add more commands here in the future
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Keygen {
            password,
            pathbuf,
            account,
        } => generate_and_store_keypair(password, pathbuf, *account),
        // Add more command matches here in the future
    }
}

fn generate_and_store_keypair(password: &str, pathbuf: &PathBuf, account: u32) {
    let mut ikm = [0u8; 32];
    rand::rng().fill_bytes(&mut ikm);

    let sk = SecretKey::key_gen(&ikm, &[]).expect("Failed to generate secret key");
    let pk = sk.sk_to_pk();

    println!("Private key (hex): {}", encode(sk.to_bytes()));
    println!("Public key  (hex): {}", encode(pk.to_bytes()));

    // Use EIP-2334 path for validator signing key
    let path = DerivationPath::new_signing(account);

    // // Create PBKDF2 KDF parameters (example values)
    // let kdf = Pbkdf2Kdf::default();

    // // Encrypt and create keystore
    // let keystore = KeyStore::encrypt(
    //     &sk.to_bytes(),
    //     password.as_bytes(),
    //     path,
    //     Some("Validator signing key".to_string()),
    //     None, // random IV
    //     kdf,
    // )
    // .expect("Keystore encryption failed");

    // // Serialize keystore (implement serde if needed)
    // // let keystore_json = serde_json::to_string_pretty(&keystore).expect("Serialization failed");

    // // // Write to file
    // // let mut file = File::create(out).expect("Failed to create output file");
    // // file.write_all(keystore_json.as_bytes()).expect("Failed to write keystore");

    // println!("Keystore written to {}", out);
}
