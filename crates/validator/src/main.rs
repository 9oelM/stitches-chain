mod cli;


use bls_keystore::pbkdf::{self, Pbkdf2Kdf};
use clap::{Parser, Subcommand};
use rand::Rng;

use crate::cli::keygen::{self, Pbkdf2KeygenArgs, ScryptKeygenArgs};

#[derive(Parser)]
#[command(name = "Stitches Validator Client")]
#[command(about = "CLI tool for validator client operations", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new BLS private/public key pair and store in a keystore file locked based on a password based on PBKDF2 algorithm
    Pbkdf2Keygen(Pbkdf2KeygenArgs),
    /// Generate a new BLS private/public key pair and store in a keystore file locked with a password based on Scrypt algorithm
    ScryptKeygen(ScryptKeygenArgs),
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Pbkdf2Keygen(args) => {
            if args.keystore_path.exists() {
                eprintln!("Error: Keystore path already exists: {}", args.keystore_path.display());
                std::process::exit(1);
            }

            let account = keygen::BlsAccount::new(args.account_index);

            let pbkdf2kdf: Pbkdf2Kdf = pbkdf::Pbkdf2KdfParamsBuilder::new(
                args.param_c,
                rand::rng().random::<[u8; 32]>().to_vec(),
                args.param_prf.clone().into(),
            )
            .try_into()
            .expect("Failed to create PBKDF2 parameters");

            let keystore = bls_keystore::keystore::KeyStore::encrypt(
                &account.sk.to_bytes(),
                args.password.as_bytes(),
                account.path.clone(),
                None,
                None,
                pbkdf2kdf,
            ).expect("Failed to create keystore");

            let mut complete_keystore_path = args.keystore_path.display().to_string();
            if args.keystore_path.extension().and_then(|s| s.to_str()) != Some("json") {
                complete_keystore_path = format!("{}.json", args.keystore_path.display());
            }

            std::fs::write(&complete_keystore_path, serde_json::to_string_pretty(&keystore).expect("Failed to serialize keystore")).expect("Failed to write keystore to file");
        }
        Commands::ScryptKeygen(args) => {}
    }
}
