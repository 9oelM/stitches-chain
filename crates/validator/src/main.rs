use blst::min_pk::SecretKey;
use clap::{Parser, Subcommand};
use hex::encode;
use rand::RngCore;

const KEYGEN_SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";

#[derive(Parser)]
#[command(name = "Stitches Validator Client")]
#[command(about = "CLI tool for validator client operations", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new BLS private/public key pair
    Keygen,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Keygen => {
        }
    }
}

// fn generate_keypair() {
//     let mut ikm = [0u8; 32];
//     rand::thread_rng().fill_bytes(&mut ikm);

//     let sk = SecretKey::key_gen(&ikm, &[]).expect("Failed to generate secret key");
//     let pk = sk.sk_to_pk();

//     println!("Private key (hex): {}", encode(sk.to_bytes()));
//     println!("Public key  (hex): {}", encode(pk.to_bytes()));
// }
