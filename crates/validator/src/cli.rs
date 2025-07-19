use clap::{Parser, Subcommand};

use crate::keygen::{Keygen, Pbkdf2KeygenArgs, ScryptKeygenArgs};

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a new BLS private/public key pair and store in a keystore file locked based on a password based on PBKDF2 algorithm
    Pbkdf2Keygen(Pbkdf2KeygenArgs),
    /// Generate a new BLS private/public key pair and store in a keystore file locked with a password based on Scrypt algorithm
    ScryptKeygen(ScryptKeygenArgs),
}

pub fn handle_validator_command(cli: &Cli) {
    match &cli.command {
        Commands::Pbkdf2Keygen(args) => {
            args.run();
        }
        Commands::ScryptKeygen(args) => {
            args.run();
        }
    }
}
