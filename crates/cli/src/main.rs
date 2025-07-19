use clap::{Parser, Subcommand, command};

#[derive(Subcommand)]
pub enum Commands {
    /// Run a validator client command
    Validator(validator::cli::Cli),
    /// Run a beacon node command
    BeaconNode(consensus::cli::Cli),
}

#[derive(Parser)]
#[command(name = "Stitches Validator Client")]
#[command(about = "CLI tool for validator client operations", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Validator(validator_cli) => {
            validator::cli::handle_validator_command(validator_cli);
        }
        Commands::BeaconNode(beacon_node_cli) => {}
    }
}
