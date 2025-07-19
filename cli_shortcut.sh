#!/bin/bash
# Example: ./cli_shortcut.sh subcommand --option value

cargo run --manifest-path crates/cli/Cargo.toml -- "$@"
