use clap::{Parser, Subcommand};
use rust_config_secrets::{decrypt_file, encrypt_file, encrypt_file_in_place, generate_key};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "config-secrets")]
#[command(about = "A CLI tool for managing secrets in configuration files", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generates a secure random key for encryption
    GenKey,
    /// Encrypts secrets in a file
    EncryptFile {
        /// Path to the configuration file
        #[arg(long)]
        path: PathBuf,

        /// Encryption key
        #[arg(long)]
        key: String,

        /// Optional output path. If not provided, encrypts in-place.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Decrypts secrets in a file
    DecryptFile {
        /// Path to the configuration file
        #[arg(long)]
        path: PathBuf,

        /// Encryption key
        #[arg(long)]
        key: String,

        /// Optional output path. If not provided, prints to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Encrypts a raw value and outputs the alphanumeric encoded ciphertext
    Encrypt {
        /// The raw value to encrypt
        #[arg(long)]
        value: String,

        /// Encryption key
        #[arg(long)]
        key: String,
    },
    /// Decrypts a SECRET(...) string or a raw encoded string
    Decrypt {
        /// The value to decrypt (either SECRET(...) or raw encoded string)
        #[arg(long)]
        value: String,

        /// Encryption key
        #[arg(long)]
        key: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenKey => {
            let key = generate_key();
            println!("{}", key);
        }
        Commands::EncryptFile { path, key, output } => {
            let result = if let Some(out_path) = output {
                encrypt_file(&path, &out_path, &key)
            } else {
                encrypt_file_in_place(&path, &key)
            };

            if let Err(e) = result {
                eprintln!("Error encrypting file: {}", e);
                process::exit(1);
            } else {
                eprintln!("File encrypted successfully.");
            }
        }
        Commands::DecryptFile { path, key, output } => match decrypt_file(&path, &key) {
            Ok(content) => {
                if let Some(out_path) = output {
                    if let Err(e) = std::fs::write(&out_path, content) {
                        eprintln!("Error writing output file: {}", e);
                        process::exit(1);
                    } else {
                        eprintln!("File decrypted successfully to {:?}", out_path);
                    }
                } else {
                    print!("{}", content);
                }
            }
            Err(e) => {
                eprintln!("Error decrypting file: {}", e);
                process::exit(1);
            }
        },
        Commands::Encrypt { value, key } => {
            match rust_config_secrets::encrypt_value(&value, &key) {
                Ok(encrypted) => println!("{}", encrypted),
                Err(e) => {
                    eprintln!("Error encrypting value: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Decrypt { value, key } => {
            match rust_config_secrets::decrypt_value(&value, &key) {
                Ok(decrypted) => println!("{}", decrypted),
                Err(e) => {
                    eprintln!("Error decrypting value: {}", e);
                    process::exit(1);
                }
            }
        }
    }
}
