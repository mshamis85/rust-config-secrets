//! # rust-config-secrets
//!
//! `rust-config-secrets` is a library designed to safely manage secrets within configuration files.
//! It allows you to encrypt sensitive data (like passwords, API keys) directly within your config strings
//! or files, and decrypt them at runtime.
//!
//! ## Features
//!
//! - **Encryption**: Encrypt plain text configuration strings or files.
//! - **Decryption**: Decrypt configuration strings or files containing `SECRET(...)` blocks.
//! - **Key Generation**: Generate secure random keys for AES-256-GCM encryption.
//! - **Format Agnostic**: Works with JSON, YAML, TOML, INI, or any text-based format.
//!
//! ## Usage
//!
//! ```rust
//! use rust_config_secrets::{encrypt_secrets, decrypt_secrets, generate_key};
//!
//! let key = generate_key();
//! let config = r#"{ "password": "ENCRYPT(my_secret_password)" }"#;
//!
//! // Encrypt the configuration
//! let encrypted_config = encrypt_secrets(config, &key).unwrap();
//! assert!(encrypted_config.contains("SECRET("));
//!
//! // Decrypt the configuration
//! let decrypted_config = decrypt_secrets(&encrypted_config, &key).unwrap();
//! assert!(decrypted_config.contains(r#""password": "my_secret_password""#));
//! ```

mod config;
mod crypto;
mod alphanumeric_encoding;
mod error;

pub use config::{
    decrypt_secrets,
    decrypt_file,
    decrypt_value,
    encrypt_secrets,
    encrypt_secrets_to_file,
    encrypt_file,
    encrypt_file_in_place,
    encrypt_value,
    generate_key,
};
pub use error::ConfigSecretsError;