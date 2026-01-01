# rust-config-secrets

A lightweight Rust library for safely managing secrets within configuration files using AES-256-GCM.

[![Crates.io](https://img.shields.io/crates/v/rust-config-secrets.svg)](https://crates.io/crates/rust-config-secrets)
[![Documentation](https://docs.rs/rust-config-secrets/badge.svg)](https://docs.rs/rust-config-secrets)

## Overview

`rust-config-secrets` allows you to embed encrypted secrets directly into your configuration files (JSON, YAML, TOML, etc.). You can commit your configuration files to version control safely by replacing sensitive plaintext with `SECRET(...)` blocks.

## Features

- **Format Agnostic**: Works with any text-based configuration format.
- **Secure**: Uses AES-256-GCM with unique nonces for every secret.
- **Simple API**: Easy functions for encrypting, decrypting, and generating keys.
- **In-place Editing**: Encrypt your configuration files directly on disk.
- **Safe**: Robust error handling without panics.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rust-config-secrets = "0.1.0"
```

## Quick Start

### 1. Generate a Key
```rust
use rust_config_secrets::generate_key;

let key = generate_key(); // Save this somewhere safe!
```

### 2. Prepare and Encrypt your Config
Write your config using `ENCRYPT(...)` placeholders:

```yaml
# config.yaml
database:
  url: "postgres://user:password@localhost/db"
  api_token: "ENCRYPT(my-very-secret-token)"
```

Encrypt it:
```rust
use rust_config_secrets::encrypt_file_in_place;

encrypt_file_in_place("config.yaml", &key).unwrap();
```

Your file now looks like this:
```yaml
# config.yaml
database:
  url: "postgres://user:password@localhost/db"
  api_token: "SECRET(Abc123...)"
```

### 3. Load and Decrypt at Runtime
```rust
use rust_config_secrets::load_config_from_file; // Assuming you renamed it or use decrypt_file

let config_str = rust_config_secrets::decrypt_file("config.yaml", &key).unwrap();
// Now use your favorite parser (serde_json, yaml-rust, etc.) on config_str
```

## API Functions

- `generate_key()`: Generates a random 32-byte AES key (base64 encoded).
- `encrypt_secrets(config, key)`: Encrypts `ENCRYPT()` blocks in a string.
- `decrypt_secrets(config, key)`: Decrypts `SECRET()` blocks in a string.
- `encrypt_file(input, output, key)`: Reads from input, encrypts, writes to output.
- `encrypt_file_in_place(path, key)`: Encrypts a file on disk.
- `decrypt_file(path, key)`: Reads and decrypts a file into a string.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
