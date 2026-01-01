use crate::crypto;
use crate::error::ConfigSecretsError;
use aes_gcm::{Aes256Gcm, KeyInit};
use bs58::{decode, encode};
use rand::{RngCore, thread_rng};
use std::fs;
use std::path::Path;

fn get_cipher(key: &str) -> Result<Aes256Gcm, ConfigSecretsError> {
    let key_bytes = decode(key)
        .into_vec()
        .map_err(|e| ConfigSecretsError::InvalidEncoding(e.to_string()))?;

    if key_bytes.len() != 32 {
        return Err(ConfigSecretsError::InvalidKeyLength(key_bytes.len()));
    }

    Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|_| ConfigSecretsError::InvalidKeyLength(key_bytes.len()))
}

/// Generates a random 32-byte AES key and returns it as an alphanumeric encoded string.
pub fn generate_key() -> String {
    let mut key = [0u8; 32];
    thread_rng().fill_bytes(&mut key);
    encode(&key).into_string()
}

/// Decrypts all `SECRET(...)` blocks in the provided string.
pub fn decrypt_secrets(config: &str, key: &str) -> Result<String, ConfigSecretsError> {
    let cipher = get_cipher(key)?;
    let marker = "SECRET(";
    let mut output = String::new();
    let mut cursor = 0;

    while let Some(start_offset) = config[cursor..].find(marker) {
        let absolute_start = cursor + start_offset;
        output.push_str(&config[cursor..absolute_start]);

        match config[absolute_start..].find(')') {
            Some(end_offset) => {
                let absolute_end = absolute_start + end_offset;
                let content_str = &config[absolute_start + marker.len()..absolute_end];

                let ciphertext = decode(content_str)
                    .into_vec()
                    .map_err(|e| ConfigSecretsError::InvalidEncoding(e.to_string()))?;

                let decrypted = crypto::decrypt(&ciphertext, &cipher)?;
                output.push_str(&decrypted);

                cursor = absolute_end + 1;
            }
            None => return Err(ConfigSecretsError::UnclosedBlock("SECRET".to_string())),
        }
    }
    output.push_str(&config[cursor..]);
    Ok(output)
}

/// Decrypts a configuration file and returns the content as a string.
pub fn decrypt_file<P: AsRef<Path>>(path: P, key: &str) -> Result<String, ConfigSecretsError> {
    let content =
        fs::read_to_string(path).map_err(|e| ConfigSecretsError::IoError(e.to_string()))?;
    decrypt_secrets(&content, key)
}

/// Encrypts all `ENCRYPT(...)` blocks in the provided string, converting them to `SECRET(...)`.
pub fn encrypt_secrets(config: &str, key: &str) -> Result<String, ConfigSecretsError> {
    let cipher = get_cipher(key)?;
    let marker = "ENCRYPT(";
    let mut output = String::new();
    let mut cursor = 0;

    while let Some(start_offset) = config[cursor..].find(marker) {
        let absolute_start = cursor + start_offset;
        output.push_str(&config[cursor..absolute_start]);

        match config[absolute_start..].find(')') {
            Some(end_offset) => {
                let absolute_end = absolute_start + end_offset;
                let content = &config[absolute_start + marker.len()..absolute_end];

                let encrypted_bytes = crypto::encrypt(content, &cipher)?;
                let encoded_str = encode(&encrypted_bytes).into_string();

                output.push_str("SECRET(");
                output.push_str(&encoded_str);
                output.push(')');

                cursor = absolute_end + 1;
            }
            None => return Err(ConfigSecretsError::UnclosedBlock("ENCRYPT".to_string())),
        }
    }
    output.push_str(&config[cursor..]);
    Ok(output)
}

/// Encrypts secrets in a string and writes the result to a file.
pub fn encrypt_secrets_to_file<P: AsRef<Path>>(
    config: &str,
    output_path: P,
    key: &str,
) -> Result<(), ConfigSecretsError> {
    let encrypted_content = encrypt_secrets(config, key)?;
    fs::write(output_path, encrypted_content)
        .map_err(|e| ConfigSecretsError::IoError(e.to_string()))
}

/// Reads a file, encrypts its secrets, and writes the result to a different output file.
pub fn encrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
    input_path: P,
    output_path: Q,
    key: &str,
) -> Result<(), ConfigSecretsError> {
    let content =
        fs::read_to_string(input_path).map_err(|e| ConfigSecretsError::IoError(e.to_string()))?;
    encrypt_secrets_to_file(&content, output_path, key)
}

/// Reads a file, encrypts its secrets, and overwrites the file with the result.
pub fn encrypt_file_in_place<P: AsRef<Path>>(path: P, key: &str) -> Result<(), ConfigSecretsError> {
    let content =
        fs::read_to_string(&path).map_err(|e| ConfigSecretsError::IoError(e.to_string()))?;
    // Only write if encryption changes something or succeeds
    let encrypted_content = encrypt_secrets(&content, key)?;
    fs::write(path, encrypted_content).map_err(|e| ConfigSecretsError::IoError(e.to_string()))
}

/// Encrypts a single value and returns the encoded ciphertext.
pub fn encrypt_value(value: &str, key: &str) -> Result<String, ConfigSecretsError> {
    let cipher = get_cipher(key)?;
    let encrypted_bytes = crypto::encrypt(value, &cipher)?;
    Ok(encode(&encrypted_bytes).into_string())
}

/// Decrypts a single value. Accepts either `SECRET(...)` format or raw encoded string.
pub fn decrypt_value(input: &str, key: &str) -> Result<String, ConfigSecretsError> {
    let cipher = get_cipher(key)?;

    // Check if it's wrapped in SECRET(...)
    let inner_content = if input.trim().starts_with("SECRET(") && input.trim().ends_with(')') {
        let trimmed = input.trim();
        &trimmed["SECRET(".len()..trimmed.len() - 1]
    } else {
        input.trim()
    };

    let ciphertext = decode(inner_content)
        .into_vec()
        .map_err(|e| ConfigSecretsError::InvalidEncoding(e.to_string()))?;

    crypto::decrypt(&ciphertext, &cipher)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_value() {
        let key = generate_key();
        let secret = "my-password";

        // Test Encrypt
        let encrypted = encrypt_value(secret, &key).unwrap();
        // Should be alphanumeric, not wrapped
        assert!(!encrypted.starts_with("SECRET("));
        assert!(encrypted.chars().all(|c| c.is_alphanumeric()));

        // Test Decrypt with raw string
        let decrypted = decrypt_value(&encrypted, &key).unwrap();
        assert_eq!(decrypted, secret);

        // Test Decrypt with wrapper
        let wrapped = format!("SECRET({})", encrypted);
        let decrypted_wrapped = decrypt_value(&wrapped, &key).unwrap();
        assert_eq!(decrypted_wrapped, secret);
    }

    #[test]
    fn test_decrypt_value_invalid_encoding() {
        let key = generate_key();
        let err = decrypt_value("invalid-encoding!", &key).unwrap_err();
        assert!(matches!(err, ConfigSecretsError::InvalidEncoding(_)));
    }

    #[test]
    fn test_generate_key() {
        let key = generate_key();
        assert!(!key.is_empty());
        // Verify it's valid alphanumeric
        let decoded = decode(&key).into_vec();
        assert!(decoded.is_ok());
        // Check decoded length is 32 bytes
        assert_eq!(decoded.unwrap().len(), 32);
    }

    #[test]
    fn test_encrypt_secrets() {
        let key = &generate_key();
        let input = r#"{"pass": "ENCRYPT(my_secret)"}"#;
        let output = encrypt_secrets(input, key).unwrap();

        assert!(output.contains("SECRET("));
        assert!(!output.contains("ENCRYPT("));
        assert!(!output.contains("my_secret")); // Plaintext should be gone
    }

    #[test]
    fn test_decrypt_secrets() {
        let key = &generate_key();
        // First encrypt to get a valid secret block
        let input = r#"{"pass": "ENCRYPT(my_secret)"}"#;
        let encrypted = encrypt_secrets(input, key).unwrap();

        // Then decrypt
        let decrypted = decrypt_secrets(&encrypted, key).unwrap();
        assert!(decrypted.contains(r#""pass": "my_secret""#));
    }

    #[test]
    fn test_encrypt_secrets_to_file() {
        let key = &generate_key();
        let dir = std::env::temp_dir();
        let path = dir.join("secrets_out.json");
        let input = r#"key = "ENCRYPT(value)""#;

        encrypt_secrets_to_file(input, &path, key).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("SECRET("));
        assert!(!content.contains("value"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_encrypt_file() {
        let key = &generate_key();
        let dir = std::env::temp_dir();
        let in_path = dir.join("in.json");
        let out_path = dir.join("out.json");

        fs::write(&in_path, r#"data: ENCRYPT(sensitive)"#).unwrap();

        encrypt_file(&in_path, &out_path, key).unwrap();

        let out_content = fs::read_to_string(&out_path).unwrap();
        assert!(out_content.contains("SECRET("));

        let _ = fs::remove_file(in_path);
        let _ = fs::remove_file(out_path);
    }

    #[test]
    fn test_encrypt_file_in_place() {
        let key = &generate_key();
        let dir = std::env::temp_dir();
        let path = dir.join("inplace_test.yaml");

        fs::write(&path, "pass: ENCRYPT(word)").unwrap();

        encrypt_file_in_place(&path, key).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("SECRET("));

        // Verify decryption works
        let decrypted = decrypt_secrets(&content, key).unwrap();
        assert!(decrypted.contains("pass: word"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_decrypt_file() {
        let key = &generate_key();
        let dir = std::env::temp_dir();
        let path = dir.join("decrypt_me.ini");

        let content = r#"secret=ENCRYPT(hidden)"#;
        let encrypted = encrypt_secrets(content, key).unwrap();
        fs::write(&path, encrypted).unwrap();

        let decrypted = decrypt_file(&path, key).unwrap();
        assert!(decrypted.contains("secret=hidden"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_mixed_content() {
        let key = &generate_key();
        let input = r#"
            visible = "true"
            secret1 = "ENCRYPT(one)"
            secret2 = "ENCRYPT(two)"
            also_visible = 123
        "#;

        let encrypted = encrypt_secrets(input, key).unwrap();
        let decrypted = decrypt_secrets(&encrypted, key).unwrap();

        assert!(decrypted.contains(r#"visible = "true""#));
        assert!(decrypted.contains(r#"secret1 = "one""#));
        assert!(decrypted.contains(r#"secret2 = "two""#));
        assert!(decrypted.contains(r#"also_visible = 123"#));
    }

    #[test]
    fn test_invalid_key_encoding() {
        assert!(matches!(
            get_cipher("not-alphanumeric!"),
            Err(ConfigSecretsError::InvalidEncoding(_))
        ));
    }

    #[test]
    fn test_invalid_key_length() {
        // Valid encoding (2 chars -> 1 byte), but decodes to 1 byte
        let key = encode(&vec![0u8]).into_string();
        assert!(matches!(
            get_cipher(&key),
            Err(ConfigSecretsError::InvalidKeyLength(1))
        ));
    }

    #[test]
    fn test_unclosed_encrypt_block() {
        let key = &generate_key();
        let input = "val = ENCRYPT(oops";
        let err = encrypt_secrets(input, key).unwrap_err();
        assert_eq!(
            err,
            ConfigSecretsError::UnclosedBlock("ENCRYPT".to_string())
        );
    }

    #[test]
    fn test_unclosed_secret_block() {
        let key = &generate_key();
        let input = "val = SECRET(oops";
        let err = decrypt_secrets(input, key).unwrap_err();
        assert_eq!(err, ConfigSecretsError::UnclosedBlock("SECRET".to_string()));
    }

    #[test]
    fn test_invalid_encoding_in_secret() {
        let key = &generate_key();
        let input = "val = SECRET(!!!)";
        let err = decrypt_secrets(input, key).unwrap_err();
        assert!(matches!(err, ConfigSecretsError::InvalidEncoding(_)));
    }

    #[test]
    fn test_decrypt_secrets_invalid_key() {
        let err = decrypt_secrets("SECRET(val)", "invalid-key").unwrap_err();
        assert!(matches!(err, ConfigSecretsError::InvalidEncoding(_)));
    }

    #[test]
    fn test_decrypt_secrets_decryption_failed() {
        let key = generate_key();
        // "2222" is valid Base58 but decodes to a very short byte array,
        // which should trigger CiphertextTooShort.
        let input = "pass = SECRET(2222)";
        let err = decrypt_secrets(input, &key).unwrap_err();
        assert!(matches!(
            err,
            ConfigSecretsError::CiphertextTooShort
                | ConfigSecretsError::DecryptionFailed
                | ConfigSecretsError::InvalidEncoding(_)
        ));
    }

    #[test]
    fn test_encrypt_secrets_invalid_key() {
        let err = encrypt_secrets("ENCRYPT(val)", "invalid-key").unwrap_err();
        assert!(matches!(err, ConfigSecretsError::InvalidEncoding(_)));
    }

    #[test]
    fn test_file_funcs_invalid_key() {
        let bad_key = "invalid-key";
        let dir = std::env::temp_dir();
        let path = dir.join("dummy_config.txt");
        fs::write(&path, "content").unwrap();

        // decrypt_file
        let err = decrypt_file(&path, bad_key).unwrap_err();
        assert!(matches!(err, ConfigSecretsError::InvalidEncoding(_)));

        // encrypt_secrets_to_file
        let err = encrypt_secrets_to_file("content", &path, bad_key).unwrap_err();
        assert!(matches!(err, ConfigSecretsError::InvalidEncoding(_)));

        // encrypt_file
        let err = encrypt_file(&path, &path, bad_key).unwrap_err();
        assert!(matches!(err, ConfigSecretsError::InvalidEncoding(_)));

        // encrypt_file_in_place
        let err = encrypt_file_in_place(&path, bad_key).unwrap_err();
        assert!(matches!(err, ConfigSecretsError::InvalidEncoding(_)));

        let _ = fs::remove_file(path);
    }
}
