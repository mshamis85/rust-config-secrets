use crate::crypto;
use crate::error::ConfigSecretsError;
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};
use rand::{RngCore, thread_rng};
use std::fs;
use std::path::Path;

fn get_cipher(key: &str) -> Result<Aes256Gcm, ConfigSecretsError> {
    let mut key_bytes = [0u8; 32];
    let input_bytes = key.as_bytes();

    // Simple padding/truncation to get 32 bytes
    for (i, b) in input_bytes.iter().enumerate() {
        if i >= 32 {
            break;
        }
        key_bytes[i] = *b;
    }

    Aes256Gcm::new_from_slice(&key_bytes).map_err(|_| ConfigSecretsError::EncryptionFailed)
}

/// Generates a random 32-byte AES key and returns it as a base64 encoded string.
pub fn generate_key() -> String {
    let mut key = [0u8; 32];
    thread_rng().fill_bytes(&mut key);
    BASE64.encode(key)
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

                let ciphertext = BASE64
                    .decode(content_str)
                    .map_err(|e| ConfigSecretsError::InvalidBase64(e.to_string()))?;

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
                let base64_str = BASE64.encode(encrypted_bytes);

                output.push_str("SECRET(");
                output.push_str(&base64_str);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key() {
        let key = generate_key();
        assert!(!key.is_empty());
        // Verify it's valid base64
        assert!(BASE64.decode(&key).is_ok());
        // Check approximate length for 32 bytes in base64 no pad (43 chars)
        assert_eq!(key.len(), 43);
    }

    #[test]
    fn test_encrypt_secrets() {
        let key = "test_key_123";
        let input = r#"{"pass": "ENCRYPT(my_secret)"}"#;
        let output = encrypt_secrets(input, key).unwrap();

        assert!(output.contains("SECRET("));
        assert!(!output.contains("ENCRYPT("));
        assert!(!output.contains("my_secret")); // Plaintext should be gone
    }

    #[test]
    fn test_decrypt_secrets() {
        let key = "test_key_123";
        // First encrypt to get a valid secret block
        let input = r#"{"pass": "ENCRYPT(my_secret)"}"#;
        let encrypted = encrypt_secrets(input, key).unwrap();

        // Then decrypt
        let decrypted = decrypt_secrets(&encrypted, key).unwrap();
        assert!(decrypted.contains(r#""pass": "my_secret""#));
    }

    #[test]
    fn test_encrypt_secrets_to_file() {
        let key = "file_key";
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
        let key = "file_key_2";
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
        let key = "inplace_key";
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
        let key = "decrypt_file_key";
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
        let key = "mixed";
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
}
