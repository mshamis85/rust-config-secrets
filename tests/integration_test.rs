use rust_config_secrets::{encrypt_secrets, decrypt_secrets, generate_key, ConfigSecretsError};

#[test]
fn test_public_api_flow() {
    // 1. Generate a key
    let key = generate_key();
    assert_eq!(key.len(), 43); // 32 bytes base64 url safe no pad

    // 2. Define a config with secrets to encrypt
    let original_config = r#"
    server:
      port: 8080
      db_password: ENCRYPT(super_secret_db_pass)
      api_key: ENCRYPT(12345-abcde)
    "#;

    // 3. Encrypt the config
    let encrypted_res = encrypt_secrets(original_config, &key);
    assert!(encrypted_res.is_ok());
    let encrypted_config = encrypted_res.unwrap();

    // Verify it's encrypted
    assert!(!encrypted_config.contains("ENCRYPT("));
    assert!(encrypted_config.contains("SECRET("));
    assert!(!encrypted_config.contains("super_secret_db_pass"));

    // 4. Decrypt the config
    let decrypted_res = decrypt_secrets(&encrypted_config, &key);
    assert!(decrypted_res.is_ok());
    let decrypted_config = decrypted_res.unwrap();

    // Verify content matches
    assert!(decrypted_config.contains("db_password: super_secret_db_pass"));
    assert!(decrypted_config.contains("api_key: 12345-abcde"));
}

#[test]
fn test_error_handling() {
    let key = generate_key();
    let bad_config = "some_value: SECRET(invalid_base64_$$$)";
    
    let result = decrypt_secrets(bad_config, &key);
    assert!(result.is_err());
    
    match result.unwrap_err() {
        ConfigSecretsError::InvalidBase64(_) => (), // Expected
        _ => panic!("Wrong error type returned"),
    }
}
