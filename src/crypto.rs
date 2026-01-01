use crate::error::ConfigSecretsError;
use aes_gcm::{Aes256Gcm, Nonce, aead::Aead};
use rand::RngCore;

pub fn encrypt(plaintext: &str, cipher: &Aes256Gcm) -> Result<Vec<u8>, ConfigSecretsError> {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| ConfigSecretsError::EncryptionFailed)?;

    let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt(
    ciphertext_with_nonce: &[u8],
    cipher: &Aes256Gcm,
) -> Result<String, ConfigSecretsError> {
    if ciphertext_with_nonce.len() < 12 {
        return Err(ConfigSecretsError::CiphertextTooShort);
    }

    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => {
            String::from_utf8(plaintext).map_err(|e| ConfigSecretsError::InvalidUtf8(e.to_string()))
        }
        Err(_) => Err(ConfigSecretsError::DecryptionFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::KeyInit;

    #[test]
    fn test_crypto_cycle() {
        let key = Aes256Gcm::generate_key(&mut rand::thread_rng());
        let cipher = Aes256Gcm::new(&key);
        let plaintext = "Hello, World!";

        let encrypted = encrypt(plaintext, &cipher).expect("Encrypt failed");
        let decrypted = decrypt(&encrypted, &cipher).expect("Decrypt failed");

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_decrypt_fail_short_ciphertext() {
        let key = Aes256Gcm::generate_key(&mut rand::thread_rng());
        let cipher = Aes256Gcm::new(&key);
        let short_data = [0u8; 10];

        let res = decrypt(&short_data, &cipher);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), ConfigSecretsError::CiphertextTooShort);
    }

    #[test]
    fn test_decryption_integrity() {
        let key = Aes256Gcm::generate_key(&mut rand::thread_rng());
        let cipher = Aes256Gcm::new(&key);
        let plaintext = "Sensitive Data";

        let mut encrypted = encrypt(plaintext, &cipher).expect("Encrypt failed");
        // Tamper with the ciphertext (last byte)
        let len = encrypted.len();
        encrypted[len - 1] ^= 0x01;

        let res = decrypt(&encrypted, &cipher);
        assert_eq!(res.unwrap_err(), ConfigSecretsError::DecryptionFailed);
    }

    #[test]
    fn test_decrypt_invalid_utf8() {
        let key = Aes256Gcm::generate_key(&mut rand::thread_rng());
        let cipher = Aes256Gcm::new(&key);
        
        // Manually construct a valid encryption of invalid UTF-8 bytes
        // We can't use `encrypt` because it takes &str
        // So we use the cipher directly
        let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
        let invalid_utf8 = vec![0xFF, 0xFF, 0xFF]; // Not valid UTF-8
        
        let ciphertext = cipher.encrypt(nonce, invalid_utf8.as_ref()).unwrap();
        
        let mut input = Vec::new();
        input.extend_from_slice(nonce);
        input.extend_from_slice(&ciphertext);

        let res = decrypt(&input, &cipher);
        assert!(matches!(res.unwrap_err(), ConfigSecretsError::InvalidUtf8(_)));
    }
}
