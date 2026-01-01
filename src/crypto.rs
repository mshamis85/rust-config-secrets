use crate::error::ConfigSecretsError;
use aes_gcm::{Aes256Gcm, Nonce, aead::Aead};
use rand::RngCore;

pub fn encrypt(plaintext: &str, cipher: &Aes256Gcm) -> Result<Vec<u8>, ConfigSecretsError> {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    match cipher.encrypt(nonce, plaintext.as_bytes()) {
        Ok(ciphertext) => {
            let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
            result.extend_from_slice(&nonce_bytes);
            result.extend_from_slice(&ciphertext);
            Ok(result)
        }
        Err(_) => Err(ConfigSecretsError::EncryptionFailed),
    }
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
}
