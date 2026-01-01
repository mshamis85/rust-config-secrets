use std::fmt;

/// Errors that can occur during configuration secret management.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSecretsError {
    /// Failed to encrypt the data.
    EncryptionFailed,
    /// Failed to decrypt the data (e.g., wrong key or tampered ciphertext).
    DecryptionFailed,
    /// The ciphertext is too short to contain a valid nonce.
    CiphertextTooShort,
    /// The provided string is not valid alphanumeric encoding.
    InvalidEncoding(String),
    /// The provided key has an invalid length (expected 32 bytes).
    InvalidKeyLength(usize),
    /// The decrypted data is not valid UTF-8.
    InvalidUtf8(String),
    /// A marker block (e.g., `ENCRYPT(` or `SECRET(`) was not properly closed.
    UnclosedBlock(String),
    /// An I/O error occurred while reading or writing a file.
    IoError(String),
}

impl fmt::Display for ConfigSecretsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncryptionFailed => write!(f, "Encryption failed"),
            Self::DecryptionFailed => write!(f, "Decryption failed"),
            Self::CiphertextTooShort => write!(f, "Ciphertext too short"),
            Self::InvalidEncoding(e) => write!(f, "Invalid encoding: {}", e),
            Self::InvalidKeyLength(l) => write!(f, "Invalid key length: {} (expected 32)", l),
            Self::InvalidUtf8(e) => write!(f, "Invalid UTF-8: {}", e),
            Self::UnclosedBlock(m) => write!(f, "Unclosed block: {}", m),
            Self::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for ConfigSecretsError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_impl() {
        assert_eq!(ConfigSecretsError::EncryptionFailed.to_string(), "Encryption failed");
        assert_eq!(ConfigSecretsError::DecryptionFailed.to_string(), "Decryption failed");
        assert_eq!(ConfigSecretsError::CiphertextTooShort.to_string(), "Ciphertext too short");
        assert_eq!(ConfigSecretsError::InvalidEncoding("bad".into()).to_string(), "Invalid encoding: bad");
        assert_eq!(ConfigSecretsError::InvalidKeyLength(10).to_string(), "Invalid key length: 10 (expected 32)");
        assert_eq!(ConfigSecretsError::InvalidUtf8("bad utf8".into()).to_string(), "Invalid UTF-8: bad utf8");
        assert_eq!(ConfigSecretsError::UnclosedBlock("tag".into()).to_string(), "Unclosed block: tag");
        assert_eq!(ConfigSecretsError::IoError("oops".into()).to_string(), "IO error: oops");
    }
}
