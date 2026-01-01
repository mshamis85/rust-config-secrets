use std::fmt;

#[derive(Debug, PartialEq)]
pub enum ConfigSecretsError {
    EncryptionFailed,
    DecryptionFailed,
    CiphertextTooShort,
    InvalidBase64(String),
    InvalidKeyLength(usize),
    InvalidUtf8(String),
    UnclosedBlock(String),
    IoError(String),
}

impl fmt::Display for ConfigSecretsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncryptionFailed => write!(f, "Encryption failed"),
            Self::DecryptionFailed => write!(f, "Decryption failed"),
            Self::CiphertextTooShort => write!(f, "Ciphertext too short"),
            Self::InvalidBase64(e) => write!(f, "Invalid base64: {}", e),
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
        assert_eq!(ConfigSecretsError::InvalidBase64("bad".into()).to_string(), "Invalid base64: bad");
        assert_eq!(ConfigSecretsError::InvalidKeyLength(10).to_string(), "Invalid key length: 10 (expected 32)");
        assert_eq!(ConfigSecretsError::InvalidUtf8("bad utf8".into()).to_string(), "Invalid UTF-8: bad utf8");
        assert_eq!(ConfigSecretsError::UnclosedBlock("tag".into()).to_string(), "Unclosed block: tag");
        assert_eq!(ConfigSecretsError::IoError("oops".into()).to_string(), "IO error: oops");
    }
}
