use std::fmt;

#[derive(Debug, PartialEq)]
pub enum ConfigSecretsError {
    EncryptionFailed,
    DecryptionFailed,
    CiphertextTooShort,
    InvalidBase64(String),
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
            Self::InvalidUtf8(e) => write!(f, "Invalid UTF-8: {}", e),
            Self::UnclosedBlock(m) => write!(f, "Unclosed block: {}", m),
            Self::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for ConfigSecretsError {}
