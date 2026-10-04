//! Error types for the civ library.
//!
//! This module defines the error types used throughout the library:
//!
//! - [`CivError`] - Main error type that wraps all other errors
//! - [`CardError`] - Card-specific errors (PIN failure, no card, etc.)
//! - [`VerificationError`] - Passive Authentication errors
//! - [`CacheError`] - Cache operation errors
//!
//! # Example
//!
//! ```
//! use civ::{CivError, CardError};
//!
//! fn handle_error(err: CivError) {
//!     match err {
//!         CivError::Card(CardError::PinFailed { remaining_retries }) => {
//!             println!("Wrong PIN! {} retries remaining", remaining_retries);
//!         }
//!         CivError::Card(CardError::CardLocked) => {
//!             println!("Card is locked!");
//!         }
//!         _ => println!("Error: {}", err),
//!     }
//! }
//! ```

use crate::models::CardType;
use thiserror::Error;

/// Main error enum for the civ library.
///
/// This is the primary error type returned by most library functions.
/// It wraps more specific error types for different categories of errors.
#[derive(Debug, Error)]
pub enum CivError {
    /// Card-related errors
    #[error("Card error: {0}")]
    Card(#[from] CardError),

    /// Verification-related errors
    #[error("Verification error: {0}")]
    Verification(#[from] VerificationError),

    /// Cache-related errors
    #[error("Cache error: {0}")]
    Cache(#[from] CacheError),

    /// I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol errors
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Validation errors
    #[error("Validation error: {0}")]
    Validation(String),

    /// Invalid data format
    #[error("Invalid data: {0}")]
    InvalidData(String),

    /// Communication errors
    #[error("Communication error: {0}")]
    Communication(String),

    /// Not found errors
    #[error("Not found: {0}")]
    NotFound(String),

    /// Crypto errors
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// APDU error with status word
    #[error("APDU error: SW={0:02X}{1:02X}")]
    ApduError(u8, u8),

    /// Unexpected error
    #[error("Unexpected error: {0}")]
    Unexpected(String),

    /// Secure messaging error
    #[error("Secure messaging error: {0}")]
    SecureMessagingError(String),
}

impl CivError {
    /// Create an error from APDU status word.
    pub fn from_sw(sw1: u8, sw2: u8) -> Self {
        match (sw1, sw2) {
            (0x63, sw2) if (sw2 & 0xF0) == 0xC0 => {
                let retries = sw2 & 0x0F;
                CivError::Card(CardError::PinFailed {
                    remaining_retries: retries,
                })
            }
            (0x69, 0x83) => CivError::Card(CardError::CardLocked),
            (0x69, 0x84) => CivError::InvalidData("Reference data invalidated".to_string()),
            (0x6A, 0x82) => CivError::NotFound("File not found".to_string()),
            (0x6A, 0x83) => CivError::NotFound("Record not found".to_string()),
            (0x6B, 0x00) => CivError::InvalidData("Wrong P1-P2".to_string()),
            (0x6D, 0x00) => CivError::InvalidData("Instruction not supported".to_string()),
            (0x6E, 0x00) => CivError::InvalidData("Class not supported".to_string()),
            _ => CivError::ApduError(sw1, sw2),
        }
    }
}

/// Card-related errors.
#[derive(Debug, Error)]
pub enum CardError {
    /// No card present in reader
    #[error("No card present in reader")]
    NoCard,

    /// Card reader disconnected
    #[error("Card reader disconnected")]
    ReaderDisconnected,

    /// Unsupported card type
    #[error("Unsupported card type: {aid}")]
    UnsupportedCard { aid: String },

    /// PIN verification failed with retry count
    #[error("PIN verification failed, {remaining_retries} retries remaining")]
    PinFailed { remaining_retries: u8 },

    /// Card locked - PIN retries exhausted
    #[error("Card locked - PIN retries exhausted")]
    CardLocked,

    /// Reader busy — another process holds the card in EXCLUSIVE mode.
    /// Maps PC/SC `SCARD_E_SHARING_VIOLATION` (and platform equivalents).
    /// FR-039 surfaces this to the consumer as
    /// `session.poll → failed / failure_reason: reader_busy`.
    #[error("Reader busy — another PC/SC client holds the card")]
    ReaderBusy,

    /// Failed to read specific file
    #[error("Failed to read file: {file}")]
    ReadError { file: String },

    /// Failed to select application
    #[error("Failed to select application: {aid}")]
    SelectError { aid: String },

    /// Communication error
    #[error("Communication error: {detail}")]
    CommunicationError { detail: String },
}

/// Verification-related errors.
#[derive(Debug, Error)]
pub enum VerificationError {
    /// Failed to fetch certificates
    #[error("Failed to fetch certificates (cached available: {cached_available})")]
    CertificateFetchFailed { cached_available: bool },

    /// Invalid signature on data group
    #[error("Invalid signature on {data_group}")]
    InvalidSignature { data_group: String },

    /// Hash mismatch
    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// Certificate expired
    #[error("Certificate expired: {subject}")]
    CertificateExpired { subject: String },

    /// Untrusted certificate
    #[error("Untrusted certificate from: {issuer}")]
    UntrustedCertificate { issuer: String },

    /// Verification not supported for card type
    #[error("Verification not supported for {card_type:?}")]
    NotSupported { card_type: CardType },
}

/// Cache-related errors.
#[derive(Debug, Error)]
pub enum CacheError {
    /// Entry not found
    #[error("Cache entry not found: {key}")]
    NotFound { key: String },

    /// Entry expired
    #[error("Cache entry expired: {key}")]
    Expired { key: String },

    /// Serialization error
    #[error("Cache serialization error: {detail}")]
    SerializationError { detail: String },

    /// Storage error
    #[error("Cache storage error: {detail}")]
    StorageError { detail: String },
}
