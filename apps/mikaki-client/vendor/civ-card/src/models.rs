//! Core data models for citizen identity verification.
//!
//! This module provides the unified data structures used across all card types:
//!
//! - [`CardType`] - Enumeration of supported smart card types
//! - [`CitizenIdentity`] - Unified identity record returned by all controllers
//! - [`IdentityController`] - Trait for card-specific controller implementations

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::errors::CivError;

/// Supported smart card types.
///
/// Each variant represents a specific type of identity card with its own
/// controller implementation.
///
/// # Example
///
/// ```
/// use civ::CardType;
///
/// let card = CardType::Jpki;
/// assert_eq!(format!("{:?}", card), "Jpki");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CardType {
    /// Japanese My Number Card (JPKI)
    Jpki,
    /// Japanese Driver's License
    Jpdl,
    /// MyNa-Menkyo (Driver's License on My Number Card)
    Jpdlmnc,
    /// Japanese Residence Card
    Jprc,
    /// ICAO 9303 ePassport
    Passport,
    /// European Union eID
    EuEid,
    /// Malaysian Identity Card
    MyKad,
    /// Thai National ID
    ThaiId,
    /// US PIV Card
    Piv,
    /// Unrecognized card with AID
    Unknown(String),
}

/// Unified identity record returned by all card controllers.
///
/// This struct provides a common representation for identity data
/// across different card types. Not all fields are populated by
/// every card type.
///
/// # Required Fields
///
/// - `full_name` - Display name (always present)
/// - `birth_date` - Date of birth in ISO 8601 format (YYYY-MM-DD)
/// - `identity_number` - Document/card number
/// - `card_type` - Type of card that produced this identity
///
/// # Optional Fields
///
/// Optional fields may be `None` depending on the card type and
/// what data the card contains.
///
/// # Example
///
/// ```
/// use civ::{CardType, CitizenIdentity};
/// use std::collections::HashMap;
///
/// let identity = CitizenIdentity {
///     full_name: "山田 太郎".to_string(),
///     surname: Some("山田".to_string()),
///     given_names: Some("太郎".to_string()),
///     full_name_kana: Some("ヤマダ タロウ".to_string()),
///     address: Some("東京都千代田区".to_string()),
///     birth_date: "1990-01-15".to_string(),
///     gender: "M".to_string(),
///     identity_number: "1234567890".to_string(),
///     card_type: CardType::Jpki,
///     issuing_authority: Some("JPN".to_string()),
///     expiration_date: Some("2030-01-15".to_string()),
///     photo_data: None,
///     verified: false,
///     attributes: HashMap::new(),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CitizenIdentity {
    /// Display name (required)
    pub full_name: String,
    /// Family name
    pub surname: Option<String>,
    /// Given/first names
    pub given_names: Option<String>,
    /// Name in katakana (Japanese cards)
    pub full_name_kana: Option<String>,
    /// Standardized address
    pub address: Option<String>,
    /// ISO 8601 format (YYYY-MM-DD)
    pub birth_date: String,
    /// "M", "F", or "X" (unspecified)
    pub gender: String,
    /// Document number (required)
    pub identity_number: String,
    /// Enum of supported card types
    pub card_type: CardType,
    /// Country code or agency
    pub issuing_authority: Option<String>,
    /// ISO 8601 format
    pub expiration_date: Option<String>,
    /// JPEG/JP2 face photo
    pub photo_data: Option<Vec<u8>>,
    /// Passive Authentication result
    pub verified: bool,
    /// Card-specific extended data
    pub attributes: HashMap<String, String>,
}

impl CitizenIdentity {
    /// Validate that full_name is not empty.
    pub fn validate_full_name(name: &str) -> Result<(), CivError> {
        if name.is_empty() {
            return Err(CivError::Validation(
                "full_name must not be empty".to_string(),
            ));
        }
        Ok(())
    }

    /// Validate that identity_number is not empty.
    pub fn validate_identity_number(id: &str) -> Result<(), CivError> {
        if id.is_empty() {
            return Err(CivError::Validation(
                "identity_number must not be empty".to_string(),
            ));
        }
        Ok(())
    }

    /// Validate birth_date is in ISO 8601 format (YYYY-MM-DD).
    pub fn validate_birth_date(date: &str) -> Result<(), CivError> {
        // Simple validation: YYYY-MM-DD format
        if date.len() != 10 {
            return Err(CivError::Validation(
                "birth_date must be in YYYY-MM-DD format".to_string(),
            ));
        }
        let parts: Vec<&str> = date.split('-').collect();
        if parts.len() != 3 {
            return Err(CivError::Validation(
                "birth_date must be in YYYY-MM-DD format".to_string(),
            ));
        }
        // Validate year, month, day are numeric
        for (i, part) in parts.iter().enumerate() {
            let expected_len = if i == 0 { 4 } else { 2 };
            if part.len() != expected_len || !part.chars().all(|c| c.is_ascii_digit()) {
                return Err(CivError::Validation(
                    "birth_date must be in YYYY-MM-DD format".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Validate the entire identity record.
    pub fn validate(&self) -> Result<(), CivError> {
        Self::validate_full_name(&self.full_name)?;
        Self::validate_identity_number(&self.identity_number)?;
        Self::validate_birth_date(&self.birth_date)?;
        Ok(())
    }
}

/// Abstract interface for card-specific controller implementations.
///
/// All card controllers implement this trait, providing a unified API
/// for reading identity data from different card types.
///
/// # Implementors
///
/// - [`JpkiController`](crate::JpkiController) - Japanese My Number Card
/// - [`PassportController`](crate::PassportController) - ICAO 9303 ePassport
/// - [`JpdlController`](crate::JpdlController) - Japanese Driver's License
/// - [`PivController`](crate::PivController) - US PIV Card
///
/// # Example
///
/// ```no_run
/// use civ::{IdentityController, MockJpkiController};
///
/// #[tokio::main]
/// async fn main() -> Result<(), civ::CivError> {
///     let mut controller = MockJpkiController::new();
///
///     // Authenticate
///     controller.provide_pin("auth", "1234").await?;
///
///     // Read identity
///     let identity = controller.read_identity().await?;
///     println!("Name: {}", identity.full_name);
///
///     // Verify (Passive Authentication)
///     let verified = controller.verify().await?;
///     println!("Verified: {}", verified);
///
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait IdentityController: Send + Sync {
    /// Read identity information from the connected card.
    ///
    /// # Returns
    ///
    /// A [`CitizenIdentity`] containing the card holder's information.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - PIN/credentials have not been provided (if required)
    /// - Communication with the card fails
    /// - The card data is malformed
    async fn read_identity(&mut self) -> Result<CitizenIdentity, CivError>;

    /// Provide credentials for card access.
    ///
    /// # Arguments
    ///
    /// * `pin_type` - Type of credential:
    ///   - `"auth"` - Authentication PIN (JPKI, PIV)
    ///   - `"sign"` - Signature PIN (JPKI)
    ///   - `"pin1"` - PIN1 for common data (JPDL)
    ///   - `"pin2"` - PIN2 for sensitive data (JPDL)
    ///   - `"mrz"` - Machine Readable Zone data (Passport)
    ///   - `"can"` - Card Access Number (Passport PACE)
    /// * `pin` - The credential value
    ///
    /// # Errors
    ///
    /// Returns an error if the PIN is invalid or the card rejects it.
    async fn provide_pin(&mut self, pin_type: &str, pin: &str) -> Result<(), CivError>;

    /// Verify card data authenticity via Passive Authentication.
    ///
    /// Passive Authentication verifies that the data on the card has not
    /// been tampered with by validating digital signatures.
    ///
    /// # Returns
    ///
    /// `true` if verification succeeds, `false` if verification fails
    /// but the card data may still be readable.
    ///
    /// # Errors
    ///
    /// Returns an error if verification is not supported for this card type
    /// or if the verification process fails.
    async fn verify(&mut self) -> Result<bool, CivError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(full: &str, id: &str, date: &str) -> CitizenIdentity {
        CitizenIdentity {
            full_name: full.to_string(),
            surname: None,
            given_names: None,
            full_name_kana: None,
            address: None,
            birth_date: date.to_string(),
            gender: "M".into(),
            identity_number: id.to_string(),
            card_type: CardType::Jpki,
            issuing_authority: None,
            expiration_date: None,
            photo_data: None,
            verified: false,
            attributes: HashMap::new(),
        }
    }

    #[test]
    fn validate_full_name_rejects_empty() {
        assert!(CitizenIdentity::validate_full_name("").is_err());
        assert!(CitizenIdentity::validate_full_name("name").is_ok());
    }

    #[test]
    fn validate_identity_number_rejects_empty() {
        assert!(CitizenIdentity::validate_identity_number("").is_err());
        assert!(CitizenIdentity::validate_identity_number("ID123").is_ok());
    }

    #[test]
    fn validate_birth_date_accepts_iso() {
        assert!(CitizenIdentity::validate_birth_date("2000-01-02").is_ok());
    }

    #[test]
    fn validate_birth_date_rejects_bad_length() {
        assert!(CitizenIdentity::validate_birth_date("2000/01/02").is_err());
        assert!(CitizenIdentity::validate_birth_date("2000-1-2").is_err());
    }

    #[test]
    fn validate_birth_date_rejects_non_numeric() {
        assert!(CitizenIdentity::validate_birth_date("YYYY-MM-DD").is_err());
    }

    #[test]
    fn validate_birth_date_rejects_wrong_part_count() {
        assert!(CitizenIdentity::validate_birth_date("2000010102").is_err());
    }

    #[test]
    fn validate_happy_path() {
        let id = make("Name", "12345", "1990-01-01");
        assert!(id.validate().is_ok());
    }

    #[test]
    fn validate_propagates_subfield_errors() {
        let id = make("", "12345", "1990-01-01");
        assert!(id.validate().is_err());
        let id = make("Name", "", "1990-01-01");
        assert!(id.validate().is_err());
        let id = make("Name", "12345", "bad");
        assert!(id.validate().is_err());
    }

    #[test]
    fn card_type_unknown_carries_aid() {
        let c = CardType::Unknown("A00000".into());
        match c {
            CardType::Unknown(s) => assert_eq!(s, "A00000"),
            _ => panic!(),
        }
    }
}
