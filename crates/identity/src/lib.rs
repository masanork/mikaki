//! Shared bounded card parsing, evidence verification and first-party issuance profile.
pub mod android_attestation_evidence;
pub mod attester_proof;
pub mod card;
pub mod certificate;
mod certificate_revocation;
pub mod client_attestation;
pub mod credential_certificate;
pub mod credential_receipt;
pub mod evidence;
pub mod issuance;
pub mod issuance_encryption;
pub mod key_attestation;
pub mod mdoc;
pub mod presentation;
pub mod wallet_authorization;
pub mod wallet_profile;
