//! Payload-free diagnostic codes shared by native and Wasm. Not HTTP responses.
macro_rules! rejection_codes {
    ($($name:ident => ($code:literal, $stage:literal)),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Invalid { $($name),+ }
        impl Invalid {
            pub const fn code(self) -> &'static str {
                match self { $(Self::$name => $code),+ }
            }
            pub fn from_code(code: &str) -> Option<Self> {
                match code { $($code => Some(Self::$name)),+, _ => None }
            }
            pub const fn stage(self) -> &'static str {
                match self { $(Self::$name => $stage),+ }
            }
        }
    };
}
rejection_codes! {
    Configuration => ("configuration", "configuration"),
    Input => ("input", "input"),
    Limit => ("limit", "input"),
    ClientDataType => ("client_data_type", "client_data"),
    Challenge => ("challenge", "client_data"),
    Origin => ("origin", "client_data"),
    RpId => ("rp_id", "authenticator_data"),
    UserPresence => ("user_presence", "authenticator_data"),
    UserVerification => ("user_verification", "authenticator_data"),
    Credential => ("credential", "credential"),
    UserHandle => ("user_handle", "credential"),
    AllowList => ("allow_list", "credential"),
    Backup => ("backup", "authenticator_data"),
    Counter => ("counter", "authenticator_data"),
    PublicKey => ("public_key", "key"),
    Algorithm => ("algorithm", "key"),
    Signature => ("signature", "signature"),
    Extensions => ("extensions", "extensions"),
    AttestationPolicy => ("attestation_policy", "attestation"),
    Attestation => ("attestation", "attestation"),
    Trust => ("trust", "attestation"),
    Certificate => ("certificate", "certificate"),
    CertificateTime => ("certificate_time", "certificate"),
    CertificatePath => ("certificate_path", "certificate"),
    Metadata => ("metadata", "metadata"),
    Crl => ("crl", "metadata"),
    CrlExpired => ("crl_expired", "metadata"),
    Revoked => ("revoked", "metadata"),
    Tpm => ("tpm", "attestation"),
    CeremonyPurpose => ("ceremony_purpose", "ceremony"),
    Browser => ("browser", "ceremony"),
    CeremonyExpired => ("ceremony_expired", "ceremony"),
    CeremonyConsumed => ("ceremony_consumed", "ceremony"),
    CeremonyAttempts => ("ceremony_attempts", "ceremony"),
}
impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for Invalid {}

pub(crate) fn ensure(ok: bool, error: Invalid) -> super::Result<()> {
    if ok { Ok(()) } else { Err(error) }
}
