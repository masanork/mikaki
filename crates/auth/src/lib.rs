//! Ceremony evidence is bound to a server-side browser transaction.
use mikaki_webauthn::{self as webauthn, Invalid};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Ceremony {
    pub purpose: String,
    pub browser_hash: String,
    pub expires_at: u64,
    pub failures: u32,
    pub consumed: bool,
    pub context: webauthn::Context,
}

impl Ceremony {
    fn validate(
        &self,
        browser_hash: &str,
        now: u64,
        max_failures: u32,
        purpose: &str,
    ) -> Result<(), Invalid> {
        for (failed, error) in [
            (self.purpose != purpose, Invalid::CeremonyPurpose),
            (
                self.browser_hash.is_empty() || self.browser_hash != browser_hash,
                Invalid::Browser,
            ),
            (self.consumed, Invalid::CeremonyConsumed),
            (now >= self.expires_at, Invalid::CeremonyExpired),
            (self.failures >= max_failures, Invalid::CeremonyAttempts),
        ] {
            if failed {
                return Err(error);
            }
        }
        Ok(())
    }
    pub fn register(
        &self,
        browser_hash: &str,
        now: u64,
        max_failures: u32,
        response: webauthn::Registration,
    ) -> Result<webauthn::VerifiedRegistration, Invalid> {
        self.validate(browser_hash, now, max_failures, "register")?;
        webauthn::register(&self.context, response)
    }
    pub fn authenticate(
        &self,
        browser_hash: &str,
        now: u64,
        max_failures: u32,
        stored: &webauthn::StoredCredential,
        response: webauthn::Assertion,
    ) -> Result<webauthn::VerifiedAssertion, Invalid> {
        self.validate(browser_hash, now, max_failures, "authenticate")?;
        webauthn::authenticate(&self.context, stored, response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ceremony_bindings_expiration_and_attempt_boundaries() {
        let mut c = Ceremony {
            purpose: "register".into(),
            browser_hash: "browser".into(),
            expires_at: 100,
            failures: 0,
            consumed: false,
            context: webauthn::Context {
                challenge: String::new(),
                origin: String::new(),
                rp_id: String::new(),
                max_bytes: 65536,
                max_depth: 8,
                user_verification: Default::default(),
                authentication: Default::default(),
                algorithms: vec![-7],
                attestation: None,
                attestation_policy: Default::default(),
            },
        };
        assert!(c.validate("browser", 99, 5, "register").is_ok());
        assert_eq!(
            c.validate("browser", 100, 5, "register"),
            Err(Invalid::CeremonyExpired)
        );
        assert_eq!(
            c.validate("other", 99, 5, "register"),
            Err(Invalid::Browser)
        );
        assert_eq!(
            c.validate("browser", 99, 5, "authenticate"),
            Err(Invalid::CeremonyPurpose)
        );
        let browser = std::mem::take(&mut c.browser_hash);
        assert_eq!(c.validate("", 99, 5, "register"), Err(Invalid::Browser));
        c.browser_hash = browser;
        assert_eq!(
            c.validate("browser", 99, 0, "register"),
            Err(Invalid::CeremonyAttempts)
        );
        c.failures = 5;
        assert_eq!(
            c.validate("browser", 99, 5, "register"),
            Err(Invalid::CeremonyAttempts)
        );
        c.failures = 4;
        c.consumed = true;
        assert_eq!(
            c.validate("browser", 99, 5, "register"),
            Err(Invalid::CeremonyConsumed)
        );
    }
}
