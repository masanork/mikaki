use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// Platform randomness boundary. Implementations must fill from a CSPRNG.
pub trait CryptographicRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), CodeEntropyError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodeEntropyError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodeIssueError {
    EntropyUnavailable,
    InvalidLifetime,
}

/// A digest suitable for persistence in place of the bearer code.
pub struct CodeDigest(String);

impl CodeDigest {
    pub fn as_base64url(&self) -> &str {
        &self.0
    }
}

/// The one-time bearer value returned to the registered redirect URI.
/// It is neither serializable nor printable through `Debug`.
pub struct PresentedAuthorizationCode(String);

impl PresentedAuthorizationCode {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

/// Code material and its persistence value, ready for one atomic store operation.
#[must_use = "persist the digest and return the bearer code only after the store confirms issuance"]
pub(crate) struct IssuedAuthorizationCode {
    presented: PresentedAuthorizationCode,
    digest: CodeDigest,
    expires_at: u64,
}

impl IssuedAuthorizationCode {
    pub(crate) fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub(crate) fn into_parts(self) -> (PresentedAuthorizationCode, CodeDigest, u64) {
        (self.presented, self.digest, self.expires_at)
    }
}

/// Creates a 256-bit opaque code and only exposes its SHA-256 digest for storage.
/// The returned expiry never exceeds the parent session expiry.
pub(crate) fn issue_authorization_code(
    random: &mut impl CryptographicRandom,
    now: u64,
    lifetime_seconds: u64,
    parent_expires_at: u64,
) -> Result<IssuedAuthorizationCode, CodeIssueError> {
    let requested_expiry = now
        .checked_add(lifetime_seconds)
        .ok_or(CodeIssueError::InvalidLifetime)?;
    let expires_at = requested_expiry.min(parent_expires_at);
    if lifetime_seconds == 0 || expires_at <= now {
        return Err(CodeIssueError::InvalidLifetime);
    }

    let mut secret = [0; 32];
    random
        .fill(&mut secret)
        .map_err(|_| CodeIssueError::EntropyUnavailable)?;
    let presented = URL_SAFE_NO_PAD.encode(secret);
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(secret));
    Ok(IssuedAuthorizationCode {
        presented: PresentedAuthorizationCode(presented),
        digest: CodeDigest(digest),
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Authorization;

    struct FixedRandom {
        fail: bool,
    }

    fn validated_request() -> crate::ValidatedAuthorization {
        Authorization {
            client_id: "client".into(),
            redirect_uri: "https://app.example/callback".into(),
            response_type: "code".into(),
            scope: "openid".into(),
            state: "state".into(),
            nonce: "nonce".into(),
            code_challenge: crate::pkce("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap(),
            code_challenge_method: "S256".into(),
        }
        .validate("client", "https://app.example/callback", 256, 256)
        .unwrap()
    }

    impl CryptographicRandom for FixedRandom {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), CodeEntropyError> {
            if self.fail {
                return Err(CodeEntropyError);
            }
            for (i, byte) in output.iter_mut().enumerate() {
                *byte = i as u8;
            }
            Ok(())
        }
    }

    #[test]
    fn code_is_high_entropy_shape_digest_only_and_capped_by_parent() {
        let prepared = validated_request()
            .prepare_code(&mut FixedRandom { fail: false }, 100, 60, 130)
            .unwrap();
        assert_eq!(prepared.authorization().state(), "state");
        assert_eq!(prepared.expires_at(), 130);
        let (authorization, presented, digest, expiry) = prepared.into_parts();
        assert_eq!(authorization.client_id(), "client");
        assert_eq!(expiry, 130);
        assert_eq!(presented.as_str().len(), 43);
        assert!(
            presented
                .as_str()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        );
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest((0_u8..32).collect::<Vec<_>>()));
        assert_eq!(digest.as_base64url(), expected);
        assert_ne!(digest.as_base64url(), presented.as_str());
    }

    #[test]
    fn code_lifetime_and_entropy_fail_closed() {
        let mut random = FixedRandom { fail: false };
        assert_eq!(
            validated_request()
                .prepare_code(&mut random, 10, 0, 100)
                .err()
                .unwrap(),
            CodeIssueError::InvalidLifetime
        );
        assert_eq!(
            validated_request()
                .prepare_code(&mut random, 10, u64::MAX, u64::MAX)
                .err()
                .unwrap(),
            CodeIssueError::InvalidLifetime
        );
        assert_eq!(
            validated_request()
                .prepare_code(&mut random, 10, 20, 10)
                .err()
                .unwrap(),
            CodeIssueError::InvalidLifetime
        );
        assert_eq!(
            validated_request()
                .prepare_code(&mut FixedRandom { fail: true }, 10, 20, 100)
                .err()
                .unwrap(),
            CodeIssueError::EntropyUnavailable
        );
    }
}
