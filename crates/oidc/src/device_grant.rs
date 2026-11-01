//! Experimental RFC 8628 grant state transitions, not an authorization server.
//!
//! Callers MUST serialize each load/transition/store as one atomic operation;
//! this module provides no persistence, entropy, authentication, rate limiting,
//! token issuance, phishing mitigation or DPoP replay protection. Do not expose
//! this state machine directly as a production endpoint.

use crate::{VerifiedDpopProof, dpop::endpoint};

/// Construct only from trusted server configuration, never request parameters.
/// Query and fragment are excluded following DPoP URL comparison semantics.
pub struct GrantEndpoints {
    initiation: String,
    token: String,
}

impl GrantEndpoints {
    pub fn new(initiation: &str, token: &str) -> Option<Self> {
        let initiation = endpoint(initiation).ok()?;
        let token = endpoint(token).ok()?;
        if initiation == token {
            return None;
        }
        Some(Self { initiation, token })
    }
}

/// The device grant is bound to a verified proof key by a separate,
/// currently unspecified profile. The proof does not authenticate the client.
/// The caller must use trusted endpoint configuration and atomically reserve
/// the proof's replay identifier with the corresponding state change.
/// Unverified key strings cannot be substituted for verified proof objects:
///
/// ```compile_fail
/// use mikaki_oidc::device_grant::Grant;
/// let _ = Grant::new("client".into(), "unverified-key", unimplemented!(), 0, 60, 5);
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct Grant {
    client: String,
    key_thumbprint: String,
    token_endpoint: String,
    expires_at: u64,
    interval: u64,
    next_poll_at: u64,
    state: State,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum State {
    Pending,
    Approved { owner: String },
    Denied,
    Redeemed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PollResult {
    AuthorizationPending,
    SlowDown,
    AccessDenied,
    ExpiredToken,
    InvalidGrant,
    /// This is only a state transition, not an issued token.
    Authorized {
        owner: String,
    },
}

impl Grant {
    /// Times are server-side seconds. The caller verifies client policy, the
    /// digest of device_code and validates the proof for the initiation
    /// endpoint before transition. This initial proof is a proposed extension,
    /// not a standardized RFC 8628 parameter.
    pub fn new(
        client: String,
        proof: &VerifiedDpopProof,
        endpoints: &GrantEndpoints,
        now: u64,
        expires_at: u64,
        interval: u64,
    ) -> Option<Self> {
        if client.is_empty()
            || expires_at <= now
            || interval == 0
            || !proof.is_token_post_to(&endpoints.initiation)
            || proof.issued_at() > now.saturating_add(10)
            || proof.retain_until() < now
        {
            return None;
        }
        Some(Self {
            client,
            key_thumbprint: proof.thumbprint().to_owned(),
            token_endpoint: endpoints.token.clone(),
            expires_at,
            interval,
            next_poll_at: now.saturating_add(interval),
            state: State::Pending,
        })
    }

    /// Call only after an authenticated, CSRF-protected user decision and any
    /// required phishing/proximity mitigation have succeeded.
    pub fn approve(&mut self, owner: &str, now: u64) -> bool {
        if owner.is_empty() || now >= self.expires_at || self.state != State::Pending {
            return false;
        }
        self.state = State::Approved {
            owner: owner.to_owned(),
        };
        true
    }

    pub fn deny(&mut self, now: u64) -> bool {
        if now >= self.expires_at || self.state != State::Pending {
            return false;
        }
        self.state = State::Denied;
        true
    }

    /// Proof must be validated for the token endpoint and its replay record
    /// atomically consumed. Atomic persistence must include token issuance or
    /// define explicit lost-response recovery. This function alone does neither.
    pub fn poll(&mut self, client: &str, proof: &VerifiedDpopProof, now: u64) -> PollResult {
        if client != self.client
            || proof.thumbprint() != self.key_thumbprint
            || !proof.is_token_post_to(&self.token_endpoint)
            || proof.issued_at() > now.saturating_add(10)
            || proof.retain_until() < now
        {
            return PollResult::InvalidGrant;
        }
        if now >= self.expires_at {
            return PollResult::ExpiredToken;
        }
        if self.state == State::Redeemed {
            return PollResult::InvalidGrant;
        }
        if self.state == State::Denied {
            return PollResult::AccessDenied;
        }
        if now < self.next_poll_at {
            self.interval = self.interval.saturating_add(5);
            self.next_poll_at = now.saturating_add(self.interval);
            return PollResult::SlowDown;
        }
        self.next_poll_at = now.saturating_add(self.interval);
        match &self.state {
            State::Pending => PollResult::AuthorizationPending,
            State::Approved { owner } => {
                let owner = owner.clone();
                self.state = State::Redeemed;
                PollResult::Authorized { owner }
            }
            State::Denied | State::Redeemed => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DpopTarget, verify_dpop_proof};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn proof(key_byte: u8, endpoint: &str, now: u64) -> VerifiedDpopProof {
        proof_for_method(key_byte, endpoint, "POST", now)
    }
    fn proof_for_method(key_byte: u8, endpoint: &str, method: &str, now: u64) -> VerifiedDpopProof {
        proof_for_target(key_byte, endpoint, method, now, false)
    }
    fn proof_for_target(
        key_byte: u8,
        endpoint: &str,
        method: &str,
        now: u64,
        resource: bool,
    ) -> VerifiedDpopProof {
        let key = SigningKey::from_slice(&[key_byte; 32]).unwrap();
        let point = key.verifying_key().to_sec1_point(false);
        let header = json!({"alg":"ES256","typ":"dpop+jwt","jwk":{
            "kty":"EC","crv":"P-256","x":B64.encode(point.x().unwrap()),"y":B64.encode(point.y().unwrap())
        }});
        let mut claims = json!({"htm":method,"htu":endpoint,"jti":"probe", "iat":now});
        if resource {
            claims["ath"] = json!(B64.encode(Sha256::digest(b"fixture-token")));
        }
        let input = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );
        let signature: Signature = key.sign(input.as_bytes());
        let compact = format!("{input}.{}", B64.encode(signature.to_bytes()));
        if resource {
            let thumbprint = proof_for_target(key_byte, endpoint, method, now, false)
                .thumbprint()
                .to_owned();
            verify_dpop_proof(
                &compact,
                method,
                endpoint,
                DpopTarget::Resource {
                    access_token: "fixture-token",
                    thumbprint: &thumbprint,
                },
                now,
            )
            .unwrap()
        } else {
            verify_dpop_proof(&compact, method, endpoint, DpopTarget::Token, now).unwrap()
        }
    }
    fn auth_proof() -> VerifiedDpopProof {
        proof(7, "https://issuer.example/device_authorization", 100)
    }
    fn token_proof(now: u64) -> VerifiedDpopProof {
        proof(7, "https://issuer.example/token", now)
    }
    fn other_proof(now: u64) -> VerifiedDpopProof {
        proof(8, "https://issuer.example/token", now)
    }
    fn endpoints() -> GrantEndpoints {
        GrantEndpoints::new(
            "https://issuer.example/device_authorization",
            "https://issuer.example/token",
        )
        .unwrap()
    }
    fn grant() -> Grant {
        Grant::new("nihos".into(), &auth_proof(), &endpoints(), 100, 200, 5).unwrap()
    }

    #[test]
    fn pending_slowdown_and_one_time_authorization() {
        let mut g = grant();
        assert_eq!(
            g.poll("nihos", &token_proof(105), 105),
            PollResult::AuthorizationPending
        );
        assert_eq!(
            g.poll("nihos", &token_proof(106), 106),
            PollResult::SlowDown
        );
        assert!(g.approve("alice", 107));
        assert_eq!(
            g.poll("nihos", &token_proof(116), 116),
            PollResult::Authorized {
                owner: "alice".into()
            }
        );
        assert_eq!(
            g.poll("nihos", &token_proof(130), 130),
            PollResult::InvalidGrant
        );
        assert!(!g.approve("bob", 130));
    }

    #[test]
    fn wrong_client_or_key_cannot_consume_or_change_poll_timing() {
        let mut g = grant();
        assert_eq!(
            g.poll("other", &token_proof(101), 101),
            PollResult::InvalidGrant
        );
        assert_eq!(
            g.poll("nihos", &other_proof(101), 101),
            PollResult::InvalidGrant
        );
        assert_eq!(
            g.poll("nihos", &token_proof(1), 101),
            PollResult::InvalidGrant
        );
        assert_eq!(
            g.poll("nihos", &proof(7, "https://issuer.example/other", 101), 101),
            PollResult::InvalidGrant
        );
        assert_eq!(
            g.poll("nihos", &auth_proof(), 101),
            PollResult::InvalidGrant
        );
        assert_eq!(
            g.poll(
                "nihos",
                &proof_for_method(7, "https://issuer.example/token", "GET", 101),
                101
            ),
            PollResult::InvalidGrant
        );
        assert_eq!(
            g.poll(
                "nihos",
                &proof_for_target(7, "https://issuer.example/token", "POST", 101, true),
                101
            ),
            PollResult::InvalidGrant
        );
        assert!(g.approve("alice", 102));
        assert_eq!(
            g.poll("nihos", &token_proof(105), 105),
            PollResult::Authorized {
                owner: "alice".into()
            }
        );
    }

    #[test]
    fn expiry_denial_and_invalid_construction() {
        let mut expired = grant();
        assert!(!expired.approve("alice", 200));
        assert_eq!(
            expired.poll("nihos", &token_proof(200), 200),
            PollResult::ExpiredToken
        );
        let mut denied = grant();
        assert!(denied.deny(101));
        assert!(!denied.approve("alice", 102));
        assert_eq!(
            denied.poll("nihos", &token_proof(105), 105),
            PollResult::AccessDenied
        );
        assert!(Grant::new("nihos".into(), &auth_proof(), &endpoints(), 100, 200, 0).is_none());
        assert!(Grant::new("nihos".into(), &token_proof(100), &endpoints(), 100, 200, 5).is_none());
        assert!(
            GrantEndpoints::new(
                "http://issuer.example/device",
                "https://issuer.example/token"
            )
            .is_none()
        );
        assert!(
            GrantEndpoints::new(
                "https://issuer.example/token",
                "https://issuer.example/token"
            )
            .is_none()
        );
    }
}
