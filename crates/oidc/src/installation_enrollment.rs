//! Proof binding for a proposed native installation enrollment.
//!
//! This is not an enrollment endpoint, user approval, device session or token.
//! The caller must authenticate and authorize the owner, issue the challenge,
//! and atomically consume the exact pending record together with replay and
//! registry writes. A valid proof alone must never authorize an account.
use crate::{VerifiedDpopProof, dpop::endpoint};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use sha2::{Digest, Sha256};

fn canonical_32(value: &str) -> bool {
    value.len() == 43
        && B64
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == 32 && B64.encode(bytes) == value)
}

/// Values must be loaded from a trusted server-created pending record and
/// configured endpoint, not reconstructed from a caller's proof or request.
#[derive(Clone, Copy)]
pub struct PendingInstallation<'a> {
    pub endpoint: &'a str,
    pub nonce: &'a str,
    pub key_thumbprint: &'a str,
    pub created_at: u64,
    pub expires_at: u64,
}

/// This does not implement Deserialize and can only follow verified proof
/// binding. Storage must recheck the pending record and live owner authority.
///
/// ```compile_fail
/// let _: mikaki_oidc::installation_enrollment::BoundInstallationProof<'_> =
///     serde_json::from_str("{}").unwrap();
/// ```
#[must_use = "atomically consume the challenge and replay record with enrollment"]
pub struct BoundInstallationProof<'a> {
    proof: &'a VerifiedDpopProof,
    nonce_hash: String,
}

impl<'a> BoundInstallationProof<'a> {
    pub fn bind(
        pending: &PendingInstallation<'_>,
        proof: &'a VerifiedDpopProof,
        now: u64,
    ) -> Option<Self> {
        let url = url::Url::parse(pending.endpoint).ok()?;
        if url.query().is_some() || url.fragment().is_some() {
            return None;
        }
        let canonical_endpoint = endpoint(pending.endpoint).ok()?;
        if !canonical_32(pending.nonce)
            || !canonical_32(pending.key_thumbprint)
            || pending.created_at > now
            || pending.expires_at <= now
            || pending.expires_at <= pending.created_at
            || pending.expires_at - pending.created_at > 120
            || !proof.is_token_post_to(&canonical_endpoint)
            || proof.thumbprint() != pending.key_thumbprint
            || proof.nonce() != Some(pending.nonce)
            || proof.issued_at().saturating_add(10) < pending.created_at
            || proof.issued_at() > now.saturating_add(10)
            || proof.retain_until() < now
        {
            return None;
        }
        Some(Self {
            proof,
            nonce_hash: B64.encode(Sha256::digest(pending.nonce.as_bytes())),
        })
    }

    pub fn thumbprint(&self) -> &str {
        self.proof.thumbprint()
    }
    pub fn replay_id_hash(&self) -> &str {
        self.proof.jti_hash()
    }
    pub fn nonce_hash(&self) -> &str {
        &self.nonce_hash
    }
    pub fn replay_retain_until(&self) -> u64 {
        self.proof.retain_until()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::{DpopTarget, verify_dpop_proof};
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use serde_json::json;

    const ENDPOINT: &str = "https://auth.example/native/installations/complete";
    fn signed(key: &SigningKey, nonce: &str, endpoint: &str, issued: u64) -> String {
        let point = key.verifying_key().to_sec1_point(false);
        let header = json!({"alg":"ES256","typ":"dpop+jwt","jwk":{
            "kty":"EC","crv":"P-256","x":B64.encode(point.x().unwrap()),"y":B64.encode(point.y().unwrap())
        }});
        let claims =
            json!({"htm":"POST","htu":endpoint,"jti":"one-use-test", "iat":issued,"nonce":nonce});
        let input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header).unwrap()),
            B64.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature: Signature = key.sign(input.as_bytes());
        format!("{input}.{}", B64.encode(signature.to_bytes()))
    }

    #[test]
    fn real_proof_must_match_the_pending_key_nonce_endpoint_and_deadlines() {
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let other = SigningKey::from_slice(&[8; 32]).unwrap();
        let nonce = B64.encode([9; 32]);
        let compact = signed(&key, &nonce, ENDPOINT, 1000);
        let proof = verify_dpop_proof(&compact, "POST", ENDPOINT, DpopTarget::Token, 1000).unwrap();
        let pending = PendingInstallation {
            endpoint: ENDPOINT,
            nonce: &nonce,
            key_thumbprint: proof.thumbprint(),
            created_at: 1000,
            expires_at: 1060,
        };
        let accepted = BoundInstallationProof::bind(&pending, &proof, 1000).unwrap();
        assert_eq!(accepted.thumbprint(), proof.thumbprint());
        assert_eq!(accepted.replay_id_hash(), proof.jti_hash());
        assert!(BoundInstallationProof::bind(&pending, &proof, 1060).is_none());
        assert!(
            BoundInstallationProof::bind(
                &PendingInstallation {
                    nonce: &B64.encode([8; 32]),
                    ..pending
                },
                &proof,
                1000
            )
            .is_none()
        );
        assert!(
            BoundInstallationProof::bind(
                &PendingInstallation {
                    endpoint: "https://auth.example/other",
                    ..pending
                },
                &proof,
                1000
            )
            .is_none()
        );
        assert!(
            BoundInstallationProof::bind(
                &PendingInstallation {
                    endpoint: "https://auth.example/native/installations/complete?x=1",
                    ..pending
                },
                &proof,
                1000
            )
            .is_none()
        );
        assert!(
            BoundInstallationProof::bind(
                &PendingInstallation {
                    created_at: 1001,
                    ..pending
                },
                &proof,
                1000
            )
            .is_none()
        );
        assert!(
            BoundInstallationProof::bind(
                &PendingInstallation {
                    expires_at: 1121,
                    ..pending
                },
                &proof,
                1000
            )
            .is_none()
        );
        let wrong_key = verify_dpop_proof(
            &signed(&other, &nonce, ENDPOINT, 1000),
            "POST",
            ENDPOINT,
            DpopTarget::Token,
            1000,
        )
        .unwrap();
        assert!(BoundInstallationProof::bind(&pending, &wrong_key, 1000).is_none());
        assert!(
            verify_dpop_proof(
                &compact,
                "POST",
                "https://auth.example/other",
                DpopTarget::Token,
                1000
            )
            .is_err()
        );
    }
}
