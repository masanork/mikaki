use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use mikaki_identity::{
    installation_proof::{InstallationSigner, Step, proof},
    issuance::PublicJwk,
};
use mikaki_oidc::{
    DpopTarget,
    installation_enrollment::{BoundInstallationProof, PendingInstallation},
    verify_dpop_proof,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

struct Key {
    public: SigningKey,
    signing: SigningKey,
}
impl InstallationSigner for Key {
    fn public_key(&self) -> Result<PublicJwk, String> {
        Ok(PublicJwk::from_key(self.public.verifying_key()))
    }
    fn sign_der(&self, input: &str) -> Result<Vec<u8>, String> {
        let signature: Signature = self.signing.sign(input.as_bytes());
        Ok(signature.to_der().as_bytes().to_vec())
    }
}
fn key(byte: u8) -> SigningKey {
    SigningKey::from_slice(&[byte; 32]).unwrap()
}
#[test]
fn native_proofs_verify_and_bind_to_server_challenge() {
    let signer = Key {
        public: key(1),
        signing: key(1),
    };
    let issuer = "https://auth.example";
    let start = format!("{issuer}/native/installations/start");
    let endpoint = format!("{issuer}/native/installations/complete");
    let jti = B64.encode([2; 32]);
    let nonce = B64.encode([3; 32]);
    let signed = proof(&signer, issuer, Step::Start, &jti, 1000).unwrap();
    let verified = verify_dpop_proof(&signed, "POST", &start, DpopTarget::Token, 1000).unwrap();
    assert_eq!(
        verified.thumbprint(),
        signer.public_key().unwrap().thumbprint().unwrap()
    );
    let signed = proof(
        &signer,
        issuer,
        Step::Complete { nonce: &nonce },
        &jti,
        1000,
    )
    .unwrap();
    let verified = verify_dpop_proof(&signed, "POST", &endpoint, DpopTarget::Token, 1000).unwrap();
    let thumbprint = signer.public_key().unwrap().thumbprint().unwrap();
    let pending = PendingInstallation {
        endpoint: &endpoint,
        nonce: &nonce,
        key_thumbprint: &thumbprint,
        created_at: 999,
        expires_at: 1050,
    };
    assert!(BoundInstallationProof::bind(&pending, &verified, 1000).is_some());
    assert!(verify_dpop_proof(&signed, "POST", &start, DpopTarget::Token, 1000).is_err());
    let wrong = B64.encode([4; 32]);
    assert!(
        BoundInstallationProof::bind(
            &PendingInstallation {
                nonce: &wrong,
                ..pending
            },
            &verified,
            1000
        )
        .is_none()
    );
}
#[test]
fn bad_configuration_and_mismatched_signer_fail_closed() {
    let signer = Key {
        public: key(1),
        signing: key(2),
    };
    let jti = B64.encode([2; 32]);
    assert!(proof(&signer, "https://auth.example", Step::Start, &jti, 1000).is_err());
    let signer = Key {
        public: key(1),
        signing: key(1),
    };
    for issuer in [
        "http://auth.example",
        "https://auth.example/",
        "https://auth.example/path",
        "https://user@auth.example",
        "https://auth.example?x=1",
    ] {
        assert!(proof(&signer, issuer, Step::Start, &jti, 1000).is_err());
    }
    assert!(proof(&signer, "https://auth.example", Step::Start, "short", 1000).is_err());
    assert!(
        proof(
            &signer,
            "https://auth.example",
            Step::Complete { nonce: "short" },
            &jti,
            1000
        )
        .is_err()
    );
}
