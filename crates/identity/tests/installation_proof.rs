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

#[test]
fn transaction_retains_key_challenge_and_expiry_until_completion_request() {
    use mikaki_identity::installation_transaction::Started;
    let signer = Key {
        public: key(1),
        signing: key(1),
    };
    let issuer = "https://auth.example";
    let first = B64.encode([11; 32]);
    let second = B64.encode([12; 32]);
    let id = B64.encode([13; 32]);
    let nonce = B64.encode([14; 32]);
    let response = serde_json::json!({"id":id,"nonce":nonce,"expires_at":1120}).to_string();
    let started = Started::begin(&signer, issuer, &first, 1000).unwrap();
    let _verified_start = verify_dpop_proof(
        started.proof(),
        "POST",
        &format!("{issuer}/native/installations/start"),
        DpopTarget::Token,
        1000,
    )
    .unwrap();
    let request = started
        .challenge(response.as_bytes(), 1001)
        .unwrap()
        .complete(&signer, &second, 1002)
        .unwrap();
    assert_eq!(request.id(), id);
    let endpoint = format!("{issuer}/native/installations/complete");
    let verified =
        verify_dpop_proof(request.proof(), "POST", &endpoint, DpopTarget::Token, 1002).unwrap();
    let thumbprint = signer.public_key().unwrap().thumbprint().unwrap();
    assert!(
        BoundInstallationProof::bind(
            &PendingInstallation {
                endpoint: &endpoint,
                nonce: &nonce,
                key_thumbprint: &thumbprint,
                created_at: 1000,
                expires_at: 1120
            },
            &verified,
            1002
        )
        .is_some()
    );
}

#[test]
fn transaction_rejects_invalid_challenges_stale_time_reused_jti_and_key_change() {
    use mikaki_identity::installation_transaction::Started;
    let signer = Key {
        public: key(1),
        signing: key(1),
    };
    let other = Key {
        public: key(2),
        signing: key(2),
    };
    let first = B64.encode([11; 32]);
    let second = B64.encode([12; 32]);
    let id = B64.encode([13; 32]);
    let nonce = B64.encode([14; 32]);
    let begin = || Started::begin(&signer, "https://auth.example", &first, 1000).unwrap();
    let response =
        |expiry| serde_json::json!({"id":id,"nonce":nonce,"expires_at":expiry}).to_string();
    assert!(begin().challenge(response(1120).as_bytes(), 999).is_err());
    assert!(begin().challenge(response(1001).as_bytes(), 1001).is_err());
    assert!(begin().challenge(response(1131).as_bytes(), 1001).is_err());
    assert!(
        begin()
            .challenge(br#"{"id":"bad","nonce":"bad","expires_at":1120}"#, 1001)
            .is_err()
    );
    let extra =
        serde_json::json!({"id":id,"nonce":nonce,"expires_at":1120,"extra":true}).to_string();
    assert!(begin().challenge(extra.as_bytes(), 1001).is_err());
    assert!(begin().challenge(&vec![b' '; 1025], 1001).is_err());
    assert!(
        begin()
            .challenge(response(1120).as_bytes(), 1001)
            .unwrap()
            .complete(&signer, &first, 1002)
            .is_err()
    );
    assert!(
        begin()
            .challenge(response(1120).as_bytes(), 1001)
            .unwrap()
            .complete(&signer, &second, 1120)
            .is_err()
    );
    assert!(
        begin()
            .challenge(response(1120).as_bytes(), 1001)
            .unwrap()
            .complete(&signer, &second, 999)
            .is_err()
    );
    assert!(
        begin()
            .challenge(response(1120).as_bytes(), 1001)
            .unwrap()
            .complete(&other, &second, 1002)
            .is_err()
    );
}

#[test]
fn lost_response_status_is_key_bound_and_strictly_parsed() {
    use mikaki_identity::installation_transaction::{RegistrationStatus, Started};
    let signer = Key {
        public: key(1),
        signing: key(1),
    };
    let other = Key {
        public: key(2),
        signing: key(2),
    };
    let first = B64.encode([11; 32]);
    let second = B64.encode([12; 32]);
    let third = B64.encode([15; 32]);
    let id = B64.encode([13; 32]);
    let nonce = B64.encode([14; 32]);
    let challenge = serde_json::json!({"id": id, "nonce": nonce, "expires_at": 1120}).to_string();
    let mut complete = Started::begin(&signer, "https://auth.example", &first, 1000)
        .unwrap()
        .challenge(challenge.as_bytes(), 1001)
        .unwrap()
        .complete(&signer, &second, 1002)
        .unwrap();
    assert!(complete.status_request(&other, &third, 1003).is_err());
    assert!(complete.status_request(&signer, &first, 1003).is_err());
    assert!(complete.status_request(&signer, &second, 1003).is_err());
    assert!(complete.status_request(&signer, &third, 999).is_err());
    let status = complete.status_request(&signer, &third, 1003).unwrap();
    assert_eq!(status.id(), id);
    let verified = verify_dpop_proof(
        status.proof(),
        "POST",
        "https://auth.example/native/installations/status",
        DpopTarget::Token,
        1003,
    )
    .unwrap();
    assert_eq!(
        verified.thumbprint(),
        signer.public_key().unwrap().thumbprint().unwrap()
    );
    let body = serde_json::json!({"id":id,"status":"active"}).to_string();
    assert_eq!(
        status.response(body.as_bytes()).unwrap(),
        RegistrationStatus::Active
    );
    assert!(complete.status_request(&signer, &third, 1004).is_err());
    for (i, body) in [
        serde_json::json!({"id":B64.encode([99;32]),"status":"active"}).to_string(),
        serde_json::json!({"id":id,"status":"mystery"}).to_string(),
        serde_json::json!({"id":id,"status":"active","extra":true}).to_string(),
        " ".repeat(1025),
    ]
    .iter()
    .enumerate()
    {
        let jti = B64.encode([20 + i as u8; 32]);
        assert!(
            complete
                .status_request(&signer, &jti, 1004)
                .unwrap()
                .response(body.as_bytes())
                .is_err()
        );
    }
    for (i, (value, expected)) in [
        ("pending", RegistrationStatus::Pending),
        ("revoked", RegistrationStatus::Revoked),
        ("unknown", RegistrationStatus::Unknown),
    ]
    .into_iter()
    .enumerate()
    {
        let jti = B64.encode([30 + i as u8; 32]);
        let body = serde_json::json!({"id":id,"status":value}).to_string();
        assert_eq!(
            complete
                .status_request(&signer, &jti, 1004)
                .unwrap()
                .response(body.as_bytes())
                .unwrap(),
            expected
        );
    }
}

#[test]
fn recovery_checkpoint_survives_restart_and_rejects_changed_authority_and_replay() {
    use mikaki_identity::installation_transaction::{
        RecoveryCheckpoint, RegistrationStatus, Started,
    };
    let signer = Key {
        public: key(1),
        signing: key(1),
    };
    let other = Key {
        public: key(2),
        signing: key(2),
    };
    let issuer = "https://auth.example";
    let start_jti = B64.encode([11; 32]);
    let completion_jti = B64.encode([12; 32]);
    let status_jti = B64.encode([15; 32]);
    let owner = B64.encode([16; 32]);
    let id = B64.encode([13; 32]);
    let nonce = B64.encode([14; 32]);
    let challenge = serde_json::json!({"id":id,"nonce":nonce,"expires_at":1120}).to_string();
    let completion = Started::begin(&signer, issuer, &start_jti, 1000)
        .unwrap()
        .challenge(challenge.as_bytes(), 1001)
        .unwrap()
        .complete(&signer, &completion_jti, 1002)
        .unwrap();
    let (checkpoint, completion_proof) = completion.into_recovery(&owner).unwrap();
    let bytes = checkpoint.encode().unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains(completion_proof.as_str()));
    assert!(!String::from_utf8_lossy(&bytes).contains(&nonce));
    assert!(
        RecoveryCheckpoint::restore(&bytes, issuer, &B64.encode([17; 32]), &signer, 1003).is_err()
    );
    assert!(
        RecoveryCheckpoint::restore(&bytes, "https://other.example", &owner, &signer, 1003)
            .is_err()
    );
    assert!(RecoveryCheckpoint::restore(&bytes, issuer, &owner, &other, 1003).is_err());
    assert!(RecoveryCheckpoint::restore(&bytes, issuer, &owner, &signer, 999).is_err());
    assert!(RecoveryCheckpoint::restore(&vec![0; 4097], issuer, &owner, &signer, 1003).is_err());
    let mut recovered = RecoveryCheckpoint::restore(&bytes, issuer, &owner, &signer, 1003).unwrap();
    let request = recovered
        .status_request(&signer, &status_jti, 1003)
        .unwrap();
    let persisted = recovered.encode().unwrap(); // Must succeed before transmitting request.
    drop(recovered);
    let mut restarted =
        RecoveryCheckpoint::restore(&persisted, issuer, &owner, &signer, 1004).unwrap();
    assert!(
        restarted
            .status_request(&signer, &status_jti, 1004)
            .is_err()
    );
    let verified = verify_dpop_proof(
        request.proof(),
        "POST",
        &format!("{issuer}/native/installations/status"),
        DpopTarget::Token,
        1003,
    )
    .unwrap();
    assert_eq!(
        verified.thumbprint(),
        signer.public_key().unwrap().thumbprint().unwrap()
    );
    let body = serde_json::json!({"id":id,"status":"active"}).to_string();
    assert_eq!(
        request.response(body.as_bytes()).unwrap(),
        RegistrationStatus::Active
    );
    let mut corrupt: serde_json::Value = serde_json::from_slice(&persisted).unwrap();
    corrupt["status_jtis"] = serde_json::json!([status_jti, status_jti]);
    assert!(
        RecoveryCheckpoint::restore(
            &serde_json::to_vec(&corrupt).unwrap(),
            issuer,
            &owner,
            &signer,
            1004
        )
        .is_err()
    );
}
