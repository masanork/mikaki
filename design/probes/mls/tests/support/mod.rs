#![allow(dead_code)]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use mikaki_mls_probe::{BoundMlsClient, Invitation, trust::*};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{OpenMlsProvider, signatures::Signer, types::SignatureScheme};
use serde_json::{Value, json};
use zeroize::Zeroizing;

pub const NOW: u64 = 1_000;
pub const GROUP: [u8; 16] = [1; 16];
pub const ALICE: &str = "https://alice.example";
pub const BOB: &str = "https://bob.example";

pub fn device(issuer: &str, n: u8, generation: u64) -> DeviceIdentity {
    DeviceIdentity {
        issuer: issuer.into(),
        account_id: format!("00000000-0000-4000-8000-{n:012x}"),
        device_id: format!("10000000-0000-4000-8000-{n:012x}"),
        generation,
    }
}

pub struct Issuer {
    pub name: String,
    pub key: SignatureKeyPair,
    pub provider: OpenMlsRustCrypto,
}
impl Issuer {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            key: SignatureKeyPair::new(SignatureScheme::ED25519).unwrap(),
            provider: OpenMlsRustCrypto::default(),
        }
    }
    pub fn authority(&self) -> Authority {
        Authority {
            issuer: self.name.clone(),
            public_key: B64.encode(self.key.public()),
        }
    }
    pub fn sign(&self, header: Value, claims: Value) -> String {
        let input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header).unwrap()),
            B64.encode(serde_json::to_vec(&claims).unwrap())
        );
        format!(
            "{input}.{}",
            B64.encode(self.key.sign(input.as_bytes()).unwrap())
        )
    }
    pub fn header(&self) -> Value {
        json!({"typ": BINDING_TYPE, "alg":"EdDSA", "kid":key_id(self.key.public())})
    }
    pub fn binding(
        &self,
        identity: &DeviceIdentity,
        key: &[u8],
        revision: u64,
        status: Status,
        now: u64,
    ) -> String {
        self.sign(
            self.header(),
            serde_json::to_value(Binding {
                iss: self.name.clone(),
                aud: AUDIENCE.into(),
                device: identity.clone(),
                public_key: B64.encode(key),
                revision,
                status,
                iat: now,
                exp: now + 300,
            })
            .unwrap(),
        )
    }
    pub fn enroll(&self, client: &BoundMlsClient, expected: &DeviceIdentity, now: u64) -> String {
        let nonce = B64.encode([7; 32]);
        let proof = client.registration_proof(&nonce, now).unwrap();
        // expected is the fixture's authenticated server-side owner/challenge
        // context, not the account/identity supplied in the proof.
        let key =
            verify_registration(&proof, expected, &nonce, now, self.provider.crypto()).unwrap();
        self.binding(expected, &key, 1, Status::Active, now)
    }
}

pub struct Pair {
    pub a: Issuer,
    pub b: Issuer,
    pub alice: BoundMlsClient,
    pub bob: BoundMlsClient,
    pub alice_id: DeviceIdentity,
    pub bob_id: DeviceIdentity,
    pub alice_token: String,
    pub bob_token: String,
    pub authorities: String,
}
impl Pair {
    pub fn new() -> Self {
        let a = Issuer::new(ALICE);
        let b = Issuer::new(BOB);
        let authorities = serde_json::to_string(&[a.authority(), b.authority()]).unwrap();
        let alice_id = device(ALICE, 1, 1);
        let bob_id = device(BOB, 2, 1);
        let mut alice = BoundMlsClient::new(&alice_id.credential().unwrap(), &authorities).unwrap();
        let mut bob = BoundMlsClient::new(&bob_id.credential().unwrap(), &authorities).unwrap();
        let alice_token = a.enroll(&alice, &alice_id, NOW);
        let bob_token = b.enroll(&bob, &bob_id, NOW);
        alice.bind_self(&alice_token, NOW).unwrap();
        bob.bind_self(&bob_token, NOW).unwrap();
        alice
            .confirm_peer(&bob_token, &bob.fingerprint().unwrap(), NOW)
            .unwrap();
        bob.confirm_peer(&alice_token, &alice.fingerprint().unwrap(), NOW)
            .unwrap();
        Self {
            a,
            b,
            alice,
            bob,
            alice_id,
            bob_id,
            alice_token,
            bob_token,
            authorities,
        }
    }
    pub fn join(&mut self) {
        self.alice.create_group(&GROUP, NOW).unwrap();
        let package = self.bob.key_package(NOW).unwrap();
        let invitation: Invitation =
            serde_json::from_str(&self.alice.invite(&package, NOW).unwrap()).unwrap();
        self.alice.merge_pending(NOW).unwrap();
        self.bob.join(&invitation.welcome, &GROUP, NOW).unwrap();
    }
    pub fn reload(&self, client: &BoundMlsClient) -> BoundMlsClient {
        let state = Zeroizing::new(client.checkpoint().unwrap());
        BoundMlsClient::restore(&state, &self.authorities).unwrap()
    }
}

/// Deliberately bypass the sender's policy to construct authenticated attacks.
/// Only synthetic test state is opened here.
pub fn fixture_group(
    client: &BoundMlsClient,
) -> (
    OpenMlsRustCrypto,
    SignatureKeyPair,
    openmls::prelude::MlsGroup,
) {
    use openmls::prelude::*;
    let outer = Zeroizing::new(client.checkpoint().unwrap());
    let outer: Value = serde_json::from_slice(&outer).unwrap();
    let inner: Vec<u8> = serde_json::from_value(outer["inner"].clone()).unwrap();
    let inner = Zeroizing::new(inner);
    let inner: Value = serde_json::from_slice(&inner).unwrap();
    let provider = OpenMlsRustCrypto::default();
    let entries: Vec<(Vec<u8>, Vec<u8>)> =
        serde_json::from_value(inner["storage"].clone()).unwrap();
    provider.storage().values.write().unwrap().extend(entries);
    let public: Vec<u8> = serde_json::from_value(inner["public_key"].clone()).unwrap();
    let signer = SignatureKeyPair::read(
        provider.storage(),
        &public,
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.signature_algorithm(),
    )
    .unwrap();
    let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&GROUP))
        .unwrap()
        .unwrap();
    (provider, signer, group)
}
