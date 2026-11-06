//! Local test fixture only. This public fixed key must never protect an account.
use mikaki_identity::{
    installation_proof::{InstallationSigner, Step, proof},
    issuance::PublicJwk,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde::Deserialize;
use std::io::{self, Read};

struct FixtureKey(SigningKey);
impl InstallationSigner for FixtureKey {
    fn public_key(&self) -> Result<PublicJwk, String> {
        Ok(PublicJwk::from_key(self.0.verifying_key()))
    }
    fn sign_der(&self, input: &str) -> Result<Vec<u8>, String> {
        let signature: Signature = self.0.sign(input.as_bytes());
        Ok(signature.to_der().as_bytes().to_vec())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    jti: String,
    now: u64,
    nonce: Option<String>,
    #[serde(default)]
    status: bool,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut raw = String::new();
    io::stdin().take(4096).read_to_string(&mut raw)?;
    let input: Request = serde_json::from_str(&raw)?;
    let key = FixtureKey(SigningKey::from_slice(&[42; 32])?);
    let step = match (input.status, input.nonce.as_deref()) {
        (true, None) => Step::Status,
        (false, Some(nonce)) => Step::Complete { nonce },
        (false, None) => Step::Start,
        (true, Some(_)) => return Err("invalid fixture input".into()),
    };
    let result = proof(&key, "https://auth.example", step, &input.jti, input.now)?;
    println!("{result}");
    Ok(())
}
