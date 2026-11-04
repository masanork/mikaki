//! Local integration fixture. The fixed test key is public and never for accounts.
use mikaki_identity::{
    installation_proof::InstallationSigner,
    installation_transaction::{CompletionRequest, Started, StatusRequest},
    issuance::PublicJwk,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};

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
#[serde(tag = "action", deny_unknown_fields)]
enum Input {
    #[serde(rename = "start")]
    Start { jti: String, now: u64 },
    #[serde(rename = "challenge")]
    Challenge {
        response: Value,
        jti: String,
        now: u64,
    },
    #[serde(rename = "status")]
    Status { jti: String, now: u64 },
    #[serde(rename = "result")]
    Result { response: Value },
}
#[derive(Default)]
enum State {
    #[default]
    Empty,
    Started(Started),
    Completed(CompletionRequest),
    Waiting(CompletionRequest, StatusRequest),
}
fn process(state: &mut State, signer: &FixtureKey, input: Input) -> Result<Value, String> {
    let prior = std::mem::take(state);
    match (prior, input) {
        (State::Empty, Input::Start { jti, now }) => {
            let started = Started::begin(signer, "https://auth.example", &jti, now)?;
            let output = json!({"proof":started.proof()});
            *state = State::Started(started);
            Ok(output)
        }
        (State::Started(started), Input::Challenge { response, jti, now }) => {
            let raw = serde_json::to_vec(&response).map_err(|_| "invalid_fixture_input")?;
            let completed = started.challenge(&raw, now)?.complete(signer, &jti, now)?;
            let output = json!({"id":completed.id(),"proof":completed.proof()});
            *state = State::Completed(completed);
            Ok(output)
        }
        (State::Completed(mut completed), Input::Status { jti, now }) => {
            let request = completed.status_request(signer, &jti, now)?;
            let output = json!({"id":request.id(),"proof":request.proof()});
            *state = State::Waiting(completed, request);
            Ok(output)
        }
        (State::Waiting(completed, request), Input::Result { response }) => {
            let raw = serde_json::to_vec(&response).map_err(|_| "invalid_fixture_input")?;
            let status = request.response(&raw)?;
            let output = json!({"status":format!("{status:?}").to_lowercase()});
            *state = State::Completed(completed);
            Ok(output)
        }
        _ => Err("invalid_fixture_state".into()),
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = FixtureKey(SigningKey::from_slice(&[43; 32])?);
    let mut state = State::Empty;
    let mut out = io::stdout().lock();
    for line in io::stdin().lock().lines() {
        let line = line?;
        if line.len() > 4096 {
            return Err("fixture input too long".into());
        }
        let result = serde_json::from_str::<Input>(&line)
            .map_err(|_| "invalid_fixture_input".to_owned())
            .and_then(|input| process(&mut state, &signer, input));
        let response = match result {
            Ok(value) => value,
            Err(_) => json!({"error":"invalid_fixture_request"}),
        };
        writeln!(out, "{response}")?;
        out.flush()?;
    }
    Ok(())
}
