//! Host-only bridge for the local D1 fixture; not a product endpoint.
use std::io::{self, Read};

#[derive(serde::Deserialize)]
struct Input {
    compact: String,
    nonce: String,
    thumbprint: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut body = String::new();
    io::stdin().take(12_001).read_to_string(&mut body)?;
    if body.len() > 12_000 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "fixture too large").into());
    }
    let input: Input = serde_json::from_str(&body)?;
    let endpoint = "https://auth.example/native/installations/complete";
    let proof = mikaki_oidc::verify_dpop_proof(
        &input.compact,
        "POST",
        endpoint,
        mikaki_oidc::DpopTarget::Token,
        1000,
    )
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid proof"))?;
    let pending = mikaki_oidc::installation_enrollment::PendingInstallation {
        endpoint,
        nonce: &input.nonce,
        key_thumbprint: &input.thumbprint,
        created_at: 1000,
        expires_at: 1060,
    };
    let bound =
        mikaki_oidc::installation_enrollment::BoundInstallationProof::bind(&pending, &proof, 1000)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "proof binding failed"))?;
    println!(
        "{}",
        serde_json::json!({"key": bound.thumbprint(), "proofId": bound.replay_id_hash(), "nonceHash":bound.nonce_hash()})
    );
    Ok(())
}
