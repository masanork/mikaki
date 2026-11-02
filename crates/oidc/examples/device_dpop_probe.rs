//! Host-only test bridge; no device authorization endpoint or persistence.
use std::io::{self, Read};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut compact = String::new();
    io::stdin().take(8193).read_to_string(&mut compact)?;
    let proof = mikaki_oidc::verify_dpop_proof(
        &compact,
        "POST",
        "https://issuer.example/token",
        mikaki_oidc::DpopTarget::Token,
        1000,
    )
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid test proof"))?;
    println!(
        "{}",
        serde_json::json!({
            "thumbprint": proof.thumbprint(),
            "jti_hash": proof.jti_hash(),
            "retain_until": proof.retain_until(),
        })
    );
    Ok(())
}
