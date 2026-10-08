//! Read-only device preparation validator. Inputs are public build configuration/metadata.
use getrandom::SysRng;
use mikaki_identity::{
    issuance_encryption::WalletEncryption,
    wallet_profile::{self, Configuration},
};
use rand_core::{Rng, UnwrapErr};
use serde::Deserialize;
use serde_json::json;
use std::{
    io::{self, Read},
    time::{SystemTime, UNIX_EPOCH},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    configuration: Option<String>,
    metadata: Option<String>,
    oauth: Option<String>,
    jwks: Option<String>,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    io::stdin().take(128 * 1024 + 1).read_to_end(&mut bytes)?;
    let input: Input = serde_json::from_value(wallet_profile::strict_json(&bytes)?)?;
    let metadata = input
        .metadata
        .as_ref()
        .map(|s| wallet_profile::strict_json(s.as_bytes()))
        .transpose()?;
    let oauth = input
        .oauth
        .as_ref()
        .map(|s| wallet_profile::strict_json(s.as_bytes()))
        .transpose()?;
    let jwks = input
        .jwks
        .as_ref()
        .map(|s| wallet_profile::strict_json(s.as_bytes()))
        .transpose()?;
    let at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut checks = Vec::new();
    let mut check = |name: &str, result: Result<(), String>| {
        checks.push(match result {
            Ok(()) => json!({"name":name,"status":"pass"}),
            Err(reason) => json!({"name":name,"status":"blocked","reason":reason}),
        });
    };
    check(
        "wallet_configuration",
        input
            .configuration
            .as_deref()
            .ok_or("wallet_not_configured".to_owned())
            .and_then(|s| Configuration::parse(s, at))
            .map(|_| ()),
    );
    for configuration in ["linked_document", "linked_document_mdoc"] {
        check(
            configuration,
            match (&metadata, &oauth) {
                (Some(m), Some(a)) => wallet_profile::validate_metadata(m, a, configuration),
                _ => Err("metadata_unavailable".into()),
            },
        );
    }
    let signing = jwks
        .as_ref()
        .ok_or("issuer_key_unavailable".to_owned())
        .and_then(wallet_profile::issuer_key);
    check(
        "issuer_signing_key",
        signing.as_ref().map(|_| ()).map_err(Clone::clone),
    );
    check(
        "issuer_encryption",
        (|| -> Result<(), String> {
            let metadata = metadata.as_ref().ok_or("metadata_unavailable")?;
            let mut entropy = [0; 32];
            UnwrapErr(SysRng).fill_bytes(&mut entropy);
            let encryption = WalletEncryption::from_metadata(metadata, entropy, "preflight")
                .map_err(str::to_string)?
                .ok_or("invalid_metadata")?;
            let (key, _) = signing.as_ref().map_err(Clone::clone)?;
            if encryption.request_key().map_err(str::to_string)? == *key {
                return Err("invalid_metadata".into());
            }
            Ok(())
        })(),
    );
    println!(
        "{}",
        json!({"checks":checks,"ready":checks.iter().all(|c|c["status"]=="pass")})
    );
    Ok(())
}
