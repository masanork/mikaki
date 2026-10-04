//! Host test adapter for the exact native HTTP transport; no signing keys or Tauri UI.
#[path = "../src/identity_issuance/presentation_transport.rs"]
mod transport;
use openidconnect::reqwest;
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};
use std::time::Duration;
use zeroize::Zeroizing;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut input = io::stdin().lock();
    let mut config = String::new();
    if input.by_ref().take(16 * 1024 + 1).read_line(&mut config)? > 16 * 1024 {
        return Err("oversized fixture configuration".into());
    }
    let config: Value = serde_json::from_str(&config)?;
    let client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .add_root_certificate(reqwest::Certificate::from_pem(
            config["tls_ca"]
                .as_str()
                .ok_or("missing TLS CA")?
                .as_bytes(),
        )?)
        .build()?;
    for _ in 0..32 {
        let mut line = Zeroizing::new(String::new());
        // The test driver is trusted; keep even its commands bounded.
        let count = input.by_ref().take(128 * 1024 + 1).read_line(&mut line)?;
        if count == 0 || count > 128 * 1024 {
            return Err("invalid command length".into());
        }
        let v: Value = serde_json::from_str(&line)?;
        if v["command"] == "finish" {
            return Ok(());
        }
        let uri = v["uri"].as_str().ok_or("missing URI")?;
        let url = url::Url::parse(uri)?;
        if url.scheme() != "https" || url.host_str() != Some("127.0.0.1") {
            return Err("nonfixture endpoint".into());
        }
        let operation_client = if v["untrusted_tls"] == json!(true) {
            reqwest::ClientBuilder::new()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()?
        } else {
            client.clone()
        };
        let result = runtime.block_on(async {
            if v["command"] == "retrieve" {
                let form: Vec<(String, String)> =
                    serde_json::from_value(v["form"].clone()).map_err(|_| "invalid form")?;
                transport::retrieve(
                    operation_client
                        .post(url)
                        .form(&form)
                        .header("accept", "application/oauth-authz-req+jwt"),
                )
                .await
                .map(|jwt| json!({"jwt":&*jwt}))
            } else if v["command"] == "deliver" {
                let response = v["response"].as_str().ok_or("missing response")?;
                transport::deliver(&operation_client, uri, &[("response", response)])
                    .await
                    .map(|response| json!({"status":response.status().as_u16()}))
            } else {
                Err("unknown command")
            }
        });
        let output = match result {
            Ok(value) => value,
            Err(error) => json!({"error":error}),
        };
        println!("{output}");
        io::stdout().flush()?;
    }
    Err("fixture command bound exceeded".into())
}
