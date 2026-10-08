//! Test bridge for the same encryption core called by the Tauri receive command.
//! Two bounded JSON lines on stdin: metadata/payload, then actual encrypted response.
use getrandom::SysRng;
use mikaki_identity::issuance_encryption::WalletEncryption;
use rand_core::{Rng, UnwrapErr};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
use zeroize::Zeroizing;
fn line(input: &mut impl BufRead) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let mut bytes = Zeroizing::new(Vec::new());
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            return Err("missing fixture input".into());
        }
        let count = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |i| i + 1);
        if bytes.len() + count > 128 * 1024 {
            return Err("oversized fixture input".into());
        }
        let done = available[count - 1] == b'\n';
        bytes.extend_from_slice(&available[..count]);
        input.consume(count);
        if done {
            break;
        }
    }
    Ok(Zeroizing::new(String::from_utf8(std::mem::take(
        &mut *bytes,
    ))?))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = io::stdin().lock();
    let first: Value = serde_json::from_str(&line(&mut input)?)?;
    let mut secret = Zeroizing::new([0u8; 32]);
    UnwrapErr(SysRng).fill_bytes(&mut *secret);
    let context =
        WalletEncryption::from_metadata(&first["metadata"], *secret, "rust-wallet-session")?
            .ok_or("encryption required for fixture")?;
    UnwrapErr(SysRng).fill_bytes(&mut *secret);
    let mut iv = [0u8; 12];
    UnwrapErr(SysRng).fill_bytes(&mut iv);
    let request = context.prepare_request(first["payload"].clone(), *secret, iv)?;
    println!("{}", json!({"request":request}));
    io::stdout().flush()?;
    let response: Value = serde_json::from_str(&line(&mut input)?)?;
    let plain =
        context.decrypt_response(response["response"].as_str().ok_or("missing response")?)?;
    let issued: Value = serde_json::from_slice(&plain)?;
    println!("{}", issued);
    Ok(())
}
