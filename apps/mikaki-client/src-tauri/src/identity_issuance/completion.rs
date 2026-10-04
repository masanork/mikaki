//! Bounded verifier acknowledgement and preregistered browser completion.
use super::*;
use mikaki_identity::presentation::completion::{parse, Registration};

async fn acknowledgement(mut response: Response) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if response.status().as_u16() != 200
        || response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(str::trim)
            .is_none_or(|v| !v.eq_ignore_ascii_case("application/json"))
        || response.content_length().is_some_and(|n| n > 8192)
    {
        return Err("invalid_response");
    }
    if let Some(length) = response.headers().get("content-length") {
        let n = length
            .to_str()
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or("invalid_response")?;
        if n > 8192 {
            return Err("invalid_response");
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|_| "invalid_response")? {
        if bytes.len() + chunk.len() > 8192 {
            return Err("invalid_response");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
pub(super) async fn finish(
    app: &AppHandle,
    guard: &Gate,
    response: Response,
    client_id: &str,
) -> &'static str {
    let Ok(bytes) = acknowledgement(response).await else {
        return "invalid_response";
    };
    let Ok(registry) = serde_json::from_str::<Vec<Registration>>(
        option_env!("MIKAKI_OID4VP_REDIRECT_URIS").unwrap_or("[]"),
    ) else {
        return "rejected";
    };
    let uri = match parse(&bytes, client_id, &registry) {
        Ok(None) => return "not_requested",
        Ok(Some(uri)) => uri,
        Err("invalid_response") => return "invalid_response",
        Err(_) => return "rejected",
    };
    if !may_open(guard) {
        return "cancelled";
    }
    if app.opener().open_url(uri.as_str(), None::<&str>).is_ok() {
        "opened"
    } else {
        "browser_unavailable"
    }
}

fn may_open(guard: &Gate) -> bool {
    guard
        .state
        .lock()
        .is_ok_and(|s| s.generation == guard.generation)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn registry() -> Vec<Registration> {
        vec![Registration {
            client_id: "verifier".into(),
            redirect_uri: "https://verifier.example/complete".into(),
        }]
    }
    fn payload(uri: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"redirect_uri":uri})).unwrap()
    }
    #[test]
    fn pins_completion_endpoint_and_accepts_query_or_fragment_code() {
        let r = registry();
        let code = "q7w8e9r0t1y2u3i4o5p6a7s8d9f0g1h2";
        for separator in ["?", "#"] {
            let uri = format!("https://verifier.example/complete{separator}response_code={code}");
            assert_eq!(
                parse(&payload(&uri), "verifier", &r)
                    .unwrap()
                    .unwrap()
                    .as_str(),
                uri
            );
        }
        assert!(parse(br#"{"ignored_extension":true}"#, "verifier", &[])
            .unwrap()
            .is_none());
        assert!(parse(
            &payload(&format!(
                "https://verifier.example/complete?response_code={code}"
            )),
            "other",
            &r
        )
        .is_err());
        for uri in [
            "http://verifier.example/complete",
            "https://evil.example/complete",
            "https://verifier.example/other",
            "javascript:alert(1)",
            "https://user@verifier.example/complete",
            "https://verifier.example:444/complete",
            "https://verifier.example/complete?response_code=short",
            "https://verifier.example/complete?response_code=abcdefghijklmnopqrstuvwxyz&response_code=abcdefghijklmnopqrstuvwxyz",
            "https://verifier.example/complete?response_code=abcdefghijklmnopqrstuvwxyz&next=https://evil.example",
            "https://verifier.example/complete?response_code=abcdefghijklmnopqrstuvwxyz#response_code=abcdefghijklmnopqrstuvwxyz",
            "https://verifier.example/complete#response_code=abcdefghijklmnopqrstuv%0A",
        ] {
            assert!(parse(&payload(uri), "verifier", &r).is_err(), "{uri}");
        }
    }
    #[test]
    fn raw_verifier_fragment_is_exact_bounded_and_never_changes_completion_destination() {
        let r = registry();
        for length in [43, 128] {
            let code = format!("{}-._~", "A".repeat(length - 4));
            let uri = format!("https://verifier.example/complete#{code}");
            assert_eq!(
                parse(&payload(&uri), "verifier", &r)
                    .unwrap()
                    .unwrap()
                    .as_str(),
                uri
            );
        }
        for code in [
            "A".repeat(42),
            "A".repeat(129),
            format!("{}\t", "A".repeat(43)),
            format!("{}%41", "A".repeat(43)),
            format!("{}&next=evil", "A".repeat(43)),
            format!("{}/path", "A".repeat(43)),
        ] {
            assert!(parse(
                &payload(&format!("https://verifier.example/complete#{code}")),
                "verifier",
                &r
            )
            .is_err());
        }
        let code = "A".repeat(43);
        for uri in [
            format!("https://evil.example/complete#{code}"),
            format!("https://verifier.example/other#{code}"),
            format!("https://verifier.example/complete?x=1#{code}"),
            format!("https://verifier.example/complete?{code}"),
        ] {
            assert!(parse(&payload(&uri), "verifier", &r).is_err());
        }
    }
    #[test]
    fn rejects_malformed_or_oversized_acknowledgements_and_registry_ambiguity() {
        let r = registry();
        for bytes in [
            b"".as_slice(),
            b"[]",
            b"null",
            br#"{"redirect_uri":null}"#,
            br#"{"redirect_uri":1}"#,
            br#"{"redirect_uri":"x","redirect_uri":"y"}"#,
        ] {
            assert!(parse(bytes, "verifier", &r).is_err());
        }
        assert!(parse(&vec![b' '; 8193], "verifier", &r).is_err());
        let uri =
            payload("https://verifier.example/complete?response_code=abcdefghijklmnopqrstuvwxyz");
        let mut r = r;
        r.push(Registration {
            client_id: "verifier".into(),
            redirect_uri: "https://verifier.example/complete".into(),
        });
        assert!(parse(&uri, "verifier", &r).is_err());
    }
    #[test]
    fn requires_bounded_json_200_acknowledgement() {
        tauri::async_runtime::block_on(async {
            use openidconnect::http;
            for (status, mime, bytes, length, valid) in [
                (200, "application/json", b"{}".to_vec(), None, true),
                (
                    200,
                    "Application/JSON; charset=utf-8",
                    b"{}".to_vec(),
                    None,
                    true,
                ),
                (204, "application/json", Vec::new(), None, false),
                (302, "application/json", b"{}".to_vec(), None, false),
                (200, "text/html", b"{}".to_vec(), None, false),
                (200, "application/json", vec![b'x'; 8193], None, false),
                (200, "application/json", b"{}".to_vec(), Some("8193"), false),
            ] {
                let mut builder = http::Response::builder()
                    .status(status)
                    .header("content-type", mime);
                if let Some(n) = length {
                    builder = builder.header("content-length", n);
                }
                let response: Response = builder.body(bytes).unwrap().into();
                assert_eq!(
                    acknowledgement(response).await.is_ok(),
                    valid,
                    "status={status}, mime={mime}, length={length:?}"
                );
            }
        });
    }
    #[test]
    fn late_acknowledgement_cannot_open_after_cancellation() {
        let state = IdentityState::default();
        let guard = gate(&state).unwrap();
        assert!(may_open(&guard));
        state.0.lock().unwrap().generation += 1;
        assert!(!may_open(&guard));
    }
}
