//! Native retrieval and one-use same-device invocations. Review IPC uses opaque IDs.
use super::*;
use mikaki_identity::presentation::{
    retrieval::{Method, RequestRetrieval},
    Profile, VerifierRegistration,
};
use serde::Deserialize;
use tauri::Emitter;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    client_id: String,
    request_uri: String,
}
pub(super) struct Invocation {
    client_id: String,
    request_uri: url::Url,
    method: Method,
}
fn parse(
    input: &url::Url,
    registry: &[VerifierRegistration],
    endpoints: &[Endpoint],
) -> Result<Invocation, String> {
    if input.as_str().len() > 4096
        || input.host_str().is_some()
        || !input.path().is_empty()
        || !input.username().is_empty()
        || input.password().is_some()
        || input.fragment().is_some()
        || !matches!(input.scheme(), "openid4vp" | "mdoc-openid4vp")
    {
        return Err("invalid_invocation".into());
    }
    let mut client_id = None;
    let mut request_uri = None;
    let mut method = None;
    for (key, value) in input.query_pairs() {
        match key.as_ref() {
            "client_id" if client_id.is_none() => client_id = Some(value.into_owned()),
            "request_uri" if request_uri.is_none() => request_uri = Some(value.into_owned()),
            "request_uri_method" if method.is_none() => method = Some(value.into_owned()),
            _ => return Err("invalid_invocation".into()),
        }
    }
    let client_id = client_id.ok_or("invalid_invocation")?;
    let verifier = registry
        .iter()
        .find(|v| v.client_id == client_id)
        .ok_or("untrusted_verifier")?;
    let method = match method.as_deref() {
        None => Method::Get,
        Some("get") if verifier.profile == Profile::Oid4vpFinalX509Hash => Method::Get,
        Some("post") if verifier.profile == Profile::Oid4vpFinalX509Hash => Method::Post,
        _ => return Err("invalid_invocation".into()),
    };
    let expected_scheme = match verifier.profile {
        Profile::Oid4vpFinal | Profile::Oid4vpFinalRequestKeys | Profile::Oid4vpFinalX509Hash => {
            "openid4vp"
        }
        Profile::Oid4vpDraft18Mdoc => "mdoc-openid4vp",
    };
    if input.scheme() != expected_scheme || endpoints.len() > 32 {
        return Err("invalid_invocation".into());
    }
    let matches: Vec<_> = endpoints
        .iter()
        .filter(|e| e.client_id == client_id)
        .collect();
    if matches.len() != 1 {
        return Err("request_uri_not_configured".into());
    }
    let endpoint =
        url::Url::parse(&matches[0].request_uri).map_err(|_| "verifier_configuration_invalid")?;
    let uri = url::Url::parse(&request_uri.ok_or("invalid_invocation")?)
        .map_err(|_| "invalid_invocation")?;
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err("verifier_configuration_invalid".into());
    }
    let mut base = uri.clone();
    base.set_query(None);
    if uri.as_str().len() > 2048 || uri.fragment().is_some() || base != endpoint {
        return Err("untrusted_request_uri".into());
    }
    Ok(Invocation {
        client_id,
        request_uri: uri,
        method,
    })
}
/// Called only by the native deep-link handler. The latest invocation replaces old consent.
#[cfg_attr(not(any(target_os = "android", target_os = "ios")), allow(dead_code))]
pub fn receive(app: &AppHandle, uri: &url::Url) {
    if !matches!(uri.scheme(), "openid4vp" | "mdoc-openid4vp") {
        return;
    }
    let Ok(registry) = verifier_registry() else {
        return;
    };
    let Ok(endpoints) = serde_json::from_str::<Vec<Endpoint>>(
        option_env!("MIKAKI_OID4VP_REQUEST_URIS").unwrap_or("[]"),
    ) else {
        return;
    };
    let Ok(invocation) = parse(uri, &registry, &endpoints) else {
        return;
    };
    let state = app.state::<IdentityState>();
    if let Ok(mut s) = state.0.lock() {
        s.generation = s.generation.wrapping_add(1);
        s.presentation = None;
        s.invocation = Some((random(), invocation, Instant::now()));
    }
    let _ = app.emit("identity-presentation-ready", ());
}
#[tauri::command]
pub fn pending_identity_invocation(
    #[allow(unused_variables)] app: AppHandle,
    state: State<'_, IdentityState>,
) -> Result<Option<String>, String> {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        use tauri_plugin_deep_link::DeepLinkExt;
        let check = {
            let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
            let check = !s.initial_invocation_checked && s.invocation.is_none();
            s.initial_invocation_checked = true;
            check
        };
        // Android's plugin may load after application setup. Read the launch intent
        // again once the bundled UI is ready, without repeatedly requeueing it.
        if check {
            if let Ok(Some(urls)) = app.deep_link().get_current() {
                for uri in urls {
                    receive(&app, &uri);
                }
            }
        }
    }
    let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
    if s.invocation
        .as_ref()
        .is_some_and(|(_, _, time)| time.elapsed() > Duration::from_secs(120))
    {
        s.invocation = None;
    }
    Ok(s.invocation.as_ref().map(|(id, _, _)| id.clone()))
}
#[tauri::command]
pub fn cancel_identity_presentation(state: State<'_, IdentityState>) -> Result<(), String> {
    let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
    s.invalidate_presentations();
    Ok(())
}
#[tauri::command]
pub async fn review_identity_invocation(
    app: AppHandle,
    state: State<'_, IdentityState>,
    invocation_id: String,
) -> Result<PresentationReview, String> {
    let guard = gate(&state)?;
    let invocation = {
        let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
        if !s.invocation.as_ref().is_some_and(|(id, _, time)| {
            id == &invocation_id && time.elapsed() <= Duration::from_secs(120)
        }) {
            return Err("invocation_expired".into());
        }
        s.invocation.take().ok_or("invocation_expired")?.1
    };
    let registry = verifier_registry()?;
    let verifier = registry
        .iter()
        .find(|v| v.client_id == invocation.client_id)
        .ok_or("untrusted_verifier")?;
    let mut entropy = [0; 32];
    OsRng.fill_bytes(&mut entropy);
    let mut retrieval = if verifier.profile == Profile::Oid4vpFinalX509Hash {
        Some(
            RequestRetrieval::new(verifier, invocation.method, now()?, entropy)
                .map_err(str::to_string)?,
        )
    } else {
        None
    };
    let request = super::presentation_transport::retrieve(request_builder(
        &client()?,
        &invocation,
        retrieval.as_ref(),
    )?)
    .await
    .map_err(str::to_string)?;
    if let Some(context) = retrieval.as_mut() {
        use mikaki_identity::presentation::retrieval::InventoryOutcome as Outcome;
        let vct = format!("{ISSUER}/types/linked-document");
        match context
            .evaluate_inventory(&request, &registry, &vct, now()?)
            .map_err(str::to_string)?
        {
            Outcome::Approved(checked) => super::inventory::prepare(
                &app,
                &state,
                &guard,
                Some(&invocation.client_id),
                *checked,
            ),
            Outcome::Error(error) => {
                let uri = error.response_uri().to_owned();
                let code = error.code();
                let deadline = error.expires_at();
                let hash = credential_hash(&format!("error:{}", error.request_hash()));
                {
                    let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
                    claim_error(&mut s, guard.generation, &hash, deadline, now()?)?;
                }
                let mut iv = [0; 12];
                OsRng.fill_bytes(&mut iv);
                let token = Zeroizing::new(
                    error
                        .encrypt(now()?, p256::SecretKey::random(&mut OsRng), iv)
                        .map_err(str::to_string)?,
                );
                {
                    let s = state.0.lock().map_err(|_| "identity_unavailable")?;
                    if s.generation != guard.generation {
                        return Err("identity_cancelled".into());
                    }
                    if now()? >= deadline {
                        return Err("request_expired".into());
                    }
                }
                // No receipt, holder key, retry, or browser completion on this path.
                super::presentation_transport::deliver(
                    &client()?,
                    &uri,
                    &[("response", token.as_str())],
                )
                .await
                .map_err(str::to_string)?;
                Err(code.into())
            }
        }
    } else {
        prepare_presentation(
            &app,
            &state,
            &request,
            &guard,
            Some(&invocation.client_id),
            None,
        )
    }
}

fn claim_error(
    s: &mut Inner,
    generation: u64,
    hash: &str,
    deadline: u64,
    at: u64,
) -> Result<(), String> {
    if s.generation != generation {
        return Err("identity_cancelled".into());
    }
    if at >= deadline {
        return Err("request_expired".into());
    }
    if s.presented_nonces.len() >= 256 || !s.presented_nonces.insert(hash.to_owned()) {
        return Err("request_consumed".into());
    }
    Ok(())
}

fn request_builder(
    client: &openidconnect::reqwest::Client,
    invocation: &Invocation,
    retrieval: Option<&RequestRetrieval>,
) -> Result<openidconnect::reqwest::RequestBuilder, String> {
    let request = match invocation.method {
        Method::Get => client.get(invocation.request_uri.clone()),
        Method::Post => client.post(invocation.request_uri.clone()).form(
            &retrieval
                .ok_or("invalid_invocation")?
                .form()
                .map_err(str::to_string)?,
        ),
    };
    Ok(request.header("accept", "application/oauth-authz-req+jwt"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn registry() -> Vec<VerifierRegistration> {
        use p256::ecdsa::SigningKey;
        vec![VerifierRegistration {
            client_id: "verifier".into(),
            name: "Verifier".into(),
            response_uri: "https://example.com/response".into(),
            kid: "key".into(),
            jwk: PublicJwk::from_key(SigningKey::from_slice(&[5; 32]).unwrap().verifying_key()),
            certificate_trust: None,
            response_encryption: None,
            profile: Profile::Oid4vpFinal,
        }]
    }
    fn link(endpoint: &str, extra: &str) -> url::Url {
        let mut u = url::Url::parse("openid4vp://").unwrap();
        u.query_pairs_mut()
            .append_pair("client_id", "verifier")
            .append_pair("request_uri", endpoint);
        url::Url::parse(&format!("{}{extra}", u.as_str())).unwrap()
    }
    #[test]
    fn invalidation_discards_queued_invocation_and_rejects_its_in_flight_generation() {
        let state = IdentityState::default();
        let pending = Invocation {
            client_id: "verifier".into(),
            request_uri: url::Url::parse("https://example.com/request").unwrap(),
            method: Method::Get,
        };
        state.0.lock().unwrap().invocation = Some(("queued".into(), pending, Instant::now()));
        let in_flight = gate(&state).unwrap();
        {
            let mut inner = state.0.lock().unwrap();
            inner.invalidate_presentations();
            assert!(inner.invocation.is_none());
            assert_ne!(inner.generation, in_flight.generation);
        }
        drop(in_flight);
        assert!(!state.0.lock().unwrap().busy);
    }
    #[test]
    fn binds_endpoint_and_rejects_ambiguous_invocations() {
        let r = registry();
        let e = vec![Endpoint {
            client_id: "verifier".into(),
            request_uri: "https://example.com/request".into(),
        }];
        assert!(parse(
            &link("https://example.com/request?session=opaque", ""),
            &r,
            &e
        )
        .is_ok());
        for uri in [
            "http://example.com/request",
            "https://evil.example/request",
            "https://example.com/request/other",
            "https://example.com/request#frag",
            "https://user@example.com/request",
        ] {
            assert!(parse(&link(uri, ""), &r, &e).is_err(), "{uri}");
        }
        for extra in [
            "&client_id=verifier",
            "&request_uri=x",
            "&request=jwt",
            "&client_metadata=x",
            "#fragment",
        ] {
            assert!(parse(&link("https://example.com/request", extra), &r, &e).is_err());
        }
        let mut legacy = r.clone();
        legacy[0].profile = Profile::Oid4vpDraft18Mdoc;
        let modern = link("https://example.com/request", "");
        assert!(parse(&modern, &legacy, &e).is_err());
        let old =
            url::Url::parse(&modern.as_str().replacen("openid4vp:", "mdoc-openid4vp:", 1)).unwrap();
        assert!(parse(&old, &legacy, &e).is_ok());
        assert!(parse(&old, &r, &e).is_err());
    }
    #[test]
    fn x509_hash_invocation_preserves_full_identity_without_profile_fallback() {
        let mut r = registry();
        r[0].profile = Profile::Oid4vpFinalX509Hash;
        r[0].client_id = format!("x509_hash:{}", "A".repeat(43));
        let e = vec![Endpoint {
            client_id: r[0].client_id.clone(),
            request_uri: "https://example.com/request".into(),
        }];
        let mut u = url::Url::parse("openid4vp://").unwrap();
        u.query_pairs_mut()
            .append_pair("client_id", &r[0].client_id)
            .append_pair("request_uri", "https://example.com/request?session=opaque");
        assert_eq!(parse(&u, &r, &e).unwrap().client_id, r[0].client_id);
        let wrong_scheme =
            url::Url::parse(&u.as_str().replacen("openid4vp:", "mdoc-openid4vp:", 1)).unwrap();
        assert!(parse(&wrong_scheme, &r, &e).is_err());
        assert!(parse(&link("https://example.com/request", ""), &r, &e).is_err());
    }
    #[test]
    fn post_invocations_require_explicit_x509_profile_and_unique_method() {
        let mut r = registry();
        r[0].profile = Profile::Oid4vpFinalX509Hash;
        r[0].client_id = format!("x509_hash:{}", "A".repeat(43));
        let e = vec![Endpoint {
            client_id: r[0].client_id.clone(),
            request_uri: "https://example.com/request".into(),
        }];
        let mut u = url::Url::parse("openid4vp://").unwrap();
        u.query_pairs_mut()
            .append_pair("client_id", &r[0].client_id)
            .append_pair("request_uri", "https://example.com/request")
            .append_pair("request_uri_method", "post");
        assert!(parse(&u, &r, &e).unwrap().method == Method::Post);
        for extra in [
            "&request_uri_method=post",
            "&request_uri_method=get",
            "&wallet_nonce=external",
        ] {
            assert!(parse(&url::Url::parse(&format!("{u}{extra}")).unwrap(), &r, &e).is_err());
        }
        let old = registry();
        let old_endpoint = vec![Endpoint {
            client_id: "verifier".into(),
            request_uri: "https://example.com/request".into(),
        }];
        assert!(parse(
            &link("https://example.com/request", "&request_uri_method=post"),
            &old,
            &old_endpoint
        )
        .is_err());
        let invalid = url::Url::parse(
            &u.as_str()
                .replace("request_uri_method=post", "request_uri_method=put"),
        )
        .unwrap();
        assert!(parse(&invalid, &r, &e).is_err());
    }
    #[test]
    fn native_post_request_encodes_shared_metadata_and_nonce_as_form_with_exact_accept() {
        let mut r = registry()[0].clone();
        r.profile = Profile::Oid4vpFinalX509Hash;
        r.client_id = format!("x509_hash:{}", "A".repeat(43));
        r.certificate_trust = Some(mikaki_identity::certificate::ReaderTrust {
            trust_anchors: vec![],
            dns_name: None,
            revocation: None,
        });
        let ctx = RequestRetrieval::new(&r, Method::Post, 1000, [9; 32]).unwrap();
        let invocation = Invocation {
            client_id: r.client_id,
            request_uri: url::Url::parse("https://example.com/request?session=opaque").unwrap(),
            method: Method::Post,
        };
        let request = request_builder(&client().unwrap(), &invocation, Some(&ctx))
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(request.method(), openidconnect::reqwest::Method::POST);
        assert_eq!(
            request.headers()["accept"],
            "application/oauth-authz-req+jwt"
        );
        assert_eq!(
            request.headers()["content-type"],
            "application/x-www-form-urlencoded"
        );
        assert_eq!(request.url(), &invocation.request_uri);
        let form = url::form_urlencoded::parse(request.body().unwrap().as_bytes().unwrap())
            .into_owned()
            .collect::<Vec<_>>();
        assert_eq!(form, ctx.form().unwrap());
        assert!(request_builder(&client().unwrap(), &invocation, None).is_err());
    }
    #[test]
    fn protocol_error_claim_is_cancelable_bounded_and_never_retried() {
        let mut s = Inner::default();
        assert!(claim_error(&mut s, 1, "hash", 120, 100).is_err());
        assert!(claim_error(&mut s, 0, "hash", 100, 100).is_err());
        assert!(s.presented_nonces.is_empty());
        claim_error(&mut s, 0, "hash", 120, 100).unwrap();
        assert!(s.receipt.is_none());
        assert!(claim_error(&mut s, 0, "hash", 120, 100).is_err());
        s.invalidate_presentations();
        assert!(claim_error(&mut s, 0, "new", 120, 100).is_err());
        for n in 1..256 {
            s.presented_nonces.insert(format!("hash-{n}"));
        }
        assert!(claim_error(&mut s, 1, "new", 120, 100).is_err());
        assert!(!s.presented_nonces.contains("new"));
    }
}
