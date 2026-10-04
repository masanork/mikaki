//! Native app-link dispatch only; no callback/code/state IPC input or event payload.
use super::*;
use tauri::Emitter;

fn owns(uri: &url::Url) -> bool {
    let mut base = uri.clone();
    base.set_query(None);
    base.set_fragment(None);
    base.as_str() == CALLBACK
}
#[derive(PartialEq, Debug)]
enum Outcome {
    Ready,
    Denied,
    Ignored,
    Expired,
}
fn accept(pending: &mut Pending, generation: u64, uri: &url::Url, at: u64) -> Outcome {
    if pending.generation != generation {
        return Outcome::Expired;
    }
    if pending.ready || !owns(uri) {
        return Outcome::Ignored;
    }
    match pending.session.protocol.accept_callback(uri.as_str(), at) {
        Ok(true) => {
            pending.ready = true;
            Outcome::Ready
        }
        Ok(false) => Outcome::Denied,
        Err(error) if error == "wallet_transaction_unavailable" => Outcome::Expired,
        Err(_) => Outcome::Ignored,
    }
}
/// Returning true reserves the dedicated callback even with no live issuance session.
/// It must never fall through to native login or presentation request handling.
#[cfg_attr(not(any(target_os = "android", target_os = "ios")), allow(dead_code))]
pub fn receive(app: &AppHandle, uri: &url::Url) -> bool {
    if !owns(uri) {
        return false;
    }
    let state = app.state::<IdentityState>();
    let Ok(mut inner) = state.0.lock() else {
        return true;
    };
    let generation = inner.generation;
    let Some(pending) = inner.haip.as_mut() else {
        return true;
    };
    let outcome = accept(pending, generation, uri, now().unwrap_or(u64::MAX));
    if matches!(outcome, Outcome::Denied | Outcome::Expired) {
        inner.haip = None;
    }
    inner.haip_state = match outcome {
        Outcome::Ready => "ready",
        Outcome::Denied => "denied",
        Outcome::Expired => "expired",
        Outcome::Ignored => inner.haip_state,
    };
    drop(inner);
    if matches!(outcome, Outcome::Ready | Outcome::Denied | Outcome::Expired) {
        let _ = app.emit("identity-issuance-updated", ());
    }
    true
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use super::*;
    fn pending() -> (Pending, String) {
        let key = |n| HolderKey::Memory(p256::ecdsa::SigningKey::from_slice(&[n; 32]).unwrap());
        let mut session = Session::from_keys(
            "native",
            CALLBACK,
            "linked_document",
            key(1),
            key(2),
            key(3),
        )
        .unwrap();
        let at = now().unwrap();
        let state = session.protocol.par_parameters(at).unwrap()["state"]
            .as_str()
            .unwrap()
            .to_owned();
        session.protocol.accept_par(&json!({"request_uri":format!("urn:ietf:params:oauth:request_uri:{}","a".repeat(43)),"expires_in":90}),at).unwrap();
        (
            Pending {
                session,
                attestation: Zeroizing::new(String::new()),
                generation: 7,
                ready: false,
                context: None,
                configuration: "linked_document".into(),
                browser_until: at + 90,
                as_nonce: None,
            },
            state,
        )
    }
    fn uri(state: &str) -> url::Url {
        let mut uri = url::Url::parse(CALLBACK).unwrap();
        uri.query_pairs_mut()
            .append_pair("state", state)
            .append_pair("iss", ISSUER)
            .append_pair("code", &"c".repeat(43));
        uri
    }
    #[test]
    fn callback_is_native_bound_one_use_and_cancellation_discards_it() {
        let (mut p, state) = pending();
        let at = now().unwrap();
        assert_eq!(accept(&mut p, 7, &uri("wrong"), at), Outcome::Ignored);
        assert_eq!(accept(&mut p, 7, &uri(&state), at), Outcome::Ready);
        assert!(p.session.protocol.token_parameters(at).is_ok());
        assert_eq!(accept(&mut p, 7, &uri(&state), at), Outcome::Ignored);
        let (mut p, state) = pending();
        assert_eq!(accept(&mut p, 8, &uri(&state), at), Outcome::Expired);
        let (mut p, state) = pending();
        let mut denied = url::Url::parse(CALLBACK).unwrap();
        denied
            .query_pairs_mut()
            .append_pair("state", &state)
            .append_pair("iss", ISSUER)
            .append_pair("error", "access_denied");
        assert_eq!(accept(&mut p, 7, &denied, at), Outcome::Denied);
        assert!(p.session.protocol.token_parameters(at).is_err());
    }
    #[test]
    fn dedicated_path_does_not_intercept_login_or_other_hosts() {
        for value in [
            "https://app.mikaki.org/oidc/native/callback",
            "https://evil.example/identity/issuance/callback",
            "https://user@app.mikaki.org/identity/issuance/callback",
            "http://app.mikaki.org/identity/issuance/callback",
            "https://app.mikaki.org:444/identity/issuance/callback",
            "https://app.mikaki.org/identity/issuance/callback/extra",
        ] {
            assert!(!owns(&url::Url::parse(value).unwrap()));
        }
        assert!(owns(&uri("test")));
        let (mut p, state) = pending();
        let mut duplicate = uri(&state);
        duplicate.query_pairs_mut().append_pair("state", &state);
        assert_eq!(
            accept(&mut p, 7, &duplicate, now().unwrap()),
            Outcome::Ignored
        );
        let mut fragment = uri(&state);
        fragment.set_fragment(Some("code=other"));
        assert_eq!(
            accept(&mut p, 7, &fragment, now().unwrap()),
            Outcome::Ignored
        );
        assert_eq!(
            accept(&mut p, 7, &uri(&state), now().unwrap()),
            Outcome::Ready
        );
    }
}
