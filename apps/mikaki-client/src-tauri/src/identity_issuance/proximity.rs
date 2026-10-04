//! QR-engaged Android BLE peripheral holder. Ciphertext stays on native transport.
use super::*;
#[derive(Serialize)]
pub struct Started {
    session_id: String,
    engagement: &'static str,
    qr_modules: Vec<Vec<bool>>,
    expires_at: u64,
}
#[derive(Serialize)]
pub struct Review {
    review_id: String,
    reader_name: String,
    values: Value,
    retained_fields: Vec<String>,
    expires_at: u64,
}
#[tauri::command]
pub async fn start_identity_proximity(
    app: AppHandle,
    state: State<'_, IdentityState>,
    engagement: Option<String>,
) -> Result<Started, String> {
    #[cfg(target_os = "android")]
    {
        android::start(app, state, engagement).await
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, state, engagement);
        Err("proximity_unsupported".into())
    }
}
#[tauri::command]
pub async fn review_identity_proximity(
    app: AppHandle,
    state: State<'_, IdentityState>,
    session_id: String,
) -> Result<Review, String> {
    #[cfg(target_os = "android")]
    {
        android::review(app, state, session_id).await
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, state, session_id);
        Err("proximity_unsupported".into())
    }
}
#[tauri::command]
pub async fn confirm_identity_proximity(
    app: AppHandle,
    state: State<'_, IdentityState>,
    session_id: String,
    review_id: String,
    approve: bool,
) -> Result<PresentationResult, String> {
    #[cfg(target_os = "android")]
    {
        android::confirm(app, state, session_id, review_id, approve).await
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, state, session_id, review_id, approve);
        Err("proximity_unsupported".into())
    }
}
#[tauri::command]
pub fn cancel_identity_proximity(
    app: AppHandle,
    state: State<'_, IdentityState>,
    session_id: Option<String>,
) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_identity_proximity::IdentityProximityExt;
        let (id, flow) = {
            let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
            if session_id.is_some() && s.proximity_id != session_id {
                return Ok(());
            }
            s.generation = s.generation.wrapping_add(1);
            (s.proximity_id.take(), s.proximity.take())
        };
        if let Some(id) = id {
            app.identity_proximity().close(&id);
        }
        drop(flow);
        Ok(())
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, state, session_id);
        Ok(())
    }
}
#[cfg(target_os = "android")]
pub(super) mod android {
    use super::*;
    use mikaki_identity::mdoc::proximity::{HolderSession, ReaderRegistration};
    use tauri_plugin_identity_proximity::IdentityProximityExt;
    pub struct Flow {
        app: AppHandle,
        pub id: String,
        session: HolderSession,
        credential_hash: String,
        created: Instant,
        expires_at: u64,
        review_id: Option<String>,
        negotiated: bool,
    }
    impl Drop for Flow {
        fn drop(&mut self) {
            self.app.identity_proximity().close(&self.id);
        }
    }
    fn registry() -> Result<Vec<ReaderRegistration>, String> {
        let readers: Vec<ReaderRegistration> =
            serde_json::from_str(option_env!("MIKAKI_MDOC_READERS").unwrap_or("[]"))
                .map_err(|_| "reader_configuration_invalid")?;
        if readers.is_empty() || readers.len() > 32 {
            return Err("reader_not_configured".into());
        }
        let mut keys = std::collections::HashSet::new();
        for r in &readers {
            r.jwk.verifying_key().map_err(str::to_string)?;
            if let Some(policy) = &r.certificate_trust {
                policy
                    .validate()
                    .map_err(|_| "reader_configuration_invalid")?;
            }
            if r.name.is_empty()
                || r.name.len() > 160
                || !keys.insert(
                    serde_json::to_string(&r.jwk).map_err(|_| "reader_configuration_invalid")?,
                )
            {
                return Err("reader_configuration_invalid".into());
            }
        }
        Ok(readers)
    }
    fn live(flow: &Flow) -> Result<(), String> {
        if flow.created.elapsed() >= Duration::from_secs(120) || now()? >= flow.expires_at {
            Err("proximity_expired".into())
        } else {
            Ok(())
        }
    }
    pub async fn start(
        app: AppHandle,
        state: State<'_, IdentityState>,
        engagement: Option<String>,
    ) -> Result<Started, String> {
        let profile = engagement.as_deref().unwrap_or("qr");
        let nfc_data = matches!(profile, "qr_nfc" | "nfc_negotiated_data");
        let negotiated = matches!(profile, "nfc_negotiated" | "nfc_negotiated_data");
        let nfc = match profile {
            "qr" | "qr_nfc" => false,
            "nfc" | "nfc_negotiated" | "nfc_negotiated_data" => true,
            _ => return Err("unsupported_engagement".into()),
        };
        let guard = gate(&state)?;
        registry()?;
        let (hash, exp) = {
            let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
            s.proximity = None;
            if let Some(id) = s.proximity_id.take() {
                app.identity_proximity().close(&id)
            }
            s.restore_receipts(&app)?;
            let receipt = s
                .receipts
                .iter()
                .rev()
                .find(|r| r.format == "mso_mdoc" && r.expires_at > now().unwrap_or(u64::MAX))
                .ok_or("credential_required")?;
            receipt.validate(ISSUER, now()?)?;
            if receipt.format != "mso_mdoc" {
                return Err("mdoc_required".into());
            }
            (credential_hash(&receipt.credential), receipt.expires_at)
        };
        let mut uuid = [0; 16];
        OsRng.fill_bytes(&mut uuid);
        uuid[6] = (uuid[6] & 15) | 64;
        uuid[8] = (uuid[8] & 63) | 128;
        let hex = uuid.iter().map(|v| format!("{v:02x}")).collect::<String>();
        let service = format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        );
        let mut sid = [0; 16];
        OsRng.fill_bytes(&mut sid);
        let id = sid.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let ephemeral = p256::SecretKey::random(&mut OsRng);
        let session = if nfc_data && negotiated {
            HolderSession::new_nfc_negotiated_data(ephemeral)
        } else if nfc_data {
            HolderSession::new_nfc_data(ephemeral)
        } else if negotiated {
            HolderSession::new_nfc_negotiated(ephemeral, uuid)
        } else if nfc {
            HolderSession::new_nfc(ephemeral, uuid)
        } else {
            HolderSession::new(ephemeral, uuid)
        }
        .map_err(str::to_string)?;
        let qr = qrcode::QrCode::with_error_correction_level(
            session.qr_uri().as_bytes(),
            qrcode::EcLevel::M,
        )
        .map_err(|_| "qr_unavailable")?;
        let width = qr.width();
        let modules = (0..width)
            .map(|y| {
                (0..width)
                    .map(|x| qr[(x, y)] == qrcode::Color::Dark)
                    .collect()
            })
            .collect();
        let flow = Flow {
            app: app.clone(),
            id: id.clone(),
            session,
            credential_hash: hash,
            created: Instant::now(),
            expires_at: exp.min(now()?.saturating_add(120)),
            review_id: None,
            negotiated,
        };
        {
            let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
            if s.generation != guard.generation {
                return Err("cancelled".into());
            }
            s.proximity_id = Some(id.clone());
        }
        app.identity_proximity().start(
            &id,
            &service,
            if negotiated {
                None
            } else {
                flow.session.handover_select()
            },
            nfc_data,
            negotiated,
        )?;
        let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
        if s.generation != guard.generation {
            return Err("cancelled".into());
        }
        let expires_at = flow.expires_at;
        s.proximity = Some(flow);
        drop(s);
        watch_closed(app.clone(), id.clone());
        Ok(Started {
            session_id: id,
            engagement: if nfc_data && negotiated {
                "nfc_negotiated_data"
            } else if nfc_data {
                "qr_nfc"
            } else if negotiated {
                "nfc_negotiated"
            } else if nfc {
                "nfc"
            } else {
                "qr"
            },
            qr_modules: if nfc { Vec::new() } else { modules },
            expires_at,
        })
    }
    fn watch_closed(app: AppHandle, id: String) {
        tauri::async_runtime::spawn(async move {
            let _ = app.identity_proximity().wait_closed(&id).await;
            let state = app.state::<IdentityState>();
            let flow = {
                let Ok(mut s) = state.0.lock() else { return };
                if s.proximity_id.as_deref() != Some(&id) {
                    return;
                }
                s.generation = s.generation.wrapping_add(1);
                s.proximity_id = None;
                s.proximity.take()
            };
            // Flow's Drop closes the Java transport; never call it with the state mutex held.
            drop(flow);
            use tauri::Emitter;
            let _ = app.emit("identity-proximity-ended", &id);
        });
    }
    pub async fn review(
        app: AppHandle,
        state: State<'_, IdentityState>,
        id: String,
    ) -> Result<Review, String> {
        let guard = gate(&state)?;
        let mut flow = {
            let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
            if s.proximity_id.as_deref() != Some(&id) {
                return Err("session_unavailable".into());
            }
            s.proximity.take().ok_or("session_unavailable")?
        };
        live(&flow)?;
        if flow.negotiated {
            let hr = app.identity_proximity().receive_handover(&id)?;
            live(&flow)?;
            let hs = flow
                .session
                .negotiate(&hr)
                .map_err(str::to_string)?
                .to_vec();
            {
                let s = state.0.lock().map_err(|_| "identity_unavailable")?;
                if s.generation != guard.generation || s.proximity_id.as_deref() != Some(&id) {
                    return Err("cancelled".into());
                }
            }
            app.identity_proximity().publish_handover(&id, &hs)?;
        }
        let packet = app.identity_proximity().receive(&id)?;
        let request = flow
            .session
            .establish(&packet, &registry()?, now()?)
            .map_err(str::to_string)?
            .clone();
        flow.expires_at = flow.expires_at.min(request.expires_at);
        live(&flow)?;
        let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
        if s.generation != guard.generation || s.proximity_id.as_deref() != Some(&id) {
            return Err("cancelled".into());
        }
        let receipt = s
            .receipts
            .iter()
            .find(|r| credential_hash(&r.credential) == flow.credential_hash)
            .ok_or("credential_changed")?;
        if credential_hash(&receipt.credential) != flow.credential_hash {
            return Err("credential_changed".into());
        }
        let validated = mdoc::verify_receipt(
            &receipt.credential,
            &receipt.issuer_key,
            &receipt.key.public()?,
            now()?,
        )
        .map_err(str::to_string)?;
        let values = mdoc::selected_values(&validated, &request.fields).map_err(str::to_string)?;
        let review_id = random();
        flow.review_id = Some(review_id.clone());
        let expires_at = flow.expires_at;
        s.proximity = Some(flow);
        Ok(Review {
            review_id,
            reader_name: request.reader_name,
            values,
            retained_fields: request.retained_fields,
            expires_at,
        })
    }
    pub async fn confirm(
        app: AppHandle,
        state: State<'_, IdentityState>,
        id: String,
        review_id: String,
        approve: bool,
    ) -> Result<PresentationResult, String> {
        let guard = gate(&state)?;
        let (mut flow, credential, key, issuer) = {
            let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
            if s.proximity_id.as_deref() != Some(&id)
                || s.proximity.as_ref().and_then(|f| f.review_id.as_deref()) != Some(&review_id)
            {
                return Err("review_required".into());
            }
            let flow = s.proximity.take().ok_or("review_required")?;
            if !approve {
                s.proximity_id = None;
                return Ok(PresentationResult { state: "denied" });
            }
            let receipt = s
                .receipts
                .iter()
                .find(|r| credential_hash(&r.credential) == flow.credential_hash)
                .ok_or("credential_changed")?;
            if credential_hash(&receipt.credential) != flow.credential_hash {
                return Err("credential_changed".into());
            }
            receipt.validate(ISSUER, now()?)?;
            (
                flow,
                Zeroizing::new(receipt.credential.to_string()),
                receipt.key.clone(),
                receipt.issuer_key.clone(),
            )
        };
        live(&flow)?;
        let holder = key.public()?;
        let validated =
            mdoc::verify_receipt(&credential, &issuer, &holder, now()?).map_err(str::to_string)?;
        let transcript = flow.session.transcript().map_err(str::to_string)?.to_vec();
        let fields = flow
            .session
            .request()
            .map_err(str::to_string)?
            .fields
            .clone();
        let authentication = mdoc::device_authentication(&transcript).map_err(str::to_string)?;
        let sig =
            key.sign_bytes(&mdoc::signature_input(&authentication).map_err(str::to_string)?)?;
        let response = Zeroizing::new(
            mdoc::device_response(&validated, &fields, &transcript, &sig, &holder)
                .map_err(str::to_string)?,
        );
        use base64::Engine;
        let response = Zeroizing::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&*response)
                .map_err(|_| "invalid_mdoc")?,
        );
        let packet = flow
            .session
            .seal_response_at(&response, now()?)
            .map_err(str::to_string)?;
        {
            let s = state.0.lock().map_err(|_| "identity_unavailable")?;
            if s.generation != guard.generation {
                return Err("cancelled".into());
            }
        }
        live(&flow)?;
        // Bound the Android transfer by both the approved wall-clock deadline and
        // the original session's remaining monotonic lifetime.
        let remaining = Duration::from_secs(120)
            .saturating_sub(flow.created.elapsed())
            .as_secs();
        let expires_at = flow.expires_at.min(now()?.saturating_add(remaining));
        app.identity_proximity().send(&id, &packet, expires_at)?;
        let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
        if s.proximity_id.as_deref() == Some(&id) {
            s.proximity_id = None;
        }
        Ok(PresentationResult { state: "presented" })
    }
}
