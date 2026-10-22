//! App-facing operations; the lower-level NFC plugin has no WebView commands.
use crate::identity_card::{CardFailure, CardPreview, FailureCode};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;
#[derive(serde::Serialize)]
pub struct ReadPreview {
    #[serde(flatten)]
    preview: CardPreview,
    #[serde(skip_serializing_if = "Option::is_none")]
    passport_authentication: Option<crate::identity_passport::AuthenticationReport>,
}

struct Session {
    #[cfg(target_os = "android")]
    id: String,
    cancelled: AtomicBool,
}
#[derive(Default)]
pub struct ReadState(Mutex<Option<Arc<Session>>>);

/// Mark cancellation before credential erasure acquires the identity-state lock.
/// A late read must check this flag while committing evidence under that lock.
pub fn cancel_active_read(app: &AppHandle) -> Result<(), String> {
    let active = app
        .state::<ReadState>()
        .0
        .lock()
        .map_err(|_| "identity_unavailable")?
        .clone();
    if let Some(session) = active {
        session.cancelled.store(true, Ordering::SeqCst);
        #[cfg(target_os = "android")]
        {
            let app = app.clone();
            tauri::async_runtime::spawn_blocking(move || {
                use tauri_plugin_identity_reader::IdentityReaderExt;
                app.identity_reader().close(&session.id);
            });
        }
    }
    crate::identity_documents::clear_pending(app)?;
    Ok(())
}

#[tauri::command]
pub fn identity_reader_supported() -> bool {
    cfg!(target_os = "android")
}

#[tauri::command]
pub async fn read_identity_card(
    app: AppHandle,
    state: State<'_, ReadState>,
    pin: String,
    document_type: Option<mikaki_identity::card::DocumentType>,
    pin2: Option<String>,
) -> Result<ReadPreview, CardFailure> {
    let pin = Zeroizing::new(pin);
    let pin2 = pin2.map(Zeroizing::new);
    if let Some(pin2) = &pin2 {
        crate::identity_card::validate_pin(pin2)?;
    }
    let kind = document_type.unwrap_or_default();
    crate::identity_card::validate_pin(&pin)?;
    if kind == mikaki_identity::card::DocumentType::Passport {
        return Err(FailureCode::UnsupportedCard.into());
    }
    read_native(app, state, ReadRequest::Card { kind, pin, pin2 }).await
}

#[tauri::command]
pub async fn read_identity_passport(
    app: AppHandle,
    state: State<'_, ReadState>,
    document_number: String,
    birth_date: String,
    expiry_date: String,
) -> Result<ReadPreview, CardFailure> {
    let access = crate::identity_passport::Access::new(document_number, birth_date, expiry_date)?;
    read_native(app, state, ReadRequest::Passport(access)).await
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
enum ReadRequest {
    Card {
        kind: mikaki_identity::card::DocumentType,
        pin: Zeroizing<String>,
        pin2: Option<Zeroizing<String>>,
    },
    Passport(crate::identity_passport::Access),
}
async fn read_native(
    app: AppHandle,
    state: State<'_, ReadState>,
    request: ReadRequest,
) -> Result<ReadPreview, CardFailure> {
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, state, request);
        Err(FailureCode::UnsupportedPlatform.into())
    }
    #[cfg(target_os = "android")]
    {
        let document_owner = crate::identity_documents::owner(&app)
            .map_err(|_| CardFailure::from(FailureCode::AccessDenied))?;
        use getrandom::SysRng;
        use rand_core::TryRng;
        use tauri::Manager;
        let session = {
            let mut active = state
                .0
                .lock()
                .map_err(|_| CardFailure::from(FailureCode::TransportError))?;
            if active.is_some() {
                return Err(FailureCode::ReaderBusy.into());
            }
            let mut random = [0u8; 16];
            SysRng
                .try_fill_bytes(&mut random)
                .map_err(|_| CardFailure::from(FailureCode::TransportError))?;
            let session = Arc::new(Session {
                id: random.iter().map(|b| format!("{b:02x}")).collect(),
                cancelled: AtomicBool::new(false),
            });
            *active = Some(session.clone());
            session
        };
        // Blocking mobile-plugin calls must not occupy the UI/event loop.
        tauri::async_runtime::spawn_blocking(move || {
            use tauri_plugin_identity_reader::IdentityReaderExt;
            struct Cleanup {
                app: AppHandle,
                session: Arc<Session>,
            }
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    self.app.identity_reader().close(&self.session.id);
                    if let Ok(mut active) = self.app.state::<ReadState>().0.lock() {
                        if active
                            .as_ref()
                            .is_some_and(|s| Arc::ptr_eq(s, &self.session))
                        {
                            *active = None;
                        }
                    }
                }
            }
            let cleanup = Cleanup { app, session };
            if cleanup.session.cancelled.load(Ordering::SeqCst) {
                return Err(FailureCode::Cancelled.into());
            }
            // A failed/new passport read must never leave an older card's link evidence.
            crate::identity_issuance::clear_identity_evidence(
                cleanup.app.clone(),
                cleanup.app.state(),
            )
            .map_err(|_| CardFailure::from(FailureCode::TransportError))?;
            cleanup
                .app
                .identity_reader()
                .open(&cleanup.session.id)
                .map_err(transport_failure)?;
            let mut transport = NfcTransport {
                app: &cleanup.app,
                session: &cleanup.session,
            };
            let (preview, evidence, passport) = match request {
                ReadRequest::Card { kind, pin, pin2 } => {
                    let (preview, evidence) = crate::identity_card::read_document(
                        &mut transport,
                        kind,
                        &pin,
                        pin2.as_deref().map(|p| p.as_str()),
                    )?;
                    (preview, Some(evidence), None)
                }
                ReadRequest::Passport(access) => {
                    let read = crate::identity_passport::read(&mut transport, &access)?;
                    (read.preview, None, Some(read.passport))
                }
            };
            if cleanup.session.cancelled.load(Ordering::SeqCst) {
                return Err(FailureCode::Cancelled.into());
            }
            if let Some(evidence) = evidence {
                crate::identity_issuance::retain_evidence(
                    &cleanup.app,
                    evidence,
                    &cleanup.session.cancelled,
                )?;
            }
            if cleanup.session.cancelled.load(Ordering::SeqCst) {
                let _ = crate::identity_issuance::clear_identity_evidence(
                    cleanup.app.clone(),
                    cleanup
                        .app
                        .state::<crate::identity_issuance::IdentityState>(),
                );
                return Err(FailureCode::Cancelled.into());
            }
            let passport_authentication = passport.as_ref().map(|p| p.authentication());
            crate::identity_documents::retain(
                &cleanup.app,
                &document_owner,
                preview.clone(),
                passport,
                &cleanup.session.cancelled,
            )
            .map_err(|_| CardFailure::from(FailureCode::Cancelled))?;
            Ok(ReadPreview {
                preview,
                passport_authentication,
            })
        })
        .await
        .map_err(|_| CardFailure::from(FailureCode::TransportError))?
    }
}

#[tauri::command]
pub async fn cancel_identity_card(
    app: AppHandle,
    state: State<'_, ReadState>,
) -> Result<(), CardFailure> {
    let active = state
        .0
        .lock()
        .map_err(|_| CardFailure::from(FailureCode::TransportError))?
        .clone();
    if let Some(session) = &active {
        session.cancelled.store(true, Ordering::SeqCst);
    }
    crate::identity_issuance::clear_identity_evidence(
        app.clone(),
        app.state::<crate::identity_issuance::IdentityState>(),
    )
    .map_err(|_| CardFailure::from(FailureCode::TransportError))?;
    #[cfg(target_os = "android")]
    if let Some(session) = active {
        tauri::async_runtime::spawn_blocking(move || {
            use tauri_plugin_identity_reader::IdentityReaderExt;
            app.identity_reader().close(&session.id);
        })
        .await
        .map_err(|_| CardFailure::from(FailureCode::TransportError))?;
    }
    #[cfg(not(target_os = "android"))]
    let _ = (app, active);
    Ok(())
}

#[cfg(target_os = "android")]
struct NfcTransport<'a> {
    app: &'a AppHandle,
    session: &'a Session,
}
#[cfg(target_os = "android")]
impl crate::identity_card::CardTransport for NfcTransport<'_> {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, CardFailure> {
        use tauri_plugin_identity_reader::IdentityReaderExt;
        if self.session.cancelled.load(Ordering::SeqCst) {
            return Err(FailureCode::Cancelled.into());
        }
        self.app
            .identity_reader()
            .transmit(&self.session.id, apdu)
            .map_err(transport_failure)
    }
}

#[cfg(any(target_os = "android", test))]
fn transport_failure(error: String) -> CardFailure {
    // Plugin error formatting varies; reflect only a closed set of known codes.
    for (word, code) in [
        ("reader_busy", FailureCode::ReaderBusy),
        ("nfc_unavailable", FailureCode::NfcUnavailable),
        ("nfc_disabled", FailureCode::NfcDisabled),
        ("read_timeout", FailureCode::ReadTimeout),
        ("cancelled", FailureCode::Cancelled),
        ("card_removed", FailureCode::CardRemoved),
        ("unsupported_card", FailureCode::UnsupportedCard),
        ("invalid_response", FailureCode::InvalidResponse),
    ] {
        if error.contains(word) {
            return code.into();
        }
    }
    FailureCode::TransportError.into()
}

#[cfg(test)]
mod tests {
    #[test]
    fn unknown_native_errors_do_not_disclose_details() {
        let failure = super::transport_failure("private attribute or native exception".into());
        assert_eq!(
            serde_json::to_string(&failure).unwrap(),
            r#"{"code":"transport_error"}"#
        );
    }
}
