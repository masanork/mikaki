//! App-facing operations; the lower-level NFC plugin has no WebView commands.
use crate::identity_card::{CardFailure, CardPreview, FailureCode};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

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
) -> Result<CardPreview, CardFailure> {
    let pin = Zeroizing::new(pin);
    let pin2 = pin2.map(Zeroizing::new);
    if let Some(pin2) = &pin2 {
        crate::identity_card::validate_pin(pin2)?;
    }
    let kind = document_type.unwrap_or_default();
    crate::identity_card::validate_pin(&pin)?;
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, state, pin, pin2, kind);
        Err(FailureCode::UnsupportedPlatform.into())
    }
    #[cfg(target_os = "android")]
    {
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
            cleanup
                .app
                .identity_reader()
                .open(&cleanup.session.id)
                .map_err(transport_failure)?;
            let mut transport = NfcTransport {
                app: &cleanup.app,
                session: &cleanup.session,
            };
            let (preview, evidence) = crate::identity_card::read_document(
                &mut transport,
                kind,
                &pin,
                pin2.as_deref().map(|p| p.as_str()),
            )?;
            if cleanup.session.cancelled.load(Ordering::SeqCst) {
                return Err(FailureCode::Cancelled.into());
            }
            crate::identity_issuance::retain_evidence(
                &cleanup.app,
                evidence,
                &cleanup.session.cancelled,
            )?;
            if cleanup.session.cancelled.load(Ordering::SeqCst) {
                let _ = crate::identity_issuance::clear_identity_evidence(
                    cleanup
                        .app
                        .state::<crate::identity_issuance::IdentityState>(),
                );
                return Err(FailureCode::Cancelled.into());
            }
            Ok(preview)
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
