//! UI notifications use a fixed native allowlist, never the plugin's raw app-link bus.
use std::sync::Mutex;
use tauri::{ipc::Channel, AppHandle, EventId, Listener, State, WebviewWindow};

#[derive(Default)]
pub struct IdentityEvents(Mutex<Vec<EventId>>);

#[derive(serde::Serialize)]
pub struct Notification {
    event: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}
fn notification(event: &'static str, payload: &str) -> Option<Notification> {
    match event {
        "identity-presentation-ready" | "identity-issuance-updated" => {
            Some(Notification { event, id: None })
        }
        "identity-proximity-ended" => {
            let id = serde_json::from_str::<String>(payload).ok()?;
            if id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            {
                return None;
            }
            Some(Notification {
                event,
                id: Some(id),
            })
        }
        _ => None,
    }
}
#[tauri::command]
pub fn subscribe_identity_updates(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, IdentityEvents>,
    on_event: Channel<Notification>,
) -> Result<(), String> {
    if window.label() != "main" {
        return Err("identity_unavailable".into());
    }
    let mut ids = state.0.lock().map_err(|_| "identity_unavailable")?;
    // Replace the previous page's subscription rather than accumulating listeners on reload.
    for id in ids.drain(..) {
        app.unlisten(id);
    }
    for name in [
        "identity-presentation-ready",
        "identity-proximity-ended",
        "identity-issuance-updated",
    ] {
        let channel = on_event.clone();
        ids.push(app.listen(name, move |event| {
            if let Some(value) = notification(name, event.payload()) {
                let _ = channel.send(value);
            }
        }));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_callback_events_and_payloads_cannot_cross_notification_channel() {
        assert!(
            notification("deep-link://new-url", r#"["https://example/?code=secret"]"#).is_none()
        );
        let value = notification(
            "identity-issuance-updated",
            r#"{"code":"secret","state":"secret"}"#,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(value).unwrap(),
            serde_json::json!({"event":"identity-issuance-updated"})
        );
        assert!(notification(
            "identity-proximity-ended",
            r#""https://example/?code=secret""#
        )
        .is_none());
        assert_eq!(
            notification("identity-proximity-ended", r#""opaque-session""#)
                .unwrap()
                .id
                .as_deref(),
            Some("opaque-session")
        );
    }
}
