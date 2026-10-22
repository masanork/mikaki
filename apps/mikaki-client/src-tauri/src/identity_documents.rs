//! Local read summaries, separate from issuer-signed presentation credentials.
//! The WebView can save only a recent native read, never supply document attributes.
use crate::identity_card::{CardPreview, DocumentType};
use crate::identity_passport::PassportData;
#[cfg(target_os = "android")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::{engine::general_purpose::STANDARD as PassportB64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager};
#[cfg(target_os = "android")]
use tauri_plugin_native_dpop::NativeDpopExt;
use zeroize::Zeroize;
#[cfg(target_os = "android")]
use zeroize::Zeroizing;

#[derive(Default)]
pub struct DocumentState(Mutex<Option<Pending>>);
struct Pending {
    owner: String,
    preview: CardPreview,
    passport: Option<PassportData>,
    read_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    id: String,
    saved_at: u64,
    preview: CardPreview,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    passport: Option<PassportData>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Collection {
    version: u8,
    owner: String,
    documents: Vec<Document>,
}
#[derive(Serialize)]
pub struct Inventory {
    documents: Vec<DocumentSummary>,
    storage: &'static str,
}
#[derive(Serialize)]
pub struct DocumentSummary {
    id: String,
    saved_at: u64,
    preview: CardPreview,
    passport_saved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    passport_authentication: Option<crate::identity_passport::AuthenticationReport>,
}
impl From<Document> for DocumentSummary {
    fn from(document: Document) -> Self {
        let passport_authentication = document.passport.as_ref().map(|p| p.authentication());
        Self {
            id: document.id,
            saved_at: document.saved_at,
            preview: document.preview,
            passport_saved: document.passport.is_some(),
            passport_authentication,
        }
    }
}
#[derive(Serialize)]
pub struct PassportDetails {
    document_number: String,
    mrz: String,
    birth_date: String,
    expiry_date: String,
}
impl Drop for PassportDetails {
    fn drop(&mut self) {
        self.document_number.zeroize();
        self.mrz.zeroize();
        self.birth_date.zeroize();
        self.expiry_date.zeroize();
    }
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "document_unavailable".into())
}
pub fn owner(app: &AppHandle) -> Result<String, String> {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let session = crate::mobile_oidc::native_session(app.state())?;
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let session = crate::native_oidc::native_session(app.state())?;
    let subject = session.ok_or("document_login_required")?.subject;
    // Domain separation also binds the collection to the configured issuer.
    Ok(Sha256::digest(format!(
        "mikaki.documents.v1\0{}\0{subject}",
        mikaki_identity::wallet_profile::ISSUER
    ))
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect())
}
fn id(kind: DocumentType) -> &'static str {
    match kind {
        DocumentType::MyNumberCard => "my_number_card",
        DocumentType::DrivingLicense => "driving_license",
        DocumentType::Passport => "passport",
    }
}
fn validate(collection: &Collection, owner: &str) -> Result<(), String> {
    if collection.version != 1 || collection.owner != owner || collection.documents.len() > 3 {
        return Err("document_storage_invalid".into());
    }
    let mut ids = std::collections::HashSet::new();
    for d in &collection.documents {
        if d.id != id(d.preview.document_type)
            || !ids.insert(&d.id)
            || d.preview.verification != "unverified"
            || (d.preview.document_type == DocumentType::Passport && d.preview.backend_verifiable)
            || d.passport.as_ref().is_some_and(|p| !p.matches(&d.preview))
            || d.preview.name.is_empty()
            || [
                &d.preview.name,
                &d.preview.address,
                &d.preview.birth_date,
                &d.preview.gender,
            ]
            .iter()
            .any(|v| v.len() > 4096)
            || d.preview.expiry_date.as_ref().is_some_and(|v| v.len() > 32)
        {
            return Err("document_storage_invalid".into());
        }
    }
    Ok(())
}
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn retain(
    app: &AppHandle,
    expected_owner: &str,
    preview: CardPreview,
    passport: Option<PassportData>,
    cancelled: &AtomicBool,
) -> Result<(), String> {
    if owner(app)? != expected_owner {
        return Err("document_login_required".into());
    }
    let state = app.state::<DocumentState>();
    let mut pending = state.0.lock().map_err(|_| "document_unavailable")?;
    if cancelled.load(Ordering::SeqCst) {
        return Err("cancelled".into());
    }
    *pending = Some(Pending {
        owner: expected_owner.into(),
        preview,
        passport,
        read_at: now()?,
    });
    Ok(())
}
pub fn clear_pending(app: &AppHandle) -> Result<(), String> {
    *app.state::<DocumentState>()
        .0
        .lock()
        .map_err(|_| "document_unavailable")? = None;
    Ok(())
}
fn load(app: &AppHandle, owner: &str) -> Result<Collection, String> {
    #[cfg(target_os = "android")]
    if let Some(payload) = app.native_dpop().load_documents(owner)? {
        let payload = Zeroizing::new(payload);
        if payload.len() > 32768 {
            return Err("document_storage_invalid".into());
        }
        let plain = Zeroizing::new(
            B64.decode(&*payload)
                .map_err(|_| "document_storage_invalid")?,
        );
        let collection: Collection =
            serde_json::from_slice(&plain).map_err(|_| "document_storage_invalid")?;
        validate(&collection, owner)?;
        return Ok(collection);
    }
    #[cfg(not(target_os = "android"))]
    let _ = app;
    Ok(Collection {
        version: 1,
        owner: owner.into(),
        documents: vec![],
    })
}
fn save(app: &AppHandle, collection: &Collection) -> Result<(), String> {
    validate(collection, &collection.owner)?;
    #[cfg(target_os = "android")]
    {
        let plain =
            Zeroizing::new(serde_json::to_vec(collection).map_err(|_| "document_storage_invalid")?);
        let encoded = Zeroizing::new(B64.encode(&*plain));
        app.native_dpop()
            .store_documents(&collection.owner, &encoded)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        Err("document_storage_unsupported".into())
    }
}
#[tauri::command]
pub fn identity_document_inventory(app: AppHandle) -> Result<Inventory, String> {
    let state = app.state::<DocumentState>();
    let _guard = state.0.lock().map_err(|_| "document_unavailable")?;
    let current = owner(&app)?;
    let collection = load(&app, &current)?;
    Ok(Inventory {
        documents: collection
            .documents
            .into_iter()
            .map(DocumentSummary::from)
            .collect(),
        storage: if cfg!(target_os = "android") {
            "device_encrypted"
        } else {
            "unsupported"
        },
    })
}
/// Private native evidence lookup; raw DG1/SOD never enters the WebView.
pub(crate) fn saved_passport_evidence(
    app: &AppHandle,
) -> Result<mikaki_identity::passport::Evidence, String> {
    let current = owner(app)?;
    let record = load(app, &current)?
        .documents
        .into_iter()
        .find(|d| d.id == "passport")
        .ok_or("passport_save_required")?;
    let passport = record.passport.ok_or("passport_save_required")?;
    let sod = PassportB64
        .decode(passport.sod.as_ref().ok_or("passport_signature_required")?)
        .map_err(|_| "passport_signature_required")?;
    let mut dg1 = vec![0x61, 91, 0x5f, 0x1f, 88];
    dg1.extend_from_slice(passport.mrz.as_bytes());
    mikaki_identity::passport::Evidence::from_bytes(dg1, sod).map_err(str::to_string)
}

/// Explicit detail/prefill request, bound to the currently authenticated account.
#[tauri::command]
pub fn identity_passport_details(app: AppHandle) -> Result<PassportDetails, String> {
    let state = app.state::<DocumentState>();
    let _guard = state.0.lock().map_err(|_| "document_unavailable")?;
    let current = owner(&app)?;
    passport_details(load(&app, &current)?)
}
fn passport_details(collection: Collection) -> Result<PassportDetails, String> {
    let document = collection
        .documents
        .into_iter()
        .find(|d| d.id == "passport")
        .ok_or("passport_details_unavailable")?;
    let passport = document.passport.ok_or("passport_details_unavailable")?;
    Ok(PassportDetails {
        document_number: passport.document_number.clone(),
        mrz: passport.mrz.clone(),
        birth_date: document.preview.birth_date.clone(),
        expiry_date: document
            .preview
            .expiry_date
            .clone()
            .ok_or("passport_details_unavailable")?,
    })
}
fn from_pending(read: &Pending, current: &str, at: u64) -> Result<Document, String> {
    if read.owner != current || at < read.read_at || at.saturating_sub(read.read_at) > 300 {
        return Err("read_required".into());
    }
    Ok(Document {
        id: id(read.preview.document_type).into(),
        saved_at: at,
        preview: read.preview.clone(),
        passport: read.passport.clone(),
    })
}

#[tauri::command]
pub fn save_identity_document(app: AppHandle) -> Result<(), String> {
    let current = owner(&app)?;
    let state = app.state::<DocumentState>();
    let mut pending = state.0.lock().map_err(|_| "document_unavailable")?;
    let read = pending.as_ref().ok_or("read_required")?;
    let document = match from_pending(read, &current, now()?) {
        Ok(document) => document,
        Err(error) => {
            *pending = None;
            return Err(error);
        }
    };
    let mut collection = load(&app, &current)?;
    collection.documents.retain(|d| d.id != document.id);
    collection.documents.push(document);
    save(&app, &collection)?;
    *pending = None;
    Ok(())
}
#[tauri::command]
pub fn remove_identity_document(app: AppHandle, document_id: String) -> Result<(), String> {
    let state = app.state::<DocumentState>();
    let _guard = state.0.lock().map_err(|_| "document_unavailable")?;
    let current = owner(&app)?;
    let mut collection = load(&app, &current)?;
    if !collection.documents.iter().any(|d| d.id == document_id) {
        return Err("document_not_found".into());
    }
    collection.documents.retain(|d| d.id != document_id);
    if collection.documents.is_empty() {
        #[cfg(target_os = "android")]
        app.native_dpop().delete_documents(&current)?;
        Ok(())
    } else {
        save(&app, &collection)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn passport_document() -> Document {
        Document {
            id: "passport".into(),
            saved_at: 1,
            preview: CardPreview {
                name: "ERIKSSON ANNA MARIA".into(),
                address: String::new(),
                birth_date: "1974-08-12".into(),
                gender: "2".into(),
                verification: "unverified".into(),
                document_type: DocumentType::Passport,
                expiry_date: Some("2012-04-15".into()),
                backend_verifiable: false,
            },
            passport: Some(PassportData {
                sod: None,
                document_number: "L898902C3".into(),
                mrz: concat!(
                    "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
                    "L898902C36UTO7408122F1204159ZE184226B<<<<<10"
                )
                .into(),
            }),
        }
    }
    #[test]
    fn passport_roundtrip_retains_only_document_data_and_inventory_omits_it() {
        let mut c = collection();
        let read = passport_document();
        let pending = Pending {
            owner: "owner-a".into(),
            preview: read.preview,
            passport: read.passport,
            read_at: 1000,
        };
        c.documents
            .push(from_pending(&pending, "owner-a", 1001).unwrap());
        assert!(validate(&c, "owner-a").is_ok());
        let encoded = serde_json::to_value(&c).unwrap();
        let p = &encoded["documents"][1]["passport"];
        assert_eq!(p.as_object().unwrap().len(), 2);
        assert_eq!(p["document_number"], "L898902C3");
        assert_eq!(p["mrz"].as_str().unwrap().len(), 88);
        let restored: Collection = serde_json::from_value(encoded.clone()).unwrap();
        assert!(validate(&restored, "owner-a").is_ok());
        assert!(validate(&restored, "owner-b").is_err());
        let details = serde_json::to_value(passport_details(restored).unwrap()).unwrap();
        assert_eq!(details["mrz"], p["mrz"]);
        assert_eq!(details["birth_date"], "1974-08-12");
        let summary = serde_json::to_value(DocumentSummary::from(passport_document())).unwrap();
        assert_eq!(summary["passport_saved"], true);
        assert!(summary.get("passport").is_none());
        assert!(!summary.to_string().contains("L898902C3"));
        // Raw SOD stays native even after an explicit MRZ detail request.
        let mut proof = passport_document();
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        proof.passport.as_mut().unwrap().sod = Some(B64.encode(include_bytes!(
            "../../../../crates/identity/src/passport/fixtures/rsa-sha256.sod"
        )));
        let details = passport_details(Collection {
            version: 1,
            owner: "owner-a".into(),
            documents: vec![proof],
        })
        .unwrap();
        assert!(serde_json::to_value(details).unwrap().get("sod").is_none());
        let mut injected = encoded;
        injected["documents"][1]["passport"]["session_key"] =
            serde_json::json!("not document data");
        assert!(serde_json::from_value::<Collection>(injected).is_err());
    }
    #[test]
    fn stored_passport_must_match_mrz_type_and_all_summary_attributes() {
        for variant in 0..6 {
            let mut d = passport_document();
            match variant {
                0 => d.passport.as_mut().unwrap().document_number = "WRONG".into(),
                1 => d.passport.as_mut().unwrap().mrz.replace_range(87.., "9"),
                2 => d.passport.as_mut().unwrap().mrz.push('A'),
                3 => {
                    d.preview.document_type = DocumentType::MyNumberCard;
                    d.id = "my_number_card".into();
                }
                4 => d.preview.name = "changed".into(),
                _ => d.preview.birth_date = "1974-08-13".into(),
            }
            let c = Collection {
                version: 1,
                owner: "owner-a".into(),
                documents: vec![d],
            };
            assert!(validate(&c, "owner-a").is_err(), "variant {variant}");
        }
        // Already-saved summaries without MRZ still restore; nothing is fabricated.
        let mut d = passport_document();
        d.passport = None;
        let c = Collection {
            version: 1,
            owner: "owner-a".into(),
            documents: vec![d],
        };
        assert!(validate(&c, "owner-a").is_ok());
        assert!(passport_details(c).is_err());
    }
    fn collection() -> Collection {
        Collection {
            version: 1,
            owner: "owner-a".into(),
            documents: vec![Document {
                id: "my_number_card".into(),
                saved_at: 1,
                passport: None,
                preview: CardPreview {
                    name: "試験 太郎".into(),
                    address: "東京都".into(),
                    birth_date: "1990-01-01".into(),
                    gender: "1".into(),
                    verification: "unverified".into(),
                    document_type: DocumentType::MyNumberCard,
                    expiry_date: None,
                    backend_verifiable: true,
                },
            }],
        }
    }
    #[test]
    fn three_distinct_types_restore_but_passport_cannot_claim_verification() {
        let mut c = collection();
        for kind in [DocumentType::DrivingLicense, DocumentType::Passport] {
            let mut d = c.documents[0].clone();
            d.id = id(kind).into();
            d.preview.document_type = kind;
            d.preview.backend_verifiable = false;
            c.documents.push(d);
        }
        assert!(validate(&c, "owner-a").is_ok());
        let encoded = serde_json::to_string(&c).unwrap();
        let restored: Collection = serde_json::from_str(&encoded).unwrap();
        assert!(validate(&restored, "owner-a").is_ok());
        c.documents[2].preview.backend_verifiable = true;
        assert!(validate(&c, "owner-a").is_err());
    }
    #[test]
    fn rejects_wrong_owner_forged_status_duplicate_and_mismatched_type() {
        let mut c = collection();
        assert!(validate(&c, "owner-a").is_ok());
        assert!(validate(&c, "owner-b").is_err());
        c.documents[0].preview.verification = "verified".into();
        assert!(validate(&c, "owner-a").is_err());
        let mut c = collection();
        c.documents.push(c.documents[0].clone());
        assert!(validate(&c, "owner-a").is_err());
        let mut c = collection();
        c.documents[0].preview.document_type = DocumentType::DrivingLicense;
        assert!(validate(&c, "owner-a").is_err());
    }
    #[test]
    fn save_requires_recent_native_read_from_the_same_account() {
        let read = Pending {
            owner: "owner-a".into(),
            preview: collection().documents[0].preview.clone(),
            read_at: 1000,
            passport: None,
        };
        assert!(from_pending(&read, "owner-a", 1300).is_ok());
        assert!(from_pending(&read, "owner-a", 1301).is_err());
        assert!(from_pending(&read, "owner-a", 999).is_err());
        assert!(from_pending(&read, "owner-b", 1001).is_err());
    }
    #[test]
    fn summary_contains_no_pin_evidence_or_presentation_credential() {
        let encoded = serde_json::to_value(collection()).unwrap();
        let fields = encoded["documents"][0].as_object().unwrap();
        assert_eq!(fields.len(), 3);
        assert_eq!(
            encoded["documents"][0]["preview"]["verification"],
            "unverified"
        );
        let mut c = collection();
        c.documents[0].preview.name = "x".repeat(4097);
        assert!(validate(&c, "owner-a").is_err());
    }
}
