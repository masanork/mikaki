//! Bounded Final inventory selection. Native storage/consent integration is separate.
use super::*;
use crate::credential_receipt::CredentialTrust;
use zeroize::Zeroizing;

/// A receipt verified with its holder, issuer key and operator-provisioned roots.
/// No unverified format, expiry or claim list can enter selection.
pub struct VerifiedCredential {
    credential: Zeroizing<String>,
    format: String,
    issuer_key: PublicJwk,
    holder: PublicJwk,
    issuer: String,
    kid: String,
    trust: CredentialTrust,
    expires: u64,
}
impl VerifiedCredential {
    // Verify the receipt against independent holder, issuer and trust inputs before storage.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        credential: String,
        format: &str,
        issuer_key: PublicJwk,
        holder: PublicJwk,
        issuer: &str,
        kid: &str,
        trust: CredentialTrust,
        now: u64,
    ) -> Result<Self, String> {
        let credential = Zeroizing::new(credential);
        trust.validate(now)?;
        let expires = match format {
            "dc+sd-jwt" => {
                crate::issuance::verify_receipt(&credential, &issuer_key, kid, &holder, issuer, now)
                    .map_err(str::to_string)?["exp"]
                    .as_u64()
                    .ok_or("invalid_credential")?
            }
            "mso_mdoc" => {
                crate::mdoc::verify_receipt(&credential, &issuer_key, &holder, now)
                    .map_err(str::to_string)?
                    .expires_at
            }
            _ => return Err("invalid_credential".into()),
        };
        trust.verify(&credential, format, &issuer_key, now, expires)?;
        Ok(Self {
            credential,
            format: format.into(),
            issuer_key,
            holder,
            issuer: issuer.into(),
            kid: kid.into(),
            trust,
            expires,
        })
    }
    fn revalidate(&self, now: u64) -> Result<(), String> {
        if now >= self.expires {
            return Err("credential_expired".into());
        }
        match self.format.as_str() {
            "dc+sd-jwt" => {
                crate::issuance::verify_receipt(
                    &self.credential,
                    &self.issuer_key,
                    &self.kid,
                    &self.holder,
                    &self.issuer,
                    now,
                )
                .map_err(str::to_string)?;
            }
            _ => {
                crate::mdoc::verify_receipt(&self.credential, &self.issuer_key, &self.holder, now)
                    .map_err(str::to_string)?;
            }
        }
        self.trust.verify(
            &self.credential,
            &self.format,
            &self.issuer_key,
            now,
            self.expires,
        )
    }
    pub fn credential(&self) -> &str {
        &self.credential
    }
}

pub struct InventoryRequest {
    request: ApprovedRequest,
    vct: String,
}
impl InventoryRequest {
    pub fn client_id(&self) -> &str {
        self.request.client_id()
    }
    pub fn response_encryption(&self) -> Option<&encryption::ResponseEncryption> {
        self.request.response_encryption()
    }
    pub(super) fn type_feasible(&self) -> bool {
        dcql::select(&self.request.request.dcql_query, &self.vct).is_ok()
    }
    /// Preserve authenticated binding while compiling the existing one-receipt adapter.
    pub fn into_single(mut self) -> Result<ApprovedRequest, &'static str> {
        let indices = dcql::select(&self.request.request.dcql_query, &self.vct)?;
        let mut queries = Vec::new();
        for i in indices {
            let query = &self.request.request.dcql_query.credentials[i];
            if queries
                .first()
                .is_some_and(|q: &Query| q.format != query.format)
            {
                return Err("mixed_presentation_formats_unsupported");
            }
            let (fields, retained) = dcql::fields(query)?;
            for field in fields {
                if !self.request.fields.contains(&field) {
                    self.request.fields.push(field);
                }
            }
            for field in retained {
                if !self.request.retained_fields.contains(&field) {
                    self.request.retained_fields.push(field);
                }
            }
            queries.push(query.clone());
        }
        self.request.request.dcql_query = Dcql {
            credentials: queries,
            credential_sets: None,
        };
        Ok(self.request)
    }
}
pub fn verify_request(
    compact: &str,
    registry: &[VerifierRegistration],
    vct: &str,
    now: u64,
) -> Result<InventoryRequest, &'static str> {
    verify_inner(compact, registry, vct, now, None)
}
pub(super) fn verify_inner(
    compact: &str,
    registry: &[VerifierRegistration],
    vct: &str,
    now: u64,
    retrieval: Option<&retrieval::RequestRetrieval>,
) -> Result<InventoryRequest, &'static str> {
    let request = verify_request_mode(compact, registry, vct, now, None, retrieval, true)?;
    Ok(InventoryRequest {
        request,
        vct: vct.into(),
    })
}
pub struct SelectedCredential<'a> {
    request: ApprovedRequest,
    credential: &'a VerifiedCredential,
    index: usize,
}
impl SelectedCredential<'_> {
    pub fn request(&self) -> &ApprovedRequest {
        &self.request
    }
    pub fn credential(&self) -> &VerifiedCredential {
        self.credential
    }
    pub fn inventory_index(&self) -> usize {
        self.index
    }
    /// Review only this query's requested attributes, after receipt/authority validation.
    pub fn values(&self, now: u64) -> Result<Value, String> {
        if now >= self.request.expires_at() {
            return Err("request_expired".into());
        }
        self.credential.revalidate(now)?;
        self.request.check_credential_authorities(
            self.credential.credential(),
            Some(&self.credential.trust),
            &self.credential.issuer_key,
            now,
            self.credential.expires,
        )?;
        if self.request.format() == "dc+sd-jwt" {
            select_disclosures(self.credential.credential(), &self.request)
                .map(|(_, values)| values)
                .map_err(str::to_string)
        } else {
            let validated = crate::mdoc::verify_receipt(
                self.credential.credential(),
                &self.credential.issuer_key,
                &self.credential.holder,
                now,
            )
            .map_err(str::to_string)?;
            crate::mdoc::selected_values(&validated, &self.request.fields).map_err(str::to_string)
        }
    }
}
pub struct PreparedInventory<'a> {
    request: ApprovedRequest,
    selected: Vec<SelectedCredential<'a>>,
    expires: u64,
}
impl InventoryRequest {
    /// First matching local receipt per query, first satisfiable option per required set.
    /// No partial response is returned if any required set lacks a complete option.
    pub fn select<'a>(
        &self,
        credentials: &'a [VerifiedCredential],
        now: u64,
    ) -> Result<PreparedInventory<'a>, String> {
        if credentials.is_empty() || credentials.len() > 8 || now >= self.request.expires_at() {
            return Err("invalid_inventory".into());
        }
        let valid: Vec<_> = credentials
            .iter()
            .map(|c| c.revalidate(now).is_ok())
            .collect();
        let mut candidates = Vec::new();
        for query in &self.request.request.dcql_query.credentials {
            let mut request = self.request.clone();
            request.request.dcql_query = Dcql {
                credentials: vec![query.clone()],
                credential_sets: None,
            };
            match dcql::select(&request.request.dcql_query, &self.vct) {
                Err("credential_query_unsatisfied") => {
                    candidates.push(None);
                    continue;
                }
                Err(error) => return Err(error.into()),
                Ok(_) => {}
            }
            (request.fields, request.retained_fields) =
                dcql::fields(query).map_err(str::to_string)?;
            let found = credentials.iter().enumerate().find(|(i, c)| {
                if !valid[*i]
                    || c.format != query.format
                    || (c.format == "dc+sd-jwt"
                        && format!("{}/types/linked-document", c.issuer) != self.vct)
                {
                    return false;
                }
                if request
                    .check_credential_authorities(
                        c.credential(),
                        Some(&c.trust),
                        &c.issuer_key,
                        now,
                        c.expires,
                    )
                    .is_err()
                {
                    return false;
                }
                if c.format == "dc+sd-jwt" {
                    select_disclosures(c.credential(), &request).is_ok()
                } else {
                    crate::mdoc::verify_receipt(c.credential(), &c.issuer_key, &c.holder, now)
                        .and_then(|r| crate::mdoc::selected_values(&r, &request.fields))
                        .is_ok()
                }
            });
            candidates.push(found.map(|(index, credential)| SelectedCredential {
                request,
                credential,
                index,
            }));
        }
        let available: Vec<_> = candidates.iter().map(Option::is_some).collect();
        let indices = dcql::select_available(
            &self.request.request.dcql_query,
            &self.vct,
            Some(&available),
        )
        .map_err(str::to_string)?;
        let mut selected = Vec::new();
        let mut expires = self.request.expires_at();
        for i in indices {
            let item = candidates[i].take().ok_or("credential_query_unsatisfied")?;
            expires = expires.min(item.credential.expires);
            selected.push(item);
        }
        Ok(PreparedInventory {
            request: self.request.clone(),
            selected,
            expires,
        })
    }
}
impl PreparedInventory<'_> {
    pub fn selected(&self) -> &[SelectedCredential<'_>] {
        &self.selected
    }
    pub fn expires_at(&self) -> u64 {
        self.expires
    }
    /// Caller obtains explicit consent and signs each selected query with its bound holder.
    /// Recheck all receipt trust/status immediately before assembling one atomic response.
    pub fn encrypt_response(
        &self,
        proofs: &[String],
        now: u64,
        ephemeral: p256::SecretKey,
        iv: [u8; 12],
    ) -> Result<String, String> {
        if now >= self.expires || proofs.len() != self.selected.len() {
            return Err("invalid_response".into());
        }
        let mut tokens = serde_json::Map::new();
        for (selection, proof) in self.selected.iter().zip(proofs) {
            if proof.is_empty() || proof.len() > 65536 {
                return Err("invalid_response".into());
            }
            selection.credential.revalidate(now)?;
            selection.request.check_credential_authorities(
                selection.credential.credential(),
                Some(&selection.credential.trust),
                &selection.credential.issuer_key,
                now,
                selection.credential.expires,
            )?;
            tokens.insert(selection.request.query_id().into(), json!([proof]));
        }
        let mut payload = json!({"vp_token": tokens});
        if let Some(state) = self.request.state() {
            payload["state"] = json!(state);
        }
        encryption::encrypt_payload(
            self.request
                .response_encryption()
                .ok_or("response_encryption_required")?,
            Some(self.request.nonce()),
            None,
            &payload,
            ephemeral,
            iv,
        )
        .map_err(str::to_string)
    }
}
