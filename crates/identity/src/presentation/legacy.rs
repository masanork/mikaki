//! Explicit, narrow preregistered Draft 18 mdoc adapter. No profile autodetection.
use super::*;
#[derive(Clone)]
pub(super) struct Binding {
    pub definition_id: String,
    pub nonce: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyRequest {
    iss: String,
    aud: String,
    client_id: String,
    client_id_scheme: String,
    response_type: String,
    response_mode: String,
    response_uri: String,
    nonce: String,
    state: String,
    iat: u64,
    exp: u64,
    require_signed_request_object: bool,
    presentation_definition: Definition,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Definition {
    id: String,
    input_descriptors: Vec<Descriptor>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    id: String,
    format: Format,
    constraints: Constraints,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Format {
    mso_mdoc: Algorithms,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Algorithms {
    alg: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Constraints {
    limit_disclosure: String,
    fields: Vec<Field>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Field {
    path: Vec<String>,
    intent_to_retain: bool,
}
pub(super) fn parse(payload: &[u8], nonce: String) -> Result<(Request, Binding), &'static str> {
    let r: LegacyRequest = serde_json::from_slice(payload).map_err(|_| "invalid_request")?;
    if r.client_id_scheme != "pre-registered"
        || !r.require_signed_request_object
        || r.response_mode != "direct_post.jwt"
        || r.presentation_definition.id.is_empty()
        || r.presentation_definition.id.len() > 128
    {
        return Err("unsupported_legacy_profile");
    }
    let [descriptor] = r.presentation_definition.input_descriptors.as_slice() else {
        return Err("unsupported_query");
    };
    if descriptor.id != crate::mdoc::DOCTYPE
        || descriptor.format.mso_mdoc.alg != ["ES256"]
        || descriptor.constraints.limit_disclosure != "required"
        || descriptor.constraints.fields.is_empty()
        || descriptor.constraints.fields.len() > 5
    {
        return Err("unsupported_query");
    }
    let mut claims = Vec::new();
    for field in &descriptor.constraints.fields {
        let [path] = field.path.as_slice() else {
            return Err("unsupported_query");
        };
        let name = [
            "name",
            "address",
            "birthdate",
            "gender",
            "document_expiry_date",
        ]
        .into_iter()
        .find(|name| *path == format!("$['{}']['{}']", crate::mdoc::NAMESPACE, name))
        .ok_or("unsupported_query")?;
        claims.push(Claim {
            path: vec![crate::mdoc::NAMESPACE.into(), name.into()],
            intent_to_retain: Some(field.intent_to_retain),
        });
    }
    let binding = Binding {
        definition_id: r.presentation_definition.id,
        nonce,
    };
    Ok((
        Request {
            client_metadata: None,
            iss: Some(json!(r.iss)),
            aud: r.aud,
            client_id: r.client_id,
            response_type: r.response_type,
            response_mode: r.response_mode,
            response_uri: r.response_uri,
            nonce: r.nonce,
            state: Some(r.state),
            iat: r.iat,
            exp: r.exp,
            dcql_query: Dcql {
                credential_sets: None,
                credentials: vec![Query {
                    trusted_authorities: None,
                    id: "identity".into(),
                    format: "mso_mdoc".into(),
                    meta: Meta {
                        doctype_value: Some(crate::mdoc::DOCTYPE.into()),
                        vct_values: None,
                    },
                    claims,
                }],
            },
        },
        binding,
    ))
}
