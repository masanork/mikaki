//! Local owner policy using the AuthZEN evaluation information model.
//! The HTTP PDP binding and delegated grants remain separate future work.

use serde::Serialize;

pub const READ_CIPHERTEXT: &str = "vault.attribute.read-ciphertext";
pub const READ_OWNER_ENVELOPE: &str = "vault.attribute.read-owner-envelope";
pub const WRITE: &str = "vault.attribute.write";
pub const DELETE: &str = "vault.attribute.delete";
pub const SHARE_SYSTEM: &str = "vault.attribute.share-system";
pub const REVOKE_SYSTEM: &str = "vault.attribute.revoke-system";

#[derive(Serialize)]
pub struct Subject<'a> {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub id: &'a str,
}

#[derive(Serialize)]
pub struct Action<'a> {
    pub name: &'a str,
}

#[derive(Serialize)]
pub struct Resource {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub id: String,
}

#[derive(Serialize)]
pub struct Evaluation<'a> {
    pub subject: Subject<'a>,
    pub action: Action<'a>,
    pub resource: Resource,
}

#[derive(Serialize)]
pub struct Decision {
    pub decision: bool,
}

pub fn vault_attribute_resource(owner: &str, attribute: &str) -> String {
    format!("vault-attribute:{owner}:{attribute}")
}

/// The local PDP permits only the authenticated owner and explicit actions.
/// The caller must construct `subject.id` from verified authentication state.
pub fn evaluate_owner(request: &Evaluation<'_>, owner: &str, attribute: &str) -> Decision {
    Decision {
        decision: request.subject.kind == "mikaki-account"
            && request.subject.id == owner
            && request.resource.kind == "mikaki-vault-attribute"
            && request.resource.id == vault_attribute_resource(owner, attribute)
            && matches!(
                request.action.name,
                READ_CIPHERTEXT
                    | READ_OWNER_ENVELOPE
                    | WRITE
                    | DELETE
                    | SHARE_SYSTEM
                    | REVOKE_SYSTEM
            ),
    }
}

pub fn owner_evaluation<'a>(
    authenticated_account: &'a str,
    action: &'a str,
    owner: &str,
    attribute: &str,
) -> Evaluation<'a> {
    Evaluation {
        subject: Subject {
            kind: "mikaki-account",
            id: authenticated_account,
        },
        action: Action { name: action },
        resource: Resource {
            kind: "mikaki-vault-attribute",
            id: vault_attribute_resource(owner, attribute),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authzen_shape_and_owner_only_policy() {
        let request = owner_evaluation("account-a", READ_CIPHERTEXT, "account-a", "name");
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            serde_json::json!({
                "subject": {"type": "mikaki-account", "id": "account-a"},
                "action": {"name": "vault.attribute.read-ciphertext"},
                "resource": {"type": "mikaki-vault-attribute", "id": "vault-attribute:account-a:name"}
            })
        );
        assert!(evaluate_owner(&request, "account-a", "name").decision);
        assert!(!evaluate_owner(&request, "account-b", "name").decision);
        assert!(!evaluate_owner(&request, "account-a", "email").decision);
        let share = owner_evaluation("account-a", SHARE_SYSTEM, "account-a", "name");
        assert!(evaluate_owner(&share, "account-a", "name").decision);
        let denied = owner_evaluation(
            "account-a",
            "vault.attribute.release-rp",
            "account-a",
            "name",
        );
        assert!(!evaluate_owner(&denied, "account-a", "name").decision);
        assert_eq!(
            serde_json::to_value(evaluate_owner(&denied, "account-a", "name")).unwrap(),
            serde_json::json!({"decision": false})
        );
    }
}
