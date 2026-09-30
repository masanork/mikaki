//! Small RP product rules, shared by the Worker through Wasm and native tests.
use serde::Serialize;

#[derive(Serialize)]
pub struct Article {
    pub slug: &'static str,
    pub title_key: &'static str,
    pub body_key: &'static str,
}

pub const ARTICLES: &[Article] = &[
    Article {
        slug: "passkeys",
        title_key: "helpPasskeysTitle",
        body_key: "helpPasskeysBody",
    },
    Article {
        slug: "vault",
        title_key: "helpVaultTitle",
        body_key: "helpVaultBody",
    },
    Article {
        slug: "sessions",
        title_key: "helpSessionsTitle",
        body_key: "helpSessionsBody",
    },
];

pub fn ticket_error(title: &str, message: &str) -> &'static str {
    if title.trim().is_empty() || title.chars().count() > 120 || title.chars().any(char::is_control)
    {
        return "invalid_title";
    }
    reply_error(message)
}

pub fn reply_error(message: &str) -> &'static str {
    if message.trim().is_empty() || message.chars().count() > 4000 || message.contains('\0') {
        "invalid_message"
    } else {
        ""
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen::prelude::wasm_bindgen)]
pub fn articles_json() -> String {
    serde_json::to_string(ARTICLES).expect("static articles serialize")
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen::prelude::wasm_bindgen)]
pub fn validate_ticket(title: &str, message: &str) -> String {
    ticket_error(title, message).to_owned()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen::prelude::wasm_bindgen)]
pub fn validate_reply(message: &str) -> String {
    reply_error(message).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_and_nulls() {
        assert_eq!(ticket_error("Hi", "Help"), "");
        assert_eq!(ticket_error(" ", "Help"), "invalid_title");
        assert_eq!(ticket_error(&"x".repeat(121), "Help"), "invalid_title");
        assert_eq!(ticket_error(&"あ".repeat(120), "Help"), "");
        assert_eq!(ticket_error(&"あ".repeat(121), "Help"), "invalid_title");
        assert_eq!(reply_error("\0"), "invalid_message");
        assert_eq!(reply_error(&"x".repeat(4001)), "invalid_message");
        assert_eq!(ARTICLES.len(), 3);
    }
}
