//! Small RP product rules, shared by the Worker through Wasm and native tests.
use serde::Serialize;

#[derive(Serialize)]
pub struct Article {
    pub slug: &'static str,
    pub title: &'static str,
    pub body: &'static str,
}

pub const ARTICLES: &[Article] = &[
    Article {
        slug: "passkeys",
        title: "パスキーでログインする",
        body: "ログイン画面でパスキーを選び、端末のロックを解除してください。パスキーはこのサービスに送信されません。端末を変更する前に、別のログイン方法を確認してください。",
    },
    Article {
        slug: "vault",
        title: "Vault を開く",
        body: "Vault の復号には PRF 対応のパスキーが必要です。通常のログインだけなら PRF は不要です。復号できない場合は保存済みデータを上書きせず、問い合わせてください。",
    },
    Article {
        slug: "sessions",
        title: "ログイン状態を確認する",
        body: "アプリごとにログイン状態があります。アプリからログアウトするとそのアプリのセッションが終了します。身に覚えのない利用があれば管理者に連絡してください。",
    },
];

pub fn ticket_error(title: &str, message: &str) -> &'static str {
    if title.trim().is_empty() || title.len() > 120 || title.chars().any(char::is_control) {
        return "invalid_title";
    }
    reply_error(message)
}

pub fn reply_error(message: &str) -> &'static str {
    if message.trim().is_empty() || message.len() > 4000 || message.contains('\0') {
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
        assert_eq!(reply_error("\0"), "invalid_message");
        assert_eq!(reply_error(&"x".repeat(4001)), "invalid_message");
        assert_eq!(ARTICLES.len(), 3);
    }
}
