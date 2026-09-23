//! Small server-side adapter for the same catalogs compiled by Paraglide JS.

use serde_json::Value;
use worker::Request;

pub struct Catalog {
    value: Value,
    pub locale: &'static str,
}

impl Catalog {
    pub fn message(&self, key: &str) -> &str {
        self.value[key]
            .as_str()
            .expect("missing translated message")
    }
}

fn supported(tag: &str) -> Option<&'static str> {
    let mut parts = tag.split('-');
    let primary = parts.next()?;
    if !tag.is_ascii()
        || tag.is_empty()
        || parts
            .clone()
            .any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        return None;
    }
    if primary.eq_ignore_ascii_case("ja") {
        Some("ja")
    } else if primary.eq_ignore_ascii_case("en") {
        Some("en")
    } else {
        None
    }
}

pub fn select(request: &Request, ui_locales: Option<&str>) -> worker::Result<&'static str> {
    if let Some(manual) = request
        .url()?
        .query_pairs()
        .find(|(key, _)| key == "lang")
        .and_then(|(_, value)| supported(&value))
    {
        return Ok(manual);
    }
    if let Some(explicit) =
        ui_locales.and_then(|list| list.split_ascii_whitespace().find_map(supported))
    {
        return Ok(explicit);
    }
    if let Some(saved) = crate::browser_cookie(request, "__Host-op-locale")?
        .as_deref()
        .and_then(supported)
    {
        return Ok(saved);
    }
    if let Some(header) = request.headers().get("Accept-Language")? {
        let mut best = None;
        for (index, item) in header.split(',').take(20).enumerate() {
            let mut tokens = item.trim().split(';');
            let Some(locale) = tokens.next().and_then(supported) else {
                continue;
            };
            let quality = tokens
                .next()
                .and_then(|q| q.trim().strip_prefix("q="))
                .and_then(|q| q.parse::<f32>().ok())
                .unwrap_or(1.0);
            if !(0.0..=1.0).contains(&quality) || quality == 0.0 {
                continue;
            }
            if best.is_none_or(|(_, rank, _): (&str, f32, usize)| quality > rank) {
                best = Some((locale, quality, index));
            }
        }
        if let Some((locale, _, _)) = best {
            return Ok(locale);
        }
    }
    Ok("ja")
}

pub fn catalog(locale: &'static str) -> Catalog {
    let source = if locale == "en" {
        include_str!("../../../messages/en.json")
    } else {
        include_str!("../../../messages/ja.json")
    };
    Catalog {
        value: serde_json::from_str(source).expect("valid translation catalog"),
        locale,
    }
}

pub fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
