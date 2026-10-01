//! Public issuer entry point. OIDC login still starts from a registered RP.

use super::*;

pub(super) async fn get(
    request: worker::Request,
    _context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let strings = i18n::catalog(i18n::select(&request, None)?);
    let message = |key| i18n::html_escape(strings.message(key));
    let other_locale = if strings.locale == "ja" { "en" } else { "ja" };
    let other_locale_label = if strings.locale == "ja" {
        "English"
    } else {
        "日本語"
    };
    let html = format!(
        r#"<!doctype html><html lang="{locale}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>mikaki</title><link rel="stylesheet" href="/login/login.css"><link rel="icon" type="image/svg+xml" href="/favicon.svg"></head><body><div id="app" data-page="home"><div class="auth-shell home-shell"><div class="shade" aria-hidden="true"></div><div class="gate-background" aria-hidden="true"><div class="gate-fallback"><span></span></div></div><div class="plate home-plate"><div class="item home-name">mikaki</div><div class="item origin"><span>{page_label}</span><strong>{host}</strong></div></div><main class="entry home-entry"><h1>{heading}</h1></main><footer><a class="quiet home-enroll" href="/enroll?lang={locale}">{enroll}<span aria-hidden="true">↗</span></a><a class="quiet" href="/?lang={other_locale}" lang="{other_locale}">{other_locale_label}</a></footer></div></div><script type="module" src="/login/login.js"></script></body></html>"#,
        locale = strings.locale,
        host = i18n::html_escape(request.url()?.host_str().unwrap_or_default()),
        page_label = message("authOriginLabel"),
        heading = message("homeHeading"),
        enroll = message("homeEnroll"),
    );
    worker::Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .with_header(
            "Content-Security-Policy",
            "default-src 'none'; img-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
        )?
        .with_header("X-Content-Type-Options", "nosniff")?
        .from_html(html)
}
