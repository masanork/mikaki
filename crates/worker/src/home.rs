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
        r#"<!doctype html><html lang="{locale}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title><link rel="stylesheet" href="/login/login.css"></head><body><div class="auth-shell"><section class="auth-story" aria-labelledby="home-title"><header class="auth-header"><div class="auth-brand" aria-label="mikaki"><span class="auth-mark" aria-hidden="true"><span></span><span></span><span></span><span></span></span>mikaki</div><span class="auth-header-tag" aria-hidden="true">IDENTITY</span></header><div class="auth-intro"><p class="auth-kicker"><span class="auth-kicker-line" aria-hidden="true"></span>{kicker}</p><h1 id="home-title">{hero_first}<br>{hero_second}</h1><p class="auth-hero-description">{hero_description}</p></div><div class="auth-art" aria-hidden="true"><div class="auth-art-ring auth-art-ring-outer"></div><div class="auth-art-ring auth-art-ring-inner"></div><div class="auth-art-core"><svg viewBox="0 0 64 64" fill="none"><circle cx="27" cy="27" r="11" stroke="currentColor" stroke-width="4"/><path d="M35 35 52 52m-7-7 5-5m-1 9 5-5" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg></div></div><p class="auth-story-footer">MIKAKI <span aria-hidden="true">/</span> PASSKEY IDENTITY</p></section><div class="auth-workspace"><div class="auth-toolbar"><a class="auth-home-language" href="/?lang={other_locale}" lang="{other_locale}">{other_locale_label}</a></div><main class="auth-layout"><section class="auth-card" aria-labelledby="home-action-title"><div class="auth-card-overline"><span class="auth-card-overline-dot"></span> MIKAKI ACCOUNT</div><h2 id="home-action-title">{heading}</h2><p class="auth-card-lead">{body}</p><p class="auth-field-help">{invite}</p><a class="auth-secondary auth-home-link" href="/enroll"><span>{enroll}</span><span aria-hidden="true">↗</span></a></section></main><footer class="auth-footer">© mikaki</footer></div></div></body></html>"#,
        locale = strings.locale,
        title = message("homeHeading"),
        kicker = message("authKicker"),
        hero_first = message("authHeroHeadingFirst"),
        hero_second = message("authHeroHeadingSecond"),
        hero_description = message("authHeroDescription"),
        heading = message("homeHeading"),
        body = message("homeBody"),
        invite = message("homeInvite"),
        enroll = message("homeEnroll"),
    );
    worker::Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .with_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'",
        )?
        .with_header("X-Content-Type-Options", "nosniff")?
        .from_html(html)
}
