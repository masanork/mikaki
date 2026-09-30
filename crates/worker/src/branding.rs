//! Public, fixed branding assets; no account or authorization data is accessed.

pub(super) async fn get(
    request: worker::Request,
    _context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let (content_type, bytes): (&str, &[u8]) = match request.url()?.path() {
        "/favicon.svg" => (
            "image/svg+xml",
            include_bytes!("../../../branding/favicon.svg"),
        ),
        "/favicon.ico" => (
            "image/x-icon",
            include_bytes!("../../../branding/favicon/favicon.ico"),
        ),
        "/favicon-32x32.png" => (
            "image/png",
            include_bytes!("../../../branding/favicon/32x32.png"),
        ),
        _ => return worker::Response::error("Not found", 404),
    };
    Ok(worker::Response::builder()
        .with_header("Content-Type", content_type)?
        .with_header("Cache-Control", "public, max-age=3600")?
        .with_header("X-Content-Type-Options", "nosniff")?
        .fixed(bytes.to_vec()))
}
