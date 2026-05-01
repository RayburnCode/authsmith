use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};

/// The current request's tenant, extracted from the `X-Tenant-ID` header.
///
/// In production this might come from a subdomain instead:
/// ```
/// // Parse host: "acme.yourapp.com" → tenant = "acme"
/// let host = headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
/// let tenant = host.split('.').next().unwrap_or("default");
/// ```
#[derive(Clone, Debug)]
pub struct TenantId(pub String);

impl<S: Send + Sync> FromRequestParts<S> for TenantId {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .headers
            .get("x-tenant-id")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(|s| TenantId(s.to_owned()))
            .ok_or((StatusCode::BAD_REQUEST, "X-Tenant-ID header is required"))
    }
}
