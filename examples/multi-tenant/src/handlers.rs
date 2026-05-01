use authsmith_axum::AuthSession;
use authsmith_core::{AuthError, CreateUserInput, PasswordHasher, Role, SessionMeta};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
};

use crate::{
    state::AppState,
    tenant::TenantId,
    types::{AppError, LoginBody, RegisterBody, TokenResponse, UserResponse},
};

/// `POST /register`
///
/// The tenant comes from the `X-Tenant-ID` header and is stored on the user
/// record via `CreateUserInput::builder().tenant_id(...)`. Every user created
/// here belongs to exactly one tenant.
pub async fn register(
    State(state): State<AppState>,
    TenantId(tenant): TenantId,
    Json(body): Json<RegisterBody>,
) -> Result<(StatusCode, Json<UserResponse>), AppError> {
    let hash = state
        .hasher
        .hash(&body.password)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let user = state
        .auth
        .register(
            CreateUserInput::builder()
                .email(body.email)
                .password_hash(hash)
                .role(Role::Investor)
                // ── Key multi-tenant line ──────────────────────────────────
                // Scopes the user to this tenant. The DB adapter stores this
                // in the `tenant_id` column and the existing index makes
                // per-tenant queries fast.
                .tenant_id(tenant)
                .build(),
        )
        .await?;

    Ok((StatusCode::CREATED, Json(user.into())))
}

/// `POST /login`
///
/// The session inherits the user's `tenant_id` automatically inside
/// `AuthEngine::create_session` (see `SessionMeta` passthrough logic).
/// The returned token is therefore scoped to the tenant — cross-tenant
/// reuse is caught by the `/me` guard.
pub async fn login(
    State(state): State<AppState>,
    TenantId(tenant): TenantId,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> Result<Json<TokenResponse>, AppError> {
    let user = state
        .auth
        .find_user_by_email(&body.email)
        .await?
        .ok_or(AppError::Auth(AuthError::InvalidCredentials))?;

    // Tenant mismatch — don't reveal that the user exists in another tenant.
    if user.tenant_id.as_deref() != Some(&tenant) {
        return Err(AppError::Auth(AuthError::InvalidCredentials));
    }

    let hash = state
        .auth
        .user_provider()
        .password_hash_for(&body.email)
        .ok_or(AppError::Auth(AuthError::InvalidCredentials))?;

    let valid = state
        .hasher
        .verify(&body.password, &hash)
        .map_err(|_| AppError::Auth(AuthError::InvalidCredentials))?;

    if !valid {
        return Err(AppError::Auth(AuthError::InvalidCredentials));
    }

    let ua = headers.get("user-agent").and_then(|v| v.to_str().ok()).map(String::from);

    // Pass tenant_id explicitly in SessionMeta so the session record is
    // scoped to the tenant (engine would inherit from the user anyway, but
    // being explicit documents intent clearly).
    let session = state
        .auth
        .create_session(
            &user,
            SessionMeta { ip_address: None, user_agent: ua, tenant_id: Some(tenant) },
        )
        .await?;

    Ok(Json(TokenResponse {
        tenant_id: session.tenant_id.clone(),
        token: session.token,
        expires_at: session.expires_at,
    }))
}

/// `GET /me`
///
/// Cross-tenant guard: even if the token is valid, the request is rejected
/// with 403 if the authenticated user's tenant doesn't match the header.
///
/// This prevents a compromised token from being replayed against a different
/// tenant's API surface.
pub async fn me(
    TenantId(tenant): TenantId,
    AuthSession(user): AuthSession,
) -> Result<Json<UserResponse>, AppError> {
    // Tenant isolation check.
    if user.tenant_id.as_deref() != Some(&tenant) {
        return Err(AppError::Auth(AuthError::Forbidden(
            "token does not belong to this tenant".into(),
        )));
    }
    Ok(Json(user.into()))
}

/// `GET /tenant/users`
///
/// List all users that belong to the requesting tenant.
///
/// `list_users()` returns ALL users across tenants (no filter at the provider
/// level). We filter in the handler here. With the DB adapters a real
/// `list_users_by_tenant(tenant_id)` query would be more efficient — this
/// example shows the filter logic when using an in-memory store.
pub async fn list_tenant_users(
    State(state): State<AppState>,
    TenantId(tenant): TenantId,
    AuthSession(caller): AuthSession,
) -> Result<Json<Vec<UserResponse>>, AppError> {
    // Only admins of the same tenant can list users.
    if caller.tenant_id.as_deref() != Some(&tenant) {
        return Err(AppError::Auth(AuthError::Forbidden(
            "token does not belong to this tenant".into(),
        )));
    }
    state.auth.require_role(&caller, &Role::Admin)?;

    let all = state.auth.list_all_users().await?;
    let tenant_users: Vec<UserResponse> = all
        .into_iter()
        .filter(|u| u.tenant_id.as_deref() == Some(&tenant))
        .map(UserResponse::from)
        .collect();

    Ok(Json(tenant_users))
}
