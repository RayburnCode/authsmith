use authsmith_core::{AuthError, AuthUser};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct RegisterBody {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginBody {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub expires_at: i64,
    pub tenant_id: Option<String>,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: Option<String>,
    pub tenant_id: Option<String>,
    pub roles: Vec<String>,
}

impl From<AuthUser> for UserResponse {
    fn from(u: AuthUser) -> Self {
        Self {
            id: u.id,
            email: u.email,
            tenant_id: u.tenant_id,
            roles: u.roles.iter().map(|r| r.to_string()).collect(),
        }
    }
}

pub enum AppError {
    Auth(AuthError),
    BadRequest(String),
}

impl From<AuthError> for AppError {
    fn from(e: AuthError) -> Self {
        Self::Auth(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg): (StatusCode, String) = match self {
            AppError::Auth(AuthError::InvalidCredentials) => {
                (StatusCode::UNAUTHORIZED, "invalid email or password".into())
            }
            AppError::Auth(AuthError::Forbidden(m)) => (StatusCode::FORBIDDEN, m),
            AppError::Auth(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
        };
        (status, msg).into_response()
    }
}
