//! # authsmith-oauth
//!
//! OAuth2 / OIDC provider integrations for AuthSmith.
//!
//! ## Planned providers
//! - Google (OpenID Connect)
//! - GitHub (OAuth2)
//! - Discord (OAuth2)
//!
//! ## Architecture
//!
//! Each provider implements [`OAuthProvider`], which takes an authorization
//! code and returns a resolved [`authsmith_core::AuthUser`]. The
//! [`AuthEngine`][authsmith_core::AuthEngine] stores the user via its
//! configured [`AuthProvider`][authsmith_core::AuthProvider].
//!
//! ```text
//! Browser ──code──> your callback handler
//!                       │
//!               OAuthProvider::exchange_code()
//!                       │
//!               AuthUser (created or updated)
//!                       │
//!               AuthEngine::create_session()
//!                       │
//!               Set-Cookie: session=<token>
//! ```
//!
//! ## Status
//! **Planned** — API design is stable; implementation coming in v0.3.

use authsmith_core::AuthUser;
use serde::{Deserialize, Serialize};

// ── Types ─────────────────────────────────────────────────────────────────────

/// The OAuth2 authorization code returned by the provider after user consent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode(pub String);

/// Normalized user info returned by any OAuth provider, before mapping to [`AuthUser`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    /// Provider-scoped unique ID (e.g. Google sub, GitHub id).
    pub provider_id: String,
    pub provider: OAuthProviderKind,
    pub email: Option<String>,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    /// Raw JSON from the provider — available for app-specific mapping.
    pub raw: serde_json::Value,
}

/// Supported OAuth2 providers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum OAuthProviderKind {
    Google,
    GitHub,
    Discord,
    /// Any provider not listed above — store the slug (e.g. `"twitter"`).
    Custom(String),
}

impl std::fmt::Display for OAuthProviderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Google => write!(f, "google"),
            Self::GitHub => write!(f, "github"),
            Self::Discord => write!(f, "discord"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("token exchange failed: {0}")]
    TokenExchange(String),
    #[error("failed to fetch user info: {0}")]
    UserInfo(String),
    #[error("provider returned an unexpected response: {0}")]
    UnexpectedResponse(String),
    #[error("state mismatch — possible CSRF attack")]
    StateMismatch,
}

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Implement this for each OAuth2 / OIDC provider.
///
/// The concrete implementations (Google, GitHub, …) live behind the
/// `providers` feature flag and will be added in v0.3.
#[async_trait::async_trait]
pub trait OAuthProvider: Send + Sync {
    /// A stable slug identifying the provider (e.g. `"google"`).
    fn name(&self) -> &str;

    /// Build the authorization URL to redirect the user to.
    fn authorization_url(&self, state: &str) -> String;

    /// Exchange an authorization code for normalized user info.
    async fn exchange_code(
        &self,
        code: AuthorizationCode,
        state: &str,
        expected_state: &str,
    ) -> Result<OAuthUserInfo, OAuthError>;

    /// Map provider user info to an [`AuthUser`].
    ///
    /// Implementors should look up an existing user by `provider_id` first,
    /// then fall back to creating a new account.
    async fn resolve_user(&self, info: OAuthUserInfo) -> Result<AuthUser, OAuthError>;
}
