//! Email notification plugin for AuthSmith.
//!
//! Enable with `features = ["smtp"]`.
//!
//! ## Quick setup
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use authsmith_notify::email::{
//!     EmailPlugin, EmailPluginConfig,
//!     sender::{SmtpConfig, SmtpEmailSender, TlsMode},
//!     template::DefaultEmailTemplates,
//! };
//!
//! let sender = Arc::new(SmtpEmailSender::new(SmtpConfig {
//!     host:     "smtp.sendgrid.net".into(),
//!     port:     587,
//!     username: "apikey".into(),
//!     password: std::env::var("SENDGRID_API_KEY").unwrap(),
//!     from:     "MyApp <noreply@myapp.com>".into(),
//!     tls:      TlsMode::StartTls,
//! })?);
//!
//! let templates = Arc::new(DefaultEmailTemplates {
//!     app_name: "MyApp".into(),
//!     base_url:  "https://app.myapp.com".into(),
//! });
//!
//! let email_plugin = Arc::new(EmailPlugin::new(Arc::clone(&sender), templates));
//!
//! let auth = AuthEngine::builder()
//!     .user_provider(my_user_store)
//!     .session_provider(my_session_store)
//!     .with_plugin(Arc::clone(&email_plugin))
//!     .build()?;
//! ```

use async_trait::async_trait;
use authsmith_core::{AuthPlugin, AuthUser, Session};
use std::sync::Arc;

pub mod sender;
pub mod template;

pub use sender::{EmailSender, SmtpBuildError, SmtpConfig, SmtpEmailSender, TlsMode};
pub use template::{DefaultEmailTemplates, EmailMessage, EmailTemplates};

// ── EmailPluginConfig ─────────────────────────────────────────────────────────

/// Controls which hook-driven emails [`EmailPlugin`] sends automatically.
#[derive(Debug, Clone)]
pub struct EmailPluginConfig {
    /// Send a welcome email on
    /// [`on_user_created`](authsmith_core::AuthPlugin::on_user_created).
    /// Default: `true`.
    pub send_welcome: bool,
    /// Send a login alert on
    /// [`on_login`](authsmith_core::AuthPlugin::on_login).
    /// Default: `false`.
    pub send_login_alert: bool,
}

impl Default for EmailPluginConfig {
    fn default() -> Self {
        Self {
            send_welcome: true,
            send_login_alert: false,
        }
    }
}

// ── EmailPlugin ───────────────────────────────────────────────────────────────

/// `AuthPlugin` that sends emails on auth lifecycle events.
///
/// Register with `AuthEngine::builder().with_plugin(email_plugin)`.
pub struct EmailPlugin<T: EmailTemplates> {
    sender: Arc<dyn EmailSender>,
    templates: Arc<T>,
    config: EmailPluginConfig,
}

impl<T: EmailTemplates + 'static> EmailPlugin<T> {
    /// Create a new `EmailPlugin` with default config (welcome email only).
    pub fn new(sender: Arc<dyn EmailSender>, templates: Arc<T>) -> Self {
        Self {
            sender,
            templates,
            config: EmailPluginConfig::default(),
        }
    }

    /// Create a new `EmailPlugin` with a custom [`EmailPluginConfig`].
    pub fn with_config(
        sender: Arc<dyn EmailSender>,
        templates: Arc<T>,
        config: EmailPluginConfig,
    ) -> Self {
        Self { sender, templates, config }
    }

    // ── Direct send helpers ───────────────────────────────────────────────────

    /// Send the email-verification email for `user`.
    pub async fn send_verification_email(
        &self,
        user: &AuthUser,
        verify_url: &str,
    ) -> Result<(), EmailError> {
        if let Some(msg) = self.templates.email_verification(user, verify_url) {
            self.sender.send(msg).await.map_err(EmailError::Send)?;
        }
        Ok(())
    }

    /// Send the password-reset email for `user`.
    pub async fn send_password_reset_email(
        &self,
        user: &AuthUser,
        reset_url: &str,
    ) -> Result<(), EmailError> {
        if let Some(msg) = self.templates.password_reset(user, reset_url) {
            self.sender.send(msg).await.map_err(EmailError::Send)?;
        }
        Ok(())
    }

    /// Send a logout-notice email for `user`.
    pub async fn send_logout_email(
        &self,
        user: &AuthUser,
        session: &Session,
    ) -> Result<(), EmailError> {
        if let Some(msg) = self.templates.logout_notice(user, session) {
            self.sender.send(msg).await.map_err(EmailError::Send)?;
        }
        Ok(())
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    async fn try_send(
        &self,
        message: Option<EmailMessage>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(msg) = message {
            self.sender.send(msg).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl<T: EmailTemplates + 'static> AuthPlugin for EmailPlugin<T> {
    fn name(&self) -> &'static str {
        "authsmith-notify/email"
    }

    async fn on_user_created(
        &self,
        user: &AuthUser,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.config.send_welcome {
            self.try_send(self.templates.welcome(user)).await?;
        }
        Ok(())
    }

    async fn on_login(
        &self,
        user: &AuthUser,
        session: &Session,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.config.send_login_alert {
            self.try_send(self.templates.login_alert(user, session)).await?;
        }
        Ok(())
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors returned by [`EmailPlugin`] direct-send methods.
#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    #[error("email send failed: {0}")]
    Send(#[source] Box<dyn std::error::Error + Send + Sync>),
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use authsmith_core::{AuthUser, Role, Session};
    use std::sync::Mutex;

    #[derive(Default)]
    struct MockSender(Mutex<Vec<EmailMessage>>);

    #[async_trait]
    impl EmailSender for MockSender {
        async fn send(
            &self,
            message: EmailMessage,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.0.lock().unwrap().push(message);
            Ok(())
        }
    }

    fn mock_user(email: &str) -> AuthUser {
        AuthUser {
            id: "u1".into(),
            email: Some(email.into()),
            peer_id: None,
            roles: vec![Role::Realtor],
            metadata: serde_json::Value::Null,
            email_verified: false,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn mock_session() -> Session {
        Session {
            token: "tok".into(),
            user_id: "u1".into(),
            expires_at: 9_999_999_999,
            ip_address: Some("127.0.0.1".into()),
            user_agent: Some("TestAgent/1.0".into()),
            created_at: 0,
        }
    }

    #[test]
    fn default_templates_welcome_contains_app_name() {
        let tmpl = DefaultEmailTemplates {
            app_name: "TestApp".into(),
            base_url: "https://example.com".into(),
        };
        let user = mock_user("alice@example.com");
        let msg = tmpl.welcome(&user).expect("should produce a message");
        assert_eq!(msg.to, "alice@example.com");
        assert!(msg.subject.contains("TestApp"));
        assert!(msg.html.contains("TestApp"));
        assert!(msg.text.as_deref().unwrap().contains("TestApp"));
    }

    #[test]
    fn default_templates_welcome_none_without_email() {
        let tmpl = DefaultEmailTemplates {
            app_name: "TestApp".into(),
            base_url: "https://example.com".into(),
        };
        let mut user = mock_user("alice@example.com");
        user.email = None;
        assert!(tmpl.welcome(&user).is_none());
    }

    #[test]
    fn default_templates_verification_contains_url() {
        let tmpl = DefaultEmailTemplates {
            app_name: "TestApp".into(),
            base_url: "https://example.com".into(),
        };
        let user = mock_user("bob@example.com");
        let url = "https://example.com/verify?token=abc123";
        let msg = tmpl.email_verification(&user, url).unwrap();
        assert!(msg.html.contains(url));
    }

    #[tokio::test]
    async fn plugin_sends_welcome_on_user_created() {
        let sender = Arc::new(MockSender::default());
        let templates = Arc::new(DefaultEmailTemplates {
            app_name: "TestApp".into(),
            base_url: "https://example.com".into(),
        });
        let plugin = EmailPlugin::new(Arc::clone(&sender) as Arc<dyn EmailSender>, templates);
        let user = mock_user("charlie@example.com");
        plugin.on_user_created(&user).await.unwrap();
        let sent = sender.0.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "charlie@example.com");
    }

    #[tokio::test]
    async fn plugin_no_login_alert_by_default() {
        let sender = Arc::new(MockSender::default());
        let templates = Arc::new(DefaultEmailTemplates {
            app_name: "TestApp".into(),
            base_url: "https://example.com".into(),
        });
        let plugin = EmailPlugin::new(Arc::clone(&sender) as Arc<dyn EmailSender>, templates);
        let user = mock_user("dave@example.com");
        let session = mock_session();
        plugin.on_login(&user, &session).await.unwrap();
        assert!(sender.0.lock().unwrap().is_empty());
    }
}
