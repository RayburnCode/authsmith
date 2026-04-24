//! SMTP transport abstraction.

use async_trait::async_trait;
use lettre::{
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

use super::template::EmailMessage;

// ── EmailSender trait ─────────────────────────────────────────────────────────

/// Send a prepared [`EmailMessage`] over any transport.
///
/// Implement this on your own type to use a custom SMTP library, an HTTP
/// transactional email API, or a mock for testing.
#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send(
        &self,
        message: EmailMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

// ── SmtpConfig ────────────────────────────────────────────────────────────────

/// TLS connection mode for [`SmtpConfig`].
#[derive(Debug, Clone, Default)]
pub enum TlsMode {
    /// STARTTLS upgrade — recommended default, typically port `587`.
    #[default]
    StartTls,
    /// TLS wrapper from the first byte (SMTPS) — typically port `465`.
    Tls,
    /// No encryption. **Development / localhost only.**
    Plain,
}

/// Configuration for the built-in [`SmtpEmailSender`].
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// SMTP server hostname (e.g. `"smtp.sendgrid.net"`).
    pub host: String,
    /// SMTP port. Typically `587` (STARTTLS) or `465` (SMTPS).
    pub port: u16,
    /// SMTP authentication username.
    pub username: String,
    /// SMTP authentication password or API key. **Never hard-code this.**
    pub password: String,
    /// The `From` header value for all outgoing mail.
    pub from: String,
    /// TLS connection mode. Default: [`TlsMode::StartTls`].
    pub tls: TlsMode,
}

// ── SmtpEmailSender ───────────────────────────────────────────────────────────

/// Built-in SMTP email sender backed by [`lettre`].
pub struct SmtpEmailSender {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: String,
}

impl SmtpEmailSender {
    /// Build an [`SmtpEmailSender`] from [`SmtpConfig`].
    pub fn new(config: SmtpConfig) -> Result<Self, SmtpBuildError> {
        let creds = Credentials::new(config.username.clone(), config.password.clone());

        let transport = match config.tls {
            TlsMode::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                .map_err(SmtpBuildError::Transport)?
                .port(config.port)
                .credentials(creds)
                .build(),

            TlsMode::Tls => {
                let tls = TlsParameters::new(config.host.clone())
                    .map_err(|e| SmtpBuildError::Tls(e.to_string()))?;
                AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
                    .map_err(SmtpBuildError::Transport)?
                    .port(config.port)
                    .tls(Tls::Wrapper(tls))
                    .credentials(creds)
                    .build()
            }

            TlsMode::Plain => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
                .port(config.port)
                .credentials(creds)
                .build(),
        };

        Ok(Self { transport, from: config.from })
    }

    /// The `From` address this sender was configured with.
    pub fn from_address(&self) -> &str {
        &self.from
    }
}

#[async_trait]
impl EmailSender for SmtpEmailSender {
    async fn send(
        &self,
        message: EmailMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use lettre::message::{header::ContentType, MultiPart, SinglePart};

        let from = self
            .from
            .parse()
            .map_err(|e| SmtpSendError::InvalidAddress(format!("from: {e}")))?;
        let to = message
            .to
            .parse()
            .map_err(|e| SmtpSendError::InvalidAddress(format!("to: {e}")))?;

        let builder = Message::builder()
            .from(from)
            .to(to)
            .subject(message.subject);

        let email = if let Some(plain) = message.text {
            builder.multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(plain),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(message.html),
                    ),
            )
        } else {
            builder.singlepart(
                SinglePart::builder()
                    .header(ContentType::TEXT_HTML)
                    .body(message.html),
            )
        }
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

        self.transport
            .send(email)
            .await
            .map(|_| ())
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors constructing an [`SmtpEmailSender`].
#[derive(Debug, thiserror::Error)]
pub enum SmtpBuildError {
    #[error("SMTP transport error: {0}")]
    Transport(#[source] lettre::transport::smtp::Error),
    #[error("TLS error: {0}")]
    Tls(String),
}

/// Errors sending via [`SmtpEmailSender`].
#[derive(Debug, thiserror::Error)]
pub enum SmtpSendError {
    #[error("invalid email address: {0}")]
    InvalidAddress(String),
    #[error("SMTP send error: {0}")]
    Send(#[from] lettre::transport::smtp::Error),
}
