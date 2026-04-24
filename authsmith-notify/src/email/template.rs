//! Email template abstraction and built-in default templates.
//!
//! Implement [`EmailTemplates`] on your own type for full control over every
//! email's content and design. All hook methods return `Option<EmailMessage>` —
//! return `None` to skip that email entirely (e.g. disable login alerts in dev).
//!
//! [`DefaultEmailTemplates`] ships clean, minimal HTML that works across all
//! major email clients out of the box.

use authsmith_core::{AuthUser, Session};

// ── EmailMessage ──────────────────────────────────────────────────────────────

/// A fully-formed email ready to hand to an [`EmailSender`](crate::EmailSender).
///
/// Build via [`EmailMessage::html`] / [`EmailMessage::multipart`], or
/// construct the struct directly.
#[derive(Debug, Clone)]
pub struct EmailMessage {
    /// Recipient address — `"alice@example.com"` or `"Alice <alice@example.com>"`.
    pub to: String,
    /// Subject line.
    pub subject: String,
    /// HTML body (required).
    pub html: String,
    /// Plain-text fallback. Shown by clients that don't render HTML.
    pub text: Option<String>,
}

impl EmailMessage {
    /// Convenience constructor — HTML body only (no plain-text fallback).
    pub fn html(
        to: impl Into<String>,
        subject: impl Into<String>,
        html: impl Into<String>,
    ) -> Self {
        Self {
            to: to.into(),
            subject: subject.into(),
            html: html.into(),
            text: None,
        }
    }

    /// Convenience constructor — both HTML and plain-text bodies.
    pub fn multipart(
        to: impl Into<String>,
        subject: impl Into<String>,
        html: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        Self {
            to: to.into(),
            subject: subject.into(),
            html: html.into(),
            text: Some(text.into()),
        }
    }
}

// ── EmailTemplates trait ──────────────────────────────────────────────────────

/// Define the email content for each auth lifecycle event.
///
/// Every method returns `Option<EmailMessage>`:
/// - `Some(message)` → the message will be sent.
/// - `None` → no email is sent for that event.
///
/// All methods have default no-op (`None`) implementations. Only override
/// the events you care about.
///
/// # Implementing custom templates
///
/// ```rust,ignore
/// use authsmith_email::template::{EmailMessage, EmailTemplates};
/// use authsmith_core::{AuthUser, Session};
///
/// struct MyTemplates {
///     app_name: &'static str,
/// }
///
/// impl EmailTemplates for MyTemplates {
///     fn welcome(&self, user: &AuthUser) -> Option<EmailMessage> {
///         let to = user.email.as_deref()?.to_string();
///         Some(EmailMessage::html(
///             to,
///             format!("Welcome to {}!", self.app_name),
///             format!("<h1>Welcome!</h1><p>You joined {}.</p>", self.app_name),
///         ))
///     }
///
///     fn email_verification(&self, user: &AuthUser, verify_url: &str) -> Option<EmailMessage> {
///         let to = user.email.as_deref()?.to_string();
///         Some(EmailMessage::html(
///             to,
///             "Verify your email".into(),
///             format!("<p>Click <a href=\"{verify_url}\">here</a> to verify.</p>"),
///         ))
///     }
/// }
/// ```
pub trait EmailTemplates: Send + Sync {
    /// Sent when a new user is created (via [`AuthEngine::register`](authsmith_core::AuthEngine::register)).
    ///
    /// Triggered by the [`on_user_created`](authsmith_core::AuthPlugin::on_user_created) hook.
    fn welcome(&self, user: &AuthUser) -> Option<EmailMessage> {
        let _ = user;
        None
    }

    /// Sent when the application calls
    /// [`EmailPlugin::send_verification_email`](crate::EmailPlugin::send_verification_email).
    ///
    /// `verify_url` is the fully-built URL the user clicks to verify their
    /// email — the caller is responsible for generating and storing the token.
    fn email_verification(&self, user: &AuthUser, verify_url: &str) -> Option<EmailMessage> {
        let _ = (user, verify_url);
        None
    }

    /// Sent when the application calls
    /// [`EmailPlugin::send_password_reset_email`](crate::EmailPlugin::send_password_reset_email).
    ///
    /// `reset_url` is the fully-built URL the user clicks to reset their
    /// password — the caller is responsible for generating and storing the token.
    fn password_reset(&self, user: &AuthUser, reset_url: &str) -> Option<EmailMessage> {
        let _ = (user, reset_url);
        None
    }

    /// Sent after a successful login (via [`AuthEngine::login`](authsmith_core::AuthEngine::login)).
    ///
    /// Return `None` (default) to opt out of login alert emails.
    fn login_alert(&self, user: &AuthUser, session: &Session) -> Option<EmailMessage> {
        let _ = (user, session);
        None
    }

    /// Sent when the application calls
    /// [`EmailPlugin::send_logout_email`](crate::EmailPlugin::send_logout_email).
    ///
    /// The `on_logout` hook only receives a [`Session`] (no user email), so
    /// this email is **not** triggered automatically — call it explicitly from
    /// your route handler after resolving the user.
    fn logout_notice(&self, user: &AuthUser, session: &Session) -> Option<EmailMessage> {
        let _ = (user, session);
        None
    }
}

// ── DefaultEmailTemplates ─────────────────────────────────────────────────────

/// Ready-to-use HTML email templates for all auth lifecycle events.
///
/// Templates produce clean, responsive HTML that works across Gmail, Outlook,
/// Apple Mail, and all major clients. Use as-is, or implement [`EmailTemplates`]
/// from scratch for full branding control.
///
/// # Example
/// ```rust,ignore
/// use authsmith_email::template::DefaultEmailTemplates;
/// use authsmith_email::{EmailPlugin, EmailPluginConfig};
/// use std::sync::Arc;
///
/// let templates = DefaultEmailTemplates {
///     app_name: "DSCR Express".into(),
///     base_url:  "https://app.dscrexpress.com".into(),
/// };
///
/// let plugin = EmailPlugin::new(Arc::new(sender), Arc::new(templates));
/// ```
#[derive(Debug, Clone)]
pub struct DefaultEmailTemplates {
    /// App name shown in subject lines and email copy.
    pub app_name: String,
    /// Base URL for links inside emails (no trailing slash).
    /// Used to generate the "go to app" footer link.
    pub base_url: String,
}

impl EmailTemplates for DefaultEmailTemplates {
    fn welcome(&self, user: &AuthUser) -> Option<EmailMessage> {
        let to = user.email.as_deref()?.to_string();
        let app = &self.app_name;
        let url = &self.base_url;

        Some(EmailMessage::multipart(
            to,
            format!("Welcome to {app}!"),
            format!(
                r#"<!DOCTYPE html>
<html lang="en">
<body style="margin:0;padding:0;background:#f4f4f5;font-family:system-ui,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0">
  <tr><td align="center" style="padding:40px 0">
    <table width="560" cellpadding="0" cellspacing="0"
           style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08)">
      <tr><td style="background:#0070f3;padding:32px 40px">
        <h1 style="margin:0;color:#fff;font-size:24px">{app}</h1>
      </td></tr>
      <tr><td style="padding:32px 40px">
        <h2 style="margin:0 0 12px;font-size:20px;color:#111">Welcome aboard!</h2>
        <p style="margin:0 0 24px;color:#444;line-height:1.6">
          Your account has been created. You're all set to get started.
        </p>
        <a href="{url}" style="display:inline-block;background:#0070f3;color:#fff;
           padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">
          Go to {app} &rarr;
        </a>
      </td></tr>
      <tr><td style="padding:16px 40px;background:#f9f9f9;border-top:1px solid #eee">
        <p style="margin:0;color:#999;font-size:12px">
          If you didn't create this account, you can safely ignore this email.
        </p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>"#
            ),
            format!(
                "Welcome to {app}!\n\nYour account has been created. You're all set.\n\n\
                 Visit: {url}\n\n\
                 If you didn't create this account, you can safely ignore this email."
            ),
        ))
    }

    fn email_verification(&self, user: &AuthUser, verify_url: &str) -> Option<EmailMessage> {
        let to = user.email.as_deref()?.to_string();
        let app = &self.app_name;

        Some(EmailMessage::multipart(
            to,
            format!("Verify your email — {app}"),
            format!(
                r#"<!DOCTYPE html>
<html lang="en">
<body style="margin:0;padding:0;background:#f4f4f5;font-family:system-ui,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0">
  <tr><td align="center" style="padding:40px 0">
    <table width="560" cellpadding="0" cellspacing="0"
           style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08)">
      <tr><td style="background:#0070f3;padding:32px 40px">
        <h1 style="margin:0;color:#fff;font-size:24px">{app}</h1>
      </td></tr>
      <tr><td style="padding:32px 40px">
        <h2 style="margin:0 0 12px;font-size:20px;color:#111">Verify your email address</h2>
        <p style="margin:0 0 24px;color:#444;line-height:1.6">
          Click the button below to verify your email address for <strong>{app}</strong>.
          This link expires in <strong>24 hours</strong>.
        </p>
        <a href="{verify_url}" style="display:inline-block;background:#0070f3;color:#fff;
           padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">
          Verify Email &rarr;
        </a>
        <p style="margin:24px 0 0;color:#999;font-size:12px;word-break:break-all">
          Or copy this link: {verify_url}
        </p>
      </td></tr>
      <tr><td style="padding:16px 40px;background:#f9f9f9;border-top:1px solid #eee">
        <p style="margin:0;color:#999;font-size:12px">
          If you didn't request this verification, you can safely ignore this email.
        </p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>"#
            ),
            format!(
                "Verify your email for {app}\n\n\
                 Click this link to verify your email address:\n{verify_url}\n\n\
                 This link expires in 24 hours.\n\n\
                 If you didn't request this, ignore this email."
            ),
        ))
    }

    fn password_reset(&self, user: &AuthUser, reset_url: &str) -> Option<EmailMessage> {
        let to = user.email.as_deref()?.to_string();
        let app = &self.app_name;

        Some(EmailMessage::multipart(
            to,
            format!("Reset your password — {app}"),
            format!(
                r#"<!DOCTYPE html>
<html lang="en">
<body style="margin:0;padding:0;background:#f4f4f5;font-family:system-ui,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0">
  <tr><td align="center" style="padding:40px 0">
    <table width="560" cellpadding="0" cellspacing="0"
           style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08)">
      <tr><td style="background:#dc2626;padding:32px 40px">
        <h1 style="margin:0;color:#fff;font-size:24px">{app}</h1>
      </td></tr>
      <tr><td style="padding:32px 40px">
        <h2 style="margin:0 0 12px;font-size:20px;color:#111">Password reset request</h2>
        <p style="margin:0 0 24px;color:#444;line-height:1.6">
          We received a request to reset the password for your <strong>{app}</strong> account.
          Click the button below — this link expires in <strong>15 minutes</strong>.
        </p>
        <a href="{reset_url}" style="display:inline-block;background:#dc2626;color:#fff;
           padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">
          Reset Password &rarr;
        </a>
        <p style="margin:24px 0 0;color:#999;font-size:12px;word-break:break-all">
          Or copy this link: {reset_url}
        </p>
      </td></tr>
      <tr><td style="padding:16px 40px;background:#f9f9f9;border-top:1px solid #eee">
        <p style="margin:0;color:#999;font-size:12px">
          If you didn't request a password reset, ignore this email —
          your password has <strong>not</strong> been changed.
        </p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>"#
            ),
            format!(
                "Reset your password for {app}\n\n\
                 Click this link to reset your password:\n{reset_url}\n\n\
                 This link expires in 15 minutes.\n\n\
                 If you didn't request a reset, ignore this email — your password has not changed."
            ),
        ))
    }

    fn login_alert(&self, user: &AuthUser, session: &Session) -> Option<EmailMessage> {
        let to = user.email.as_deref()?.to_string();
        let app = &self.app_name;
        let ip = session.ip_address.as_deref().unwrap_or("unknown");
        let ua = session.user_agent.as_deref().unwrap_or("unknown");

        Some(EmailMessage::multipart(
            to,
            format!("New sign-in to your {app} account"),
            format!(
                r#"<!DOCTYPE html>
<html lang="en">
<body style="margin:0;padding:0;background:#f4f4f5;font-family:system-ui,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0">
  <tr><td align="center" style="padding:40px 0">
    <table width="560" cellpadding="0" cellspacing="0"
           style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08)">
      <tr><td style="background:#111;padding:32px 40px">
        <h1 style="margin:0;color:#fff;font-size:24px">{app}</h1>
      </td></tr>
      <tr><td style="padding:32px 40px">
        <h2 style="margin:0 0 12px;font-size:20px;color:#111">New sign-in detected</h2>
        <p style="margin:0 0 20px;color:#444;line-height:1.6">
          A new sign-in to your <strong>{app}</strong> account was just detected.
        </p>
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border:1px solid #eee;border-radius:6px;overflow:hidden">
          <tr style="background:#f9f9f9">
            <td style="padding:10px 16px;color:#666;font-size:13px;width:140px">IP Address</td>
            <td style="padding:10px 16px;font-size:13px;color:#111">{ip}</td>
          </tr>
          <tr>
            <td style="padding:10px 16px;color:#666;font-size:13px;border-top:1px solid #eee">Browser</td>
            <td style="padding:10px 16px;font-size:13px;color:#111;border-top:1px solid #eee">{ua}</td>
          </tr>
        </table>
      </td></tr>
      <tr><td style="padding:16px 40px;background:#f9f9f9;border-top:1px solid #eee">
        <p style="margin:0;color:#999;font-size:12px">
          If this was you, no action is needed.
          If you don't recognise this activity, change your password immediately.
        </p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>"#
            ),
            format!(
                "New sign-in to your {app} account\n\n\
                 IP Address: {ip}\n\
                 Browser:    {ua}\n\n\
                 If this was you, no action is needed.\n\
                 If you don't recognise this, change your password immediately."
            ),
        ))
    }

    fn logout_notice(&self, user: &AuthUser, session: &Session) -> Option<EmailMessage> {
        let to = user.email.as_deref()?.to_string();
        let app = &self.app_name;
        let ip = session.ip_address.as_deref().unwrap_or("unknown");

        Some(EmailMessage::multipart(
            to,
            format!("You've been signed out of {app}"),
            format!(
                r#"<!DOCTYPE html>
<html lang="en">
<body style="margin:0;padding:0;background:#f4f4f5;font-family:system-ui,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0">
  <tr><td align="center" style="padding:40px 0">
    <table width="560" cellpadding="0" cellspacing="0"
           style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08)">
      <tr><td style="background:#111;padding:32px 40px">
        <h1 style="margin:0;color:#fff;font-size:24px">{app}</h1>
      </td></tr>
      <tr><td style="padding:32px 40px">
        <h2 style="margin:0 0 12px;font-size:20px;color:#111">You've been signed out</h2>
        <p style="margin:0 0 16px;color:#444;line-height:1.6">
          Your session from IP <strong>{ip}</strong> was signed out of <strong>{app}</strong>.
        </p>
        <p style="margin:0;color:#444;line-height:1.6">
          If you didn't do this, your account may have been accessed without your permission.
          Change your password immediately and contact support.
        </p>
      </td></tr>
      <tr><td style="padding:16px 40px;background:#f9f9f9;border-top:1px solid #eee">
        <p style="margin:0;color:#999;font-size:12px">
          If this was you, no further action is needed.
        </p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>"#
            ),
            format!(
                "You've been signed out of {app}\n\n\
                 Your session from IP {ip} was signed out.\n\n\
                 If you didn't do this, change your password immediately."
            ),
        ))
    }
}
