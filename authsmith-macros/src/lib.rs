//! # authsmith-macros
//!
//! Proc-macro helpers for the AuthSmith authentication framework.
//!
//! ## `#[require_role("RoleName")]`
//!
//! Attribute macro for Axum handler functions. Injects an `AuthSession`
//! extractor and returns `403 Forbidden` if the authenticated user does not
//! hold the specified role — without touching the rest of the handler.
//!
//! The middleware provided by `authsmith-axum` must be active on the router
//! for `AuthSession` to be populated.
//!
//! ```rust,ignore
//! use authsmith_macros::require_role;
//!
//! #[require_role("Admin")]
//! async fn admin_dashboard() -> &'static str {
//!     "welcome, admin"
//! }
//!
//! // Expands to roughly:
//! // async fn admin_dashboard(
//! //     __authsmith_session: authsmith_axum::AuthSession,
//! // ) -> axum::response::Response {
//! //     let authsmith_axum::AuthSession(__authsmith_user) = __authsmith_session;
//! //     let __role: authsmith_core::Role = "Admin".parse()
//! //         .unwrap_or_else(|_| authsmith_core::Role::Custom("Admin".to_string()));
//! //     if !__authsmith_user.has_role(&__role) {
//! //         use axum::response::IntoResponse;
//! //         return (axum::http::StatusCode::FORBIDDEN, "insufficient role").into_response();
//! //     }
//! //     use axum::response::IntoResponse;
//! //     { "welcome, admin" }.into_response()
//! // }
//! ```
//!
//! ## `derive(AuthProvider)`
//!
//! Derive macro that implements [`authsmith_core::AuthProvider`] on a newtype
//! wrapper around a database pool, delegating to the matching `authsmith-db`
//! store.
//!
//! ```rust,ignore
//! use authsmith_macros::AuthProvider;
//! use sqlx::PgPool;
//!
//! #[derive(AuthProvider)]
//! #[auth_provider(backend = "postgres")]
//! pub struct MyUserStore(PgPool);
//!
//! // Expands to an impl that delegates every AuthProvider method to
//! // authsmith_db::postgres::PgUserStore::new(self.0.clone()).
//! ```

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, DeriveInput, FnArg, ItemFn, LitStr, Pat, Token,
};

// ── #[require_role("RoleName")] ───────────────────────────────────────────────

/// Attribute macro — enforces a role requirement on an Axum handler.
///
/// See the [crate-level documentation](self) for usage and expansion details.
#[proc_macro_attribute]
pub fn require_role(attr: TokenStream, item: TokenStream) -> TokenStream {
    let role_lit = parse_macro_input!(attr as LitStr);
    let role_str = role_lit.value();

    let mut func = parse_macro_input!(item as ItemFn);

    let original_block = func.block.clone();
    let original_inputs = func.sig.inputs.clone();

    // Inject `__authsmith_session: authsmith_axum::AuthSession` as the first
    // parameter only if the caller didn't already declare one.
    let session_ident = syn::Ident::new("__authsmith_session", Span::call_site());
    let has_auth_session = original_inputs.iter().any(|arg| {
        if let FnArg::Typed(pt) = arg {
            let ty = &pt.ty;
            let ty_str = quote!(#ty).to_string();
            ty_str.contains("AuthSession")
        } else {
            false
        }
    });

    if !has_auth_session {
        let injected: FnArg = syn::parse_quote! {
            #session_ident: authsmith_axum::AuthSession
        };
        func.sig.inputs.insert(0, injected);
    }

    // Rewrite the return type to `axum::response::Response` so we can return
    // an early rejection before calling the original body.
    func.sig.output = syn::parse_quote! {
        -> axum::response::Response
    };

    // Determine the binding to use: injected name or the caller's name.
    let user_binding = if has_auth_session {
        // Find the existing AuthSession param name.
        original_inputs
            .iter()
            .find_map(|arg| {
                if let FnArg::Typed(pt) = arg {
                    let ty_str = quote!(&pt.ty).to_string();
                    if ty_str.contains("AuthSession") {
                        if let Pat::Ident(id) = pt.pat.as_ref() {
                            return Some(id.ident.clone());
                        }
                    }
                }
                None
            })
            .unwrap_or_else(|| syn::Ident::new("__authsmith_session", Span::call_site()))
    } else {
        session_ident.clone()
    };

    let role_value = role_str.clone();

    func.block = Box::new(syn::parse_quote! {
        {
            let authsmith_axum::AuthSession(__authsmith_user) = #user_binding;
            let __role: authsmith_core::Role = #role_value.parse()
                .unwrap_or_else(|_| authsmith_core::Role::Custom(#role_value.to_string()));
            if !__authsmith_user.has_role(&__role) {
                use axum::response::IntoResponse as _;
                return (axum::http::StatusCode::FORBIDDEN, "insufficient role").into_response();
            }
            use axum::response::IntoResponse as _;
            #original_block.into_response()
        }
    });

    quote!(#func).into()
}

// ── derive(AuthProvider) ──────────────────────────────────────────────────────

/// Backend identifier parsed from `#[auth_provider(backend = "...")]`.
struct AuthProviderArgs {
    backend: String,
}

impl Parse for AuthProviderArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // Expect: backend = "sqlite" | "postgres"
        let key: syn::Ident = input.parse()?;
        if key != "backend" {
            return Err(syn::Error::new(key.span(), "expected `backend`"));
        }
        let _: Token![=] = input.parse()?;
        let val: LitStr = input.parse()?;
        Ok(Self {
            backend: val.value(),
        })
    }
}

/// Derive macro — generates an [`authsmith_core::AuthProvider`] impl that
/// delegates to the matching `authsmith-db` store.
///
/// See the [crate-level documentation](self) for usage and expansion details.
#[proc_macro_derive(AuthProvider, attributes(auth_provider))]
pub fn derive_auth_provider(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    // Find the `#[auth_provider(backend = "...")]` attribute.
    let backend = input
        .attrs
        .iter()
        .find(|a| a.path().is_ident("auth_provider"))
        .and_then(|a| a.parse_args::<AuthProviderArgs>().ok())
        .map(|args| args.backend)
        .unwrap_or_else(|| "postgres".to_string());

    let (user_store, _session_store, error_ty, _store_mod) = match backend.as_str() {
        "sqlite" => (
            quote!(authsmith_db::sqlite::SqliteUserStore),
            quote!(authsmith_db::sqlite::SqliteSessionStore),
            quote!(authsmith_db::sqlite::SqliteError),
            quote!(authsmith_db::sqlite),
        ),
        _ => (
            quote!(authsmith_db::postgres::PgUserStore),
            quote!(authsmith_db::postgres::PgSessionStore),
            quote!(authsmith_db::postgres::PgError),
            quote!(authsmith_db::postgres),
        ),
    };

    let expanded = quote! {
        #[async_trait::async_trait]
        impl authsmith_core::AuthProvider for #name {
            type Error = #error_ty;

            async fn create_user(
                &self,
                input: authsmith_core::CreateUserInput,
            ) -> Result<authsmith_core::AuthUser, Self::Error> {
                #user_store::new(self.0.clone()).create_user(input).await
            }

            async fn find_user_by_id(
                &self,
                id: &str,
            ) -> Result<Option<authsmith_core::AuthUser>, Self::Error> {
                #user_store::new(self.0.clone()).find_user_by_id(id).await
            }

            async fn find_user_by_email(
                &self,
                email: &str,
            ) -> Result<Option<authsmith_core::AuthUser>, Self::Error> {
                #user_store::new(self.0.clone()).find_user_by_email(email).await
            }

            async fn update_user(
                &self,
                user: authsmith_core::AuthUser,
            ) -> Result<authsmith_core::AuthUser, Self::Error> {
                #user_store::new(self.0.clone()).update_user(user).await
            }

            async fn delete_user(&self, id: &str) -> Result<(), Self::Error> {
                #user_store::new(self.0.clone()).delete_user(id).await
            }

            async fn list_users(&self) -> Result<Vec<authsmith_core::AuthUser>, Self::Error> {
                #user_store::new(self.0.clone()).list_users().await
            }
        }
    };

    expanded.into()
}

// ── derive(SessionProvider) ───────────────────────────────────────────────────

/// Derive macro — generates a [`authsmith_core::SessionProvider`] impl that
/// delegates to the matching `authsmith-db` session store.
///
/// Apply the same `#[auth_provider(backend = "...")]` attribute as for
/// [`derive(AuthProvider)`].
///
/// ```rust,ignore
/// #[derive(SessionProvider)]
/// #[auth_provider(backend = "postgres")]
/// pub struct MySessionStore(sqlx::PgPool);
/// ```
#[proc_macro_derive(SessionProvider, attributes(auth_provider))]
pub fn derive_session_provider(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let backend = input
        .attrs
        .iter()
        .find(|a| a.path().is_ident("auth_provider"))
        .and_then(|a| a.parse_args::<AuthProviderArgs>().ok())
        .map(|args| args.backend)
        .unwrap_or_else(|| "postgres".to_string());

    let (session_store, error_ty) = match backend.as_str() {
        "sqlite" => (
            quote!(authsmith_db::sqlite::SqliteSessionStore),
            quote!(authsmith_db::sqlite::SqliteError),
        ),
        _ => (
            quote!(authsmith_db::postgres::PgSessionStore),
            quote!(authsmith_db::postgres::PgError),
        ),
    };

    let expanded = quote! {
        #[async_trait::async_trait]
        impl authsmith_core::SessionProvider for #name {
            type Error = #error_ty;

            async fn create_session(
                &self,
                user_id: &str,
                expires_at: i64,
                meta: authsmith_core::SessionMeta,
            ) -> Result<authsmith_core::Session, Self::Error> {
                #session_store::new(self.0.clone())
                    .create_session(user_id, expires_at, meta)
                    .await
            }

            async fn get_session(
                &self,
                token: &str,
            ) -> Result<Option<authsmith_core::Session>, Self::Error> {
                #session_store::new(self.0.clone()).get_session(token).await
            }

            async fn revoke_session(&self, token: &str) -> Result<(), Self::Error> {
                #session_store::new(self.0.clone()).revoke_session(token).await
            }

            async fn revoke_all_sessions(&self, user_id: &str) -> Result<(), Self::Error> {
                #session_store::new(self.0.clone())
                    .revoke_all_sessions(user_id)
                    .await
            }

            async fn list_sessions_for_user(
                &self,
                user_id: &str,
            ) -> Result<Vec<authsmith_core::Session>, Self::Error> {
                #session_store::new(self.0.clone())
                    .list_sessions_for_user(user_id)
                    .await
            }

            async fn list_all_sessions(
                &self,
            ) -> Result<Vec<authsmith_core::Session>, Self::Error> {
                #session_store::new(self.0.clone()).list_all_sessions().await
            }
        }
    };

    expanded.into()
}
