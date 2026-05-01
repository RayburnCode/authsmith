use async_trait::async_trait;
use authsmith_core::{
    session::{now_secs, SecureTokenGenerator},
    AuthProvider, AuthUser, CreateUserInput, Session, SessionMeta, SessionProvider, TokenGenerator,
};
use std::{collections::HashMap, sync::Mutex};

#[derive(Debug, thiserror::Error)]
#[error("store error")]
pub struct StoreError;

pub struct MemUserStore {
    inner: Mutex<HashMap<String, (AuthUser, Option<String>)>>,
    id_gen: SecureTokenGenerator,
}

impl Default for MemUserStore {
    fn default() -> Self {
        Self { inner: Mutex::default(), id_gen: SecureTokenGenerator::default() }
    }
}

impl MemUserStore {
    pub fn password_hash_for(&self, email: &str) -> Option<String> {
        self.inner
            .lock()
            .ok()?
            .values()
            .find(|(u, _)| u.email.as_deref() == Some(email))
            .and_then(|(_, h)| h.clone())
    }
}

#[async_trait]
impl AuthProvider for MemUserStore {
    type Error = StoreError;

    async fn create_user(&self, input: CreateUserInput) -> Result<AuthUser, Self::Error> {
        let mut store = self.inner.lock().map_err(|_| StoreError)?;
        let now = now_secs();
        let user = AuthUser {
            id: self.id_gen.generate(),
            email: input.email,
            peer_id: input.peer_id,
            tenant_id: input.tenant_id,
            roles: input.roles,
            metadata: input.metadata,
            email_verified: false,
            banned: false,
            created_at: now,
            updated_at: now,
        };
        store.insert(user.id.clone(), (user.clone(), input.password_hash));
        Ok(user)
    }

    async fn find_user_by_id(&self, id: &str) -> Result<Option<AuthUser>, Self::Error> {
        Ok(self.inner.lock().map_err(|_| StoreError)?.get(id).map(|(u, _)| u.clone()))
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, Self::Error> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| StoreError)?
            .values()
            .find(|(u, _)| u.email.as_deref() == Some(email))
            .map(|(u, _)| u.clone()))
    }

    async fn update_user(&self, user: AuthUser) -> Result<AuthUser, Self::Error> {
        if let Some(entry) = self.inner.lock().map_err(|_| StoreError)?.get_mut(&user.id) {
            entry.0 = user.clone();
        }
        Ok(user)
    }

    async fn delete_user(&self, id: &str) -> Result<(), Self::Error> {
        self.inner.lock().map_err(|_| StoreError)?.remove(id);
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<AuthUser>, Self::Error> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| StoreError)?
            .values()
            .map(|(u, _)| u.clone())
            .collect())
    }
}

#[derive(Default)]
pub struct MemSessionStore {
    sessions: Mutex<HashMap<String, Session>>,
    token_gen: SecureTokenGenerator,
}

#[async_trait]
impl SessionProvider for MemSessionStore {
    type Error = StoreError;

    async fn create_session(
        &self,
        user_id: &str,
        expires_at: i64,
        meta: SessionMeta,
    ) -> Result<Session, Self::Error> {
        let session = Session {
            token: self.token_gen.generate(),
            user_id: user_id.to_string(),
            tenant_id: meta.tenant_id,
            expires_at,
            ip_address: meta.ip_address,
            user_agent: meta.user_agent,
            created_at: now_secs(),
        };
        self.sessions
            .lock()
            .map_err(|_| StoreError)?
            .insert(session.token.clone(), session.clone());
        Ok(session)
    }

    async fn get_session(&self, token: &str) -> Result<Option<Session>, Self::Error> {
        Ok(self.sessions.lock().map_err(|_| StoreError)?.get(token).cloned())
    }

    async fn revoke_session(&self, token: &str) -> Result<(), Self::Error> {
        self.sessions.lock().map_err(|_| StoreError)?.remove(token);
        Ok(())
    }

    async fn revoke_all_sessions(&self, user_id: &str) -> Result<(), Self::Error> {
        self.sessions.lock().map_err(|_| StoreError)?.retain(|_, s| s.user_id != user_id);
        Ok(())
    }

    async fn list_sessions_for_user(&self, user_id: &str) -> Result<Vec<Session>, Self::Error> {
        Ok(self
            .sessions
            .lock()
            .map_err(|_| StoreError)?
            .values()
            .filter(|s| s.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn list_all_sessions(&self) -> Result<Vec<Session>, Self::Error> {
        Ok(self.sessions.lock().map_err(|_| StoreError)?.values().cloned().collect())
    }
}
