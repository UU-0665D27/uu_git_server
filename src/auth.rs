use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::LazyLock};
use tracing::{debug, info, warn};

/// Структура пользователя, хранящаяся в отдельном JSON-файле.
/// Теперь дополнительно хранит список разрешённых SSH-ключей.
#[derive(Debug, Deserialize, Serialize)]
pub struct User {
    pub username: String,
    pub password_hash: String,
    /// Список публичных SSH-ключей в формате OpenSSH (например "ssh-ed25519 AAAA...")
    #[serde(default)]
    pub public_keys: Vec<String>,
}
/// Валидный argon2-хэш от произвольного пароля, используется только
/// чтобы выравнять время ответа, когда пользователь не найден.
static DUMMY_HASH: LazyLock<String> = LazyLock::new(|| {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(b"dummy-password-for-timing-safety", &salt)
        .expect("dummy hash generation must not fail")
        .to_string()
});

impl User {
    /// Загружает пользователя из файла <username>.json в указанной директории
    pub fn load(username: &str, users_dir: &Path) -> Option<Self> {
        // Защита от path traversal
        if username.contains('/') || username.contains('\\') {
            return None;
        }

        let path = users_dir.join(format!("{}.json", username));
        match std::fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).ok(),
            Err(_) => None,
        }
    }

    /// Проверяет пароль с помощью Argon2.
    ///
    /// Принимает `Option<&Self>`, а не `&self`, чтобы даже при отсутствующем
    /// пользователе выполнялась полноценная Argon2-верификация против
    /// фиктивного хэша — это не позволяет злоумышленнику отличить
    /// "юзера нет" от "пароль неверный" по времени ответа.
    pub fn verify_password(user: Option<&Self>, password: &str) -> bool {
        let hash_str = match user {
            Some(u) => &u.password_hash,
            None => &DUMMY_HASH,
        };

        let parsed_hash = match PasswordHash::new(hash_str) {
            Ok(h) => h,
            Err(e) => {
                warn!("Failed to parse password hash: {e}");
                return false;
            }
        };

        let result = Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok();

        // если юзера не было — всегда false, даже если бы фиктивный хэш
        // случайно совпал с введённым паролем
        user.is_some() && result
    }

    pub(crate) fn verify_public_key(&self, public_key: &russh::keys::PublicKey) -> bool {
        let incoming = match public_key.to_openssh() {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "Failed to convert SSH public key to OpenSSH format for user '{}': {}",
                    self.username, e
                );
                return false;
            }
        };

        info!(
            "Incoming SSH key for user '{}': {}",
            self.username,
            incoming.trim()
        );

        let incoming_norm = normalize_public_key(&incoming);

        if self.public_keys.is_empty() {
            info!(
                "User '{}' has no authorized SSH keys configured",
                self.username
            );
        } else {
            info!(
                "User '{}' has {} authorized SSH key(s)",
                self.username,
                self.public_keys.len()
            );
            for stored in &self.public_keys {
                debug!("Stored key for user '{}': {}", self.username, stored.trim());
            }
        }

        let result = self.public_keys.iter().any(|stored| {
            let stored_norm = normalize_public_key(stored);
            match (stored_norm, incoming_norm) {
                (Some((t1, d1)), Some((t2, d2))) => t1 == t2 && d1 == d2,
                _ => false,
            }
        });

        if result {
            info!("SSH public key accepted for user '{}'", self.username);
        } else {
            warn!(
                "SSH public key rejected for user '{}': no matching key found",
                self.username
            );
        }

        result
    }
}

/// Данные, извлеченные из заголовка Basic Auth
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

/// Кастомный экстрактор Axum для Basic Authentication
impl<S> FromRequestParts<S> for BasicAuth
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok());

        let Some(auth_header) = auth_header else {
            return Err(unauthorized_response());
        };

        if !auth_header.starts_with("Basic ") {
            return Err(unauthorized_response());
        }

        let base64_credentials = &auth_header[6..];
        let decoded =
            match base64::Engine::decode(&base64::prelude::BASE64_STANDARD, base64_credentials) {
                Ok(d) => d,
                Err(_) => return Err(unauthorized_response()),
            };

        let credentials = match String::from_utf8(decoded) {
            Ok(c) => c,
            Err(_) => return Err(unauthorized_response()),
        };

        let mut parts = credentials.splitn(2, ':');
        let username = parts.next().unwrap_or("").to_string();
        let password = parts.next().unwrap_or("").to_string();

        if username.is_empty() {
            return Err(unauthorized_response());
        }

        Ok(BasicAuth { username, password })
    }
}

/// Формирует стандартный ответ 401 для Git-клиентов
pub fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            axum::http::header::WWW_AUTHENTICATE,
            "Basic realm=\"Git Server\"",
        )],
        "Unauthorized",
    )
        .into_response()
}
/// Нормализует строку ключа: возвращает кортеж (тип_ключа, base64_данные)
fn normalize_public_key(s: &str) -> Option<(&str, &str)> {
    let mut parts = s.split_whitespace();
    let key_type = parts.next()?;
    let key_data = parts.next()?;
    Some((key_type, key_data))
}
