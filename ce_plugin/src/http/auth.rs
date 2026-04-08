use std::collections::HashMap;

#[derive(Debug, Clone, Copy)]
pub enum AuthError {
    MissingAuthorization,
    InvalidAuthorizationScheme,
    InvalidToken,
}

impl AuthError {
    pub fn status(self) -> &'static str {
        match self {
            Self::MissingAuthorization | Self::InvalidAuthorizationScheme => "401 Unauthorized",
            Self::InvalidToken => "403 Forbidden",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::MissingAuthorization => "missing bearer token",
            Self::InvalidAuthorizationScheme => "authorization must use Bearer scheme",
            Self::InvalidToken => "invalid bearer token",
        }
    }
}

pub fn extract_bearer_token(headers: &HashMap<String, String>) -> Result<String, AuthError> {
    let Some(value) = headers.get("authorization") else {
        return Err(AuthError::MissingAuthorization);
    };

    let Some(token) = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
    else {
        return Err(AuthError::InvalidAuthorizationScheme);
    };

    let token = token.trim();
    if token.is_empty() {
        return Err(AuthError::MissingAuthorization);
    }

    Ok(token.to_owned())
}

pub fn authorize_request(
    headers: &HashMap<String, String>,
    expected_token: Option<&str>,
) -> Result<(), AuthError> {
    let Some(expected_token) = expected_token.filter(|token| !token.trim().is_empty()) else {
        return Err(AuthError::InvalidToken);
    };

    let actual = extract_bearer_token(headers)?;
    if actual == expected_token {
        Ok(())
    } else {
        Err(AuthError::InvalidToken)
    }
}
