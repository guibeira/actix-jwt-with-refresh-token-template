use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, FromRow, Serialize, Clone)]
pub struct User {
    pub id: uuid::Uuid,
    pub name: String,
    pub email: String,
    pub password: Option<String>,
    pub role: String,
    pub photo: String,
    pub provider: String,
    pub verified: bool,
    pub password_reset_token: Option<uuid::Uuid>,
    pub password_reset_token_expires_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}
