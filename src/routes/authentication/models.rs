use crate::repository::models::User;
use actix_web::{body::BoxBody, HttpRequest, HttpResponse, Responder};
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct LoginUserPayload {
    pub email: String,
    pub password: String,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UserResponse {
    pub id: uuid::Uuid,
    pub name: String,
    pub email: String,
    pub role: String,
    pub photo: String,
    pub provider: String,
    pub verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
impl Responder for UserResponse {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> actix_web::HttpResponse<Self::Body> {
        let body = serde_json::to_string(&self);
        match body {
            Ok(body) => HttpResponse::Ok()
                .content_type("application/json")
                .body(body),

            Err(e) => HttpResponse::InternalServerError()
                .content_type("application/json")
                .body(format!("{{\"error\": \"{}\"}}", e)),
        }
    }
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email.to_owned(),
            name: user.name.to_owned(),
            photo: user.photo.to_owned(),
            role: user.role.to_owned(),
            provider: user.provider.to_owned(),
            verified: user.verified,
            created_at: user.created_at.unwrap(),
            updated_at: user.updated_at.unwrap(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordPayload {
    pub token: Uuid,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterUserPayload {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize, Serialize)]
pub struct ResetPasswordRequest {
    pub email: String,
}
