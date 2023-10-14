use actix_web::{
    cookie::{time::Duration as ActixWebDuration, Cookie},
    web, HttpRequest, HttpResponse, Responder,
};
use apalis::{prelude::*, redis::RedisStorage};
use chrono::Utc;
use redis::AsyncCommands;

use super::models::{
    LoginUserPayload, RegisterUserPayload, ResetPasswordPayload, ResetPasswordRequest, UserResponse,
};
use crate::errors::CustomError;
use crate::jwt_auth_middleware::JwtMiddleware;
use crate::repository::users;
use crate::token::{generate_jwt_token, generate_tokens, verify_jwt_token};
use crate::AppState;

pub async fn register_user_handler(
    body: web::Json<RegisterUserPayload>,
    data: web::Data<AppState>,
) -> Result<HttpResponse, CustomError> {
    let db = &data.db;
    let query_result = users::create_user(body.into_inner(), db).await;

    match query_result {
        Ok(user) => Ok(HttpResponse::Created().json(Into::<UserResponse>::into(user))),
        Err(e) => Err(e),
    }
}

pub async fn login_user_handler(
    body: web::Json<LoginUserPayload>,
    data: web::Data<AppState>,
) -> Result<impl Responder, CustomError> {
    let db = &data.db;
    let user = users::get_user_and_check_password(body.into_inner(), db).await?;

    let tokens = match generate_tokens(user.clone(), &data.env) {
        Ok(tokens) => tokens,
        Err(e) => {
            log::error!("Error while generating tokens: {:?}", e);
            return Err(CustomError::InternalError);
        }
    };

    users::save_tokens(&data, &tokens, user).await?;

    let access_cookie = Cookie::build("access_token", tokens.access_token.token.clone().unwrap())
        .path("/")
        .max_age(ActixWebDuration::new(data.env.access_token_max_age * 60, 0))
        .http_only(true)
        .finish();
    let refresh_cookie = Cookie::build("refresh_token", tokens.refresh_token.token.unwrap())
        .path("/")
        .max_age(ActixWebDuration::new(
            data.env.refresh_token_max_age * 60,
            0,
        ))
        .http_only(true)
        .finish();
    let logged_in_cookie = Cookie::build("logged_in", "true")
        .path("/")
        .max_age(ActixWebDuration::new(data.env.access_token_max_age * 60, 0))
        .http_only(false)
        .finish();

    Ok(HttpResponse::Ok()
        .cookie(access_cookie)
        .cookie(refresh_cookie)
        .cookie(logged_in_cookie)
        .json(serde_json::json!({"access_token": tokens.access_token.token.unwrap()})))
}

pub async fn get_me_handler(jwt_guard: JwtMiddleware) -> UserResponse {
    jwt_guard.user.into()
}

pub async fn logout_handler(
    req: HttpRequest,
    auth_guard: JwtMiddleware,
    data: web::Data<AppState>,
) -> Result<HttpResponse, CustomError> {
    let message = "Token is invalid or session has expired";

    let refresh_token = match req.cookie("refresh_token") {
        Some(c) => c.value().to_string(),
        None => {
            return Err(CustomError::BadRequest {
                message: message.to_string(),
            });
        }
    };

    let refresh_token_details =
        match verify_jwt_token(data.env.refresh_token_public_key.to_owned(), &refresh_token) {
            Ok(token_details) => token_details,
            Err(e) => {
                log::error!("Error while verifying refresh token: {:?}", e);
                return Err(CustomError::BadRequest {
                    message: message.to_string(),
                });
            }
        };

    let mut redis_client = data.redis_client.get_async_connection().await.unwrap();
    let redis_result: redis::RedisResult<usize> = redis_client
        .del(&[
            refresh_token_details.token_uuid.to_string(),
            auth_guard.access_token_uuid.to_string(),
        ])
        .await;

    if redis_result.is_err() {
        log::error!(
            "Error while deleting tokens from Redis: {:?}",
            redis_result.unwrap_err()
        );
        return Err(CustomError::InternalError);
    }

    let access_cookie = Cookie::build("access_token", "")
        .path("/")
        .max_age(ActixWebDuration::new(-1, 0))
        .http_only(true)
        .finish();
    let refresh_cookie = Cookie::build("refresh_token", "")
        .path("/")
        .max_age(ActixWebDuration::new(-1, 0))
        .http_only(true)
        .finish();
    let logged_in_cookie = Cookie::build("logged_in", "")
        .path("/")
        .max_age(ActixWebDuration::new(-1, 0))
        .http_only(true)
        .finish();

    Ok(HttpResponse::Ok()
        .cookie(access_cookie)
        .cookie(refresh_cookie)
        .cookie(logged_in_cookie)
        .json(serde_json::json!({"status": "success"})))
}

pub async fn refresh_access_token_handler(
    req: HttpRequest,
    data: web::Data<AppState>,
) -> Result<HttpResponse, CustomError> {
    let message = "could not refresh access token";

    let refresh_token = match req.cookie("refresh_token") {
        Some(c) => c.value().to_string(),
        None => {
            log::error!("Refresh token not found");
            return Err(CustomError::BadRequest {
                message: message.to_string(),
            });
        }
    };

    let refresh_token_details =
        match verify_jwt_token(data.env.refresh_token_public_key.to_owned(), &refresh_token) {
            Ok(token_details) => token_details,
            Err(e) => {
                log::error!("Error while verifying refresh token: {:?}", e);
                return Err(CustomError::BadRequest {
                    message: message.to_string(),
                });
            }
        };

    let result = data.redis_client.get_async_connection().await;
    let mut redis_client = match result {
        Ok(redis_client) => redis_client,
        Err(e) => {
            log::error!("Error while getting redis connection: {:?}", e);
            return Err(CustomError::InternalError);
        }
    };

    let user_uuid =
        users::get_user_id_from_redis(&mut redis_client, refresh_token_details, message).await;
    let user_uuid = match user_uuid {
        Ok(user_uuid) => user_uuid,
        Err(_) => {
            return Err(CustomError::BadRequest {
                message: "Invalid token".to_string(),
            });
        }
    };

    let query_result = users::get_user_by_id(user_uuid, &data.db).await;

    if query_result.is_none() {
        log::error!("User not found");
        return Err(CustomError::BadRequest {
            message: message.to_string(),
        });
    }

    let user = query_result.unwrap();

    let access_token_details = match generate_jwt_token(
        user.id,
        data.env.access_token_max_age,
        data.env.access_token_private_key.to_owned(),
    ) {
        Ok(token_details) => token_details,
        Err(e) => {
            log::error!("Error while generating access token: {:?}", e);
            return Err(CustomError::InternalError);
        }
    };

    let access_cookie = Cookie::build("access_token", access_token_details.token.clone().unwrap())
        .path("/")
        .max_age(ActixWebDuration::new(data.env.access_token_max_age * 60, 0))
        .http_only(true)
        .finish();

    let logged_in_cookie = Cookie::build("logged_in", "true")
        .path("/")
        .max_age(ActixWebDuration::new(data.env.access_token_max_age * 60, 0))
        .http_only(false)
        .finish();

    Ok(HttpResponse::Ok()
        .cookie(access_cookie)
        .cookie(logged_in_cookie)
        .json(serde_json::json!({"status": "success", "access_token": access_token_details.token.unwrap()})))
}

pub async fn reset_password_handler(
    payload: web::Json<ResetPasswordPayload>,
    data: web::Data<AppState>,
) -> actix_web::Result<impl Responder> {
    let db = data.db.clone();
    let token = payload.token;

    let user = match users::get_user_by_reset_token(token, &db).await {
        Ok(user) => user,
        Err(e) => {
            log::error!("Error while getting user by reset token: {:?}", e);
            return Err(actix_web::error::ErrorBadRequest("Invalid token"));
        }
    };

    match user.password_reset_token_expires_at {
        Some(expires_at) => {
            if expires_at < Utc::now() {
                return Err(actix_web::error::ErrorBadRequest("Token expired"));
            }
        }
        None => {
            return Err(actix_web::error::ErrorBadRequest("Invalid token"));
        }
    }

    users::update_user_password(payload, user, &db).await?;

    Ok(HttpResponse::Accepted())
}

pub async fn email_reset_password_handler(
    email: web::Json<ResetPasswordRequest>,
    sender: web::Data<RedisStorage<ResetPasswordRequest>>,
) -> Result<HttpResponse, CustomError> {
    let req_email = ResetPasswordRequest {
        email: email.email.to_owned(),
    };
    log::info!("Sending reset password email to queue: {}", email.email);

    let mut sender = (**sender).clone();
    let push_msg = sender.push(req_email).await;

    if push_msg.is_err() {
        log::error!("Failed to push email to queue: {}", push_msg.err().unwrap());
        return Err(CustomError::InternalError);
    }

    Ok(HttpResponse::Accepted().json(serde_json::json!({"status": "success"})))
}
