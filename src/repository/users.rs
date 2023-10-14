use super::models::User;
use crate::errors::CustomError;
use crate::routes::authentication::models::{
    LoginUserPayload, RegisterUserPayload, ResetPasswordPayload,
};
use crate::AppState;
use actix_web::{web, HttpResponse};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use redis::AsyncCommands;
use sqlx::Row;
use uuid::Uuid;

pub async fn create_user(
    body: RegisterUserPayload,
    db: &sqlx::postgres::PgPool,
) -> Result<User, CustomError> {
    let exists: bool = sqlx::query("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(body.email.to_owned())
        .fetch_one(db)
        .await
        .unwrap()
        .get(0);

    if exists {
        return Err(CustomError::BadRequest {
            message: "Email already exists".to_string(),
        });
    }

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .expect("Error while hashing password")
        .to_string();
    let query_result = sqlx::query_as!(
        User,
        "INSERT INTO users (name,email,password) VALUES ($1, $2, $3) RETURNING *",
        body.name.to_string(),
        body.email.to_string().to_lowercase(),
        hashed_password
    )
    .fetch_one(db)
    .await;
    match query_result {
        Ok(user) => Ok(user),
        Err(e) => {
            log::error!("Error creating user: {:?}", e);
            Err(CustomError::InternalError)
        }
    }
}

pub async fn get_user_and_check_password(
    body: LoginUserPayload,
    db: &sqlx::postgres::PgPool,
) -> Result<User, CustomError> {
    let user = get_user_by_email(&body, db).await?;
    let is_valid = check_user_password(user.clone(), body.password.to_owned()).await;
    if !is_valid {
        return Err(CustomError::BadRequest {
            message: "Invalid email or password".to_string(),
        });
    }
    Ok(user)
}

async fn check_user_password(user: User, password: String) -> bool {
    let user_password = user.password.to_owned().unwrap();
    PasswordHash::new(&user_password)
        .and_then(|parsed_hash| {
            Argon2::default().verify_password(password.as_bytes(), &parsed_hash)
        })
        .map_or(false, |_| true)
}

async fn get_user_by_email(
    body: &LoginUserPayload,
    db: &sqlx::postgres::PgPool,
) -> Result<User, CustomError> {
    let query_result = sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", body.email)
        .fetch_optional(db)
        .await
        .unwrap();

    let user = match query_result {
        Some(user) => user,
        None => {
            log::info!("User not found");
            return Err(CustomError::BadRequest {
                message: "Invalid email or password".to_string(),
            });
        }
    };
    if user.provider != "local" {
        log::info!("User uses {:?}, instead of local", user.provider);
        return Err(CustomError::BadRequest {
            message: "Invalid email or password".to_string(),
        });
    }

    Ok(user)
}
pub async fn save_tokens(
    data: &web::Data<AppState>,
    tokens: &crate::token::Tokens,
    user: User,
) -> Result<(), CustomError> {
    let mut redis_client = match data.redis_client.get_async_connection().await {
        Ok(redis_client) => redis_client,
        Err(e) => {
            log::error!("Error while getting redis connection: {:?}", e);
            return Err(CustomError::InternalError);
        }
    };
    let access_result: redis::RedisResult<()> = redis_client
        .set_ex(
            tokens.access_token.token_uuid.to_string(),
            user.id.to_string(),
            (data.env.access_token_max_age * 60) as usize,
        )
        .await;
    if let Err(e) = access_result {
        log::error!("Error while setting access token in Redis: {:?}", e);
        return Err(CustomError::InternalError);
    }
    let refresh_result: redis::RedisResult<()> = redis_client
        .set_ex(
            tokens.refresh_token.token_uuid.to_string(),
            user.id.to_string(),
            (data.env.refresh_token_max_age * 60) as usize,
        )
        .await;

    if let Err(e) = refresh_result {
        log::error!("Error while setting refresh token in Redis: {:?}", e);
        return Err(CustomError::InternalError);
    }
    Ok(())
}

pub async fn get_user_by_id(user_uuid: Uuid, db: &sqlx::postgres::PgPool) -> Option<User> {
    sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_uuid)
        .fetch_optional(db)
        .await
        .unwrap()
}

pub async fn get_user_id_from_redis(
    redis_client: &mut redis::aio::Connection,
    refresh_token_details: crate::token::TokenDetails,
    message: &str,
) -> Result<Uuid, HttpResponse> {
    let redis_result: redis::RedisResult<String> = redis_client
        .get(refresh_token_details.token_uuid.to_string())
        .await;
    let user_id = match redis_result {
        Ok(value) => value,
        Err(_) => {
            log::error!("Error while getting user id from Redis");
            return Err(HttpResponse::Forbidden()
                .json(serde_json::json!({"status": "fail", "message": message})));
        }
    };
    let user_id_uuid = match Uuid::parse_str(&user_id) {
        Ok(user_id_uuid) => user_id_uuid,
        Err(_) => {
            log::error!("Error while parsing user id from Redis");
            return Err(HttpResponse::Forbidden()
                .json(serde_json::json!({"status": "fail", "message": message})));
        }
    };
    Ok(user_id_uuid)
}

pub async fn update_user_password(
    payload: web::Json<ResetPasswordPayload>,
    user: User,
    db: &sqlx::postgres::PgPool,
) -> Result<(), actix_web::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(payload.new_password.as_bytes(), &salt)
        .expect("Error while hashing password")
        .to_string();
    let query_result = sqlx::query!(
        "UPDATE users SET password = $1, password_reset_token = NULL, password_reset_token_expires_at = NULL WHERE id = $2",
        hashed_password,
        user.id
    ).execute(db).await;

    if query_result.is_err() {
        log::error!(
            "Error while updating password: {:?}",
            query_result.err().unwrap()
        );
        return Err(actix_web::error::ErrorInternalServerError(
            "Internal server error",
        ));
    }
    Ok(())
}

pub async fn get_user_by_reset_token(
    token: uuid::Uuid,
    conn: &sqlx::Pool<sqlx::Postgres>,
) -> Result<User, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"
        SELECT * FROM users WHERE password_reset_token = $1
        "#,
        token
    )
    .fetch_one(conn)
    .await
}

pub async fn save_token_in_redis(
    mut redis_client: redis::aio::Connection,
    access_token_details: &crate::token::TokenDetails,
    user: User,
    data: &web::Data<AppState>,
) -> Result<(), HttpResponse> {
    let redis_result: redis::RedisResult<()> = redis_client
        .set_ex(
            access_token_details.token_uuid.to_string(),
            user.id.to_string(),
            (data.env.access_token_max_age * 60) as usize,
        )
        .await;

    if redis_result.is_err() {
        return Err(HttpResponse::UnprocessableEntity().json(
            serde_json::json!({"status": "error", "message": format_args!("{:?}", redis_result.unwrap_err())}),
        ));
    }
    Ok(())
}
