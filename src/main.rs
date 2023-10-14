use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use dotenv::dotenv;
use redis::Client as RedisClient;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
mod config;
mod db;
mod errors;
mod jobs;
mod jwt_auth_middleware;
mod repository;
mod routes;
mod token;
use crate::db::{get_db_conn, get_redis_conn};
use config::Config;

#[derive(Deserialize, Serialize)]
pub struct ResetPasswordRequest {
    pub email: String,
}

pub struct AppState {
    db: PgPool,
    env: Config,
    redis_client: RedisClient,
}
impl AppState {
    pub async fn new(env_config: &Config) -> Self {
        let db = get_db_conn(env_config).await;
        let redis_client = get_redis_conn(env_config).await;

        Self {
            db,
            env: env_config.clone(),
            redis_client,
        }
    }
}

async fn health_checker_handler() -> impl Responder {
    const MESSAGE: &str = "Up and running!";

    HttpResponse::Ok().json(serde_json::json!({"message": MESSAGE}))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    dotenv().ok();

    let email_sender = match jobs::persistent_jobs::start_processing_email_queue().await {
        Ok(email_sender) => email_sender,
        Err(e) => {
            log::error!("Error while starting email queue: {:?}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Error while starting email queue",
            ));
        }
    };

    let config = Config::init();
    let app_data = AppState::new(&config).await;
    let app_data = web::Data::new(app_data);

    HttpServer::new(move || {
        App::new()
            .app_data(app_data.clone())
            .app_data(web::Data::new(email_sender.clone()))
            .route("/health-checker", web::get().to(health_checker_handler))
            .service(web::scope("/api/v1").configure(routes::user_routes))
    })
    .bind(format!("{}:{}", config.host, config.port))?
    .run()
    .await?;

    Ok(())
}
