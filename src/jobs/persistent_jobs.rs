use crate::config;
use crate::db::get_db_conn;
use crate::jobs::email::{Email, UserEmail};
use crate::repository::models::User;
use crate::routes::authentication::models::ResetPasswordRequest;
use apalis::{prelude::*, redis::RedisStorage};
use uuid::Uuid;

impl Job for ResetPasswordRequest {
    const NAME: &'static str = "send_email";
}

async fn process_email_job(
    email: ResetPasswordRequest,
    _ctx: JobContext,
) -> anyhow::Result<(), JobError> {
    log::info!("sending email to {:?}", &email.email);
    let config = config::Config::init();

    let conn = get_db_conn(&config).await;
    // check if user exists
    let query_result = sqlx::query_as!(
        User,
        r#"
        SELECT * FROM users WHERE email = $1
        "#,
        email.email
    )
    .fetch_one(&conn)
    .await;

    match query_result {
        Ok(user) => {
            // check the provider
            if user.provider != "local" {
                log::info!("User {} is not a local user", user.email);
                return Ok(());
            }
            log::info!("Sending email to {}", user.email);
            let user_email = UserEmail {
                name: user.name,
                email: user.email,
            };

            let token = Uuid::new_v4();
            let token_expire_date_time = chrono::Utc::now() + chrono::Duration::minutes(10);

            let query_result = sqlx::query!(
                r#"
                    UPDATE users 
                    SET password_reset_token = $1, password_reset_token_expires_at = $2 
                    WHERE email = $3
            "#,
                token,
                token_expire_date_time,
                user_email.email,
            )
            .execute(&conn)
            .await;

            if query_result.is_err() {
                log::error!(
                    "Error updating password reset token: {}",
                    query_result.err().unwrap()
                );
                return Ok(());
            }
            let url = format!("{}/reset-password/{}", config.client_origin.clone(), token);
            let email = Email::new(user_email, url, config);
            //let _ = email.send_verification_code().await;
            let _ = email.send_password_reset_token().await;
        }
        Err(e) => {
            log::error!("Error query user by email: {}", e);
        }
    }
    Ok(())
}

pub(crate) async fn start_processing_email_queue(
) -> anyhow::Result<RedisStorage<ResetPasswordRequest>> {
    let redis_url = std::env::var("REDIS_URL").expect("Missing env variable REDIS_URL");
    let storage = RedisStorage::connect(redis_url).await?;
    log::info!("Connected to redis");
    log::info!("Starting email job handler");

    // create job monitor(s) and attach email job handler
    let monitor = Monitor::new().register_with_count(2, {
        let storage = storage.clone();
        move |n| {
            WorkerBuilder::new(format!("job-handler-{n}"))
                .with_storage(storage.clone())
                .build_fn(process_email_job)
        }
    });

    // spawn job monitor into background
    // the monitor manages itself otherwise so we don't need to return a join handle
    #[allow(clippy::let_underscore_future)]
    let _ = tokio::spawn(monitor.run());

    Ok(storage)
}
