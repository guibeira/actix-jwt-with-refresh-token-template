use crate::config::Config;
use redis::Client as RedisClient;
use sqlx::migrate;

pub async fn get_db_conn(config: &Config) -> sqlx::postgres::PgPool {
    let postgres_host = config.postgres_host.clone();
    let postgres_port = config.postgres_port;
    let postgres_password = config.postgres_password.clone();
    let postgres_user = config.postgres_user.clone();
    let postgres_db = config.postgres_db.clone();

    let postgres_url = format!(
        "postgres://{postgres_user}:{postgres_password}@{postgres_host}:{postgres_port}/{postgres_db}"
    );
    let conn = sqlx::postgres::PgPool::connect(&postgres_url).await;
    let conn = match conn {
        Ok(conn) => {
            log::info!("sqlx connection success ✅");
            conn
        }
        Err(e) => {
            log::error!("sqlx connection error 🔥: {:?}", e);
            std::process::exit(1);
        }
    };

    if config.enable_auto_migrate {
        let migrate = migrate!("./migrations").run(&conn).await;
        match migrate {
            Ok(()) => log::info!("sqlx migration success ✅"),
            Err(e) => log::error!("sqlx migration error 🔥: {:?}", e),
        }
    } else {
        log::info!("Auto migration is disabled");
    }
    conn
}
pub async fn get_redis_conn(config: &Config) -> RedisClient {
    match RedisClient::open(config.redis_url.as_str()) {
        Ok(client) => {
            log::info!("Connection to the redis is successful! ✅");
            client
        }
        Err(e) => {
            println!("Error connecting to Redis🔥 : {}", e);
            std::process::exit(1);
        }
    }
}
