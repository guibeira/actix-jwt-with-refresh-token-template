fn get_env_var(var_name: &str) -> String {
    std::env::var(var_name).unwrap_or_else(|_| panic!("{} must be set", var_name))
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Config {
    pub host: String,
    pub port: String,

    pub postgres_host: String,
    pub postgres_port: u16,
    pub postgres_password: String,
    pub postgres_user: String,
    pub postgres_db: String,
    pub enable_auto_migrate: bool,

    pub redis_url: String,
    pub client_origin: String,

    pub access_token_private_key: String,
    pub access_token_public_key: String,
    pub access_token_expires_in: String,
    pub access_token_max_age: i64,

    pub refresh_token_private_key: String,
    pub refresh_token_public_key: String,
    pub refresh_token_expires_in: String,
    pub refresh_token_max_age: i64,

    // oauth stuff
    pub jwt_secret: String,
    pub jwt_expires_in: String,
    pub jwt_max_age: i64,

    // email stuff
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_pass: String,
    pub smtp_from: String,
    pub smtp_to: String,
}

impl Config {
    pub fn init() -> Config {
        let host = std::env::var("HOST").unwrap_or("0.0.0.0".to_string());
        let port = std::env::var("PORT").unwrap_or("8000".to_string());

        let postgres_host = get_env_var("POSTGRES_HOST");
        let postgres_port = get_env_var("POSTGRES_PORT").parse::<u16>().unwrap();
        let postgres_password = get_env_var("POSTGRES_PASSWORD");
        let postgres_user = get_env_var("POSTGRES_USER");
        let postgres_db = get_env_var("POSTGRES_DB");
        let enable_auto_migrate = std::env::var("ENABLE_AUTO_MIGRATE")
            .unwrap_or("true".to_string())
            .parse::<bool>()
            .unwrap();

        let redis_url = get_env_var("REDIS_URL");
        let client_origin = get_env_var("CLIENT_ORIGIN");

        let access_token_private_key = get_env_var("ACCESS_TOKEN_PRIVATE_KEY");
        let access_token_public_key = get_env_var("ACCESS_TOKEN_PUBLIC_KEY");
        let access_token_expires_in = get_env_var("ACCESS_TOKEN_EXPIRED_IN");
        let access_token_max_age = get_env_var("ACCESS_TOKEN_MAXAGE");

        let refresh_token_private_key = get_env_var("REFRESH_TOKEN_PRIVATE_KEY");
        let refresh_token_public_key = get_env_var("REFRESH_TOKEN_PUBLIC_KEY");
        let refresh_token_expires_in = get_env_var("REFRESH_TOKEN_EXPIRED_IN");
        let refresh_token_max_age = get_env_var("REFRESH_TOKEN_MAXAGE");

        let jwt_secret = get_env_var("JWT_SECRET");
        let jwt_expires_in = get_env_var("TOKEN_EXPIRED_IN");
        let jwt_max_age = get_env_var("TOKEN_MAXAGE");

        let smtp_host = std::env::var("SMTP_HOST").expect("SMTP_HOST must be set");
        let smtp_port = std::env::var("SMTP_PORT").expect("SMTP_PORT must be set");
        let smtp_user = std::env::var("SMTP_USER").expect("SMTP_USER must be set");
        let smtp_pass = std::env::var("SMTP_PASS").expect("SMTP_PASS must be set");
        let smtp_from = std::env::var("SMTP_FROM").expect("SMTP_FROM must be set");
        let smtp_to = std::env::var("SMTP_TO").expect("SMTP_TO must be set");

        Config {
            host,
            port,

            postgres_host,
            postgres_port,
            postgres_password,
            postgres_user,
            postgres_db,
            enable_auto_migrate,

            redis_url,

            client_origin,
            access_token_private_key,
            access_token_public_key,
            refresh_token_private_key,
            refresh_token_public_key,
            access_token_expires_in,
            refresh_token_expires_in,
            access_token_max_age: access_token_max_age.parse::<i64>().unwrap(),
            refresh_token_max_age: refresh_token_max_age.parse::<i64>().unwrap(),

            jwt_secret,
            jwt_expires_in,
            jwt_max_age: jwt_max_age.parse::<i64>().unwrap(),

            smtp_host,
            smtp_pass,
            smtp_user,
            smtp_port: smtp_port.parse::<u16>().unwrap(),
            smtp_from,
            smtp_to,
        }
    }
}
