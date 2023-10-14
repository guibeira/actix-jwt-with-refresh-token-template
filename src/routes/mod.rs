use actix_web::web;
pub mod authentication;
use crate::routes::authentication::routes as user_routes;

pub fn user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .service(
                web::resource("/register")
                    .route(web::post().to(user_routes::register_user_handler)),
            )
            .service(web::resource("/me").route(web::get().to(user_routes::get_me_handler)))
            .service(web::resource("/logout").route(web::get().to(user_routes::logout_handler)))
            .service(
                web::resource("/refresh")
                    .route(web::get().to(user_routes::refresh_access_token_handler)),
            )
            .service(
                web::resource("/reset-password/")
                    .route(web::post().to(user_routes::reset_password_handler)),
            )
            .service(
                web::resource("/forgot-password")
                    .route(web::post().to(user_routes::email_reset_password_handler)),
            )
            .service(
                web::resource("/login").route(web::post().to(user_routes::login_user_handler)),
            ),
    );
}
