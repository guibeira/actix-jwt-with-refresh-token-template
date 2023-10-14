use actix_web::{
    http::{header::ContentType, StatusCode},
    HttpResponse, ResponseError,
};
use derive_more::{Display, Error};

/// errors visible by the user
#[derive(Debug, Display, Error, PartialEq)]
pub enum CustomError {
    #[display(fmt = "Bad Request: {}.", message)]
    BadRequest { message: String },
    #[display(fmt = "An internal error occurred. Please try again later.")]
    InternalError,
}

impl CustomError {
    pub fn convert_to_user_error(e: sqlx::Error) -> CustomError {
        match e {
            sqlx::Error::RowNotFound => CustomError::InternalError,
            sqlx::Error::ColumnDecode { .. } => CustomError::InternalError,
            sqlx::Error::Decode(_) => CustomError::InternalError,
            sqlx::Error::PoolTimedOut => CustomError::InternalError,
            sqlx::Error::PoolClosed => CustomError::InternalError,
            sqlx::Error::WorkerCrashed => CustomError::InternalError,
            #[cfg(feature = "migrate")]
            sqlx::Error::Migrate(_) => CustomError::InternalError,
            _ => CustomError::InternalError,
        }
    }
}

impl ResponseError for CustomError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::html())
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            CustomError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            CustomError::BadRequest { .. } => StatusCode::BAD_REQUEST,
        }
    }
}
impl From<sqlx::Error> for CustomError {
    fn from(e: sqlx::Error) -> CustomError {
        CustomError::convert_to_user_error(e)
    }
}
