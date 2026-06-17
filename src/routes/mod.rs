use rocket::get;
use rocket_okapi::openapi;

pub mod authorization;
pub mod authzen;
pub mod data;
pub mod policies;
pub mod schema;

#[openapi]
#[get("/")]
pub async fn health() -> &'static str {
    "ok"
}
