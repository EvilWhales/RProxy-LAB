use actix_web::web;

use super::views;

pub fn register_urls(cfg: &mut web::ServiceConfig) {
    cfg.route("/turnstile", web::get().to(views::turnstile))
        .route("/submit_turnstile", web::post().to(views::submit_turnstile));
}
