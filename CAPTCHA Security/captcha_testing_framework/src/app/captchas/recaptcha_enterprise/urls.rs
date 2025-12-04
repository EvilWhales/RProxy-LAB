use actix_web::web;

use super::views;

pub fn register_urls(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/recaptcha_enterprise",
        web::get().to(views::recaptcha_enterprise),
    )
    .route(
        "/submit_recaptcha_enterprise",
        web::post().to(views::submit_recaptcha_enterprise),
    );
}
