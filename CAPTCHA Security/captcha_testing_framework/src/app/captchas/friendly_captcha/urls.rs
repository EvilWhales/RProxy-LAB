use actix_web::web;

use super::views;

pub fn register_urls(cfg: &mut web::ServiceConfig) {
    cfg.route("/friendly_captcha", web::get().to(views::friendly_captcha))
        .route(
            "/submit_friendly_captcha",
            web::post().to(views::submit_friendly_captcha),
        );
}
