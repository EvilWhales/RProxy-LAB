use actix_web::web;

use super::views;

pub fn register_urls(cfg: &mut web::ServiceConfig) {
    cfg.route("/recaptcha_v2", web::get().to(views::recaptcha_v2))
        .route(
            "/submit_recaptcha_v2",
            web::post().to(views::submit_recaptcha_v2),
        );
}
