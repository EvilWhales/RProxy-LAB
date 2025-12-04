use actix_web::web;

use super::views;

pub fn register_urls(cfg: &mut web::ServiceConfig) {
    cfg.route("/captcha_fox", web::get().to(views::captcha_fox))
        .route(
            "/submit_captcha_fox",
            web::post().to(views::submit_captcha_fox),
        );
}
