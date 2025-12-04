use actix_web::web;

use super::views;

pub fn register_urls(cfg: &mut web::ServiceConfig) {
    cfg.route("/", web::get().to(views::landing_page));
}