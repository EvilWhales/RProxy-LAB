pub mod captchas;
pub mod landing_page;

pub fn register_urls(cfg: &mut actix_web::web::ServiceConfig) {
    captchas::register_urls(cfg);
    landing_page::urls::register_urls(cfg);
}