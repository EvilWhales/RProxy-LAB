pub mod recaptcha_enterprise;
pub mod recaptcha_v3;
pub mod recaptcha_v2;
pub mod turnstile;
pub mod friendly_captcha;
pub mod captchafox;

pub fn register_urls(cfg: &mut actix_web::web::ServiceConfig) {
    recaptcha_enterprise::urls::register_urls(cfg);
    recaptcha_v3::urls::register_urls(cfg);
    recaptcha_v2::urls::register_urls(cfg);
    turnstile::urls::register_urls(cfg);
    friendly_captcha::urls::register_urls(cfg);
    captchafox::urls::register_urls(cfg);
}