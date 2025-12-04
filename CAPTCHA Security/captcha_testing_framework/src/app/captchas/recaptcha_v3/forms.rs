use serde::Deserialize;

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct RecaptchaV3Form {
    pub username: String,
    pub password: String,
    #[serde(rename = "g-recaptcha-response")]
    pub recaptcha_token: String,
}
