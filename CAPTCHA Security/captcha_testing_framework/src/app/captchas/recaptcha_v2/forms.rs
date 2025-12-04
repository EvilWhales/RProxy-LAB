use serde::Deserialize;

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct RecaptchaV2Form {
    pub username: String,
    pub password: String,
    #[serde(rename = "g-recaptcha-response")]
    pub g_recaptcha_response: String,
}
