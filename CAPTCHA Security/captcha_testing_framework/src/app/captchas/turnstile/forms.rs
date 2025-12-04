use serde::Deserialize;

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct TurnstileForm {
    pub username: String,
    pub password: String,
    #[serde(rename = "cf-turnstile-response")]
    pub cf_turnstile_response: String,
}
