use serde::Deserialize;

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct FriendlyCaptchaForm {
    pub username: String,
    pub password: String,
    #[serde(rename = "frc-captcha-solution")]
    pub frc_captcha_solution: String,
}
