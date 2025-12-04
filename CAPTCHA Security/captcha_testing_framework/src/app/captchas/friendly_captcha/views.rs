use actix_web::{web, HttpResponse, Result};
use dotenv::dotenv;
use reqwest::Client;
use tera::{Context, Tera};

use super::forms::FriendlyCaptchaForm;

pub async fn friendly_captcha(tera: web::Data<Tera>) -> Result<HttpResponse> {
    dotenv().ok();

    let mut context = Context::new();
    match std::env::var("FRIENDLY_CAPTCHA_SITE_KEY") {
        Ok(sitekey) => {
            context.insert("site_key", &sitekey);

            let rendered = tera
                .render("captchas/friendly_captcha.html", &context)
                .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

            Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
        }
        Err(e) => {
            eprintln!("Environment variable error: {:?}", e);
            Ok(HttpResponse::InternalServerError()
                .body("Internal server error: FRIENDLY_CAPTCHA_SITE_KEY not found"))
        }
    }
}

pub async fn submit_friendly_captcha(
    post_data: web::Form<FriendlyCaptchaForm>,
) -> Result<HttpResponse> {
    // Check env
    dotenv().ok();

    // Load API key
    let secret_key = match std::env::var("FRIENDLY_CAPTCHA_SECRET_KEY") {
        Ok(key) => key,
        Err(_) => {
            return Ok(HttpResponse::InternalServerError()
                .body("FRIENDLY_CAPTCHA_SECRET_KEY is not set in environment."))
        }
    };

    // Send post request to api endpoint
    let client = Client::new();
    let response = client
        .post("https://api.friendlycaptcha.com/api/v1/siteverify")
        .json(&serde_json::json!({
            "secret": secret_key,
            "solution": post_data.frc_captcha_solution
        }))
        .send()
        .await;

    // Handle network or request sending errors
    let response = match response {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Request error: {:?}", e);
            return Ok(
                HttpResponse::InternalServerError().body("Error sending verification request.")
            );
        }
    };

    // Check response code
    if response.status().is_success() {
        let friendly_captcha_response: Result<serde_json::Value, _> = response.json().await;

        match friendly_captcha_response {
            Ok(data) => {
                if data.get("success").and_then(serde_json::Value::as_bool) == Some(true) {
                    Ok(HttpResponse::Ok().body(format!("Form submission successful: {:?}", data)))
                } else {
                    Ok(HttpResponse::BadRequest()
                        .body(format!("Captcha verification failed: {:?}", data)))
                }
            }
            Err(e) => {
                eprintln!("JSON parsing error: {:?}", e);
                Ok(HttpResponse::InternalServerError()
                    .body("Error processing verification response."))
            }
        }
    } else {
        let friendly_captcha_response: Result<serde_json::Value, _> = response.json().await;

        match friendly_captcha_response {
            Ok(data) => {
                Ok(HttpResponse::BadRequest()
                    .body(format!("Captcha verification failed: {:?}", data)))
            }
            Err(e) => {
                eprintln!("JSON parsing error: {:?}", e);
                Ok(HttpResponse::InternalServerError()
                    .body("Error processing verification response."))
            }
        }
    }
}
