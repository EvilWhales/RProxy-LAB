use actix_web::{web, HttpResponse, Result};
use dotenv::dotenv;
use reqwest::Client;
use tera::{Context, Tera};

use super::forms::RecaptchaV2Form;

pub async fn recaptcha_v2(tera: web::Data<Tera>) -> Result<HttpResponse> {
    dotenv().ok();

    let mut context = Context::new();
    match std::env::var("RECAPTCHA_V2_SITE_KEY") {
        Ok(sitekey) => {
            context.insert("site_key", &sitekey);

            let rendered = tera
                .render("captchas/recaptcha_v2.html", &context)
                .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

            Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
        }
        Err(e) => {
            eprintln!("Environment variable error: {:?}", e);
            Ok(HttpResponse::InternalServerError()
                .body("Internal server error: RECAPTCHA_V2_SITE_KEY not found"))
        }
    }
}

pub async fn submit_recaptcha_v2(post_data: web::Form<RecaptchaV2Form>) -> Result<HttpResponse> {
    // Check env
    dotenv().ok();

    // Load API key
    let secret_key = match std::env::var("RECAPTCHA_V2_SECRET_KEY") {
        Ok(key) => key,
        Err(_) => {
            return Ok(HttpResponse::InternalServerError()
                .body("RECAPTCHA_V2_SECRET_KEY is not set in environment."))
        }
    };

    // Send post request to api endpoint
    let client = Client::new();
    let response = client
        .post("https://www.google.com/recaptcha/api/siteverify")
        .form(&[
            ("secret", secret_key),
            ("response", post_data.g_recaptcha_response.clone()),
        ])
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

    // Parse response JSON
    let recaptcha_response: Result<serde_json::Value, _> = response.json().await;

    match recaptcha_response {
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
            Ok(HttpResponse::InternalServerError().body("Error processing verification response."))
        }
    }
}
