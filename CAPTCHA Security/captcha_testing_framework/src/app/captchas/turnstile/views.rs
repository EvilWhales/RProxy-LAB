use actix_web::{web, HttpResponse, Result};
use dotenv::dotenv;
use reqwest::Client;
use tera::{Context, Tera};

use super::forms::TurnstileForm;

pub async fn turnstile(tera: web::Data<Tera>) -> Result<HttpResponse> {
    dotenv().ok();

    let mut context = Context::new();
    match std::env::var("TURNSTILE_SITE_KEY") {
        Ok(sitekey) => {
            // Insert custom sitekey
            context.insert("site_key", &sitekey);

            let rendered = tera
                .render("captchas/turnstile.html", &context)
                .map_err(|e| {
                    eprintln!("Template error: {:?}", e);
                    actix_web::error::ErrorInternalServerError("Template rendering error")
                })?;

            Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
        }
        Err(e) => {
            eprintln!("Environment variable error: {:?}", e); // Log or handle the env var error
            Ok(HttpResponse::InternalServerError()
                .body("Internal server error: TURNSTILE_SITE_KEY not found"))
        }
    }
}

pub async fn submit_turnstile(post_data: web::Form<TurnstileForm>) -> Result<HttpResponse> {
    // Check env
    dotenv().ok();

    // Load API key
    let secret_key = match std::env::var("TURNSTILE_SECRET_KEY") {
        Ok(key) => key,
        Err(_) => {
            return Ok(HttpResponse::InternalServerError()
                .body("TURNSTILE_SECRET_KEY is not set in environment."))
        }
    };

    // Send post request to api endpoint
    let client = Client::new();
    let response = client
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .json(&serde_json::json!({
            "secret": secret_key,
            "response": post_data.cf_turnstile_response
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

    // Parse response JSON
    let turnstile_response: Result<serde_json::Value, _> = response.json().await;

    match turnstile_response {
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
