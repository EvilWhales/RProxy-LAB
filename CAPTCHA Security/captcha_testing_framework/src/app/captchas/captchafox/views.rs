use actix_web::{web, HttpResponse, Result};
use dotenv::dotenv;
use reqwest::Client;
use tera::{Context, Tera};

use super::forms::CaptchaFoxForm;

pub async fn captcha_fox(tera: web::Data<Tera>) -> Result<HttpResponse> {
    let mut context = Context::new();
    match std::env::var("CAPTCHA_FOX_SITE_KEY") {
        Ok(sitekey) => {
            context.insert("site_key", &sitekey);

            let rendered = tera
                .render("captchas/captcha_fox.html", &context)
                .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

            Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
        }
        Err(e) => {
            eprintln!("Environment variable error: {:?}", e);
            Ok(HttpResponse::InternalServerError()
                .body("Internal server error: CAPTCHA_FOX_SITE_KEY not found"))
        }
    }
}

pub async fn submit_captcha_fox(post_data: web::Form<CaptchaFoxForm>) -> Result<HttpResponse> {
    // Check env
    dotenv().ok();

    // Load API key
    let secret_key = match std::env::var("CAPTCHA_FOX_SECRET_KEY") {
        Ok(key) => key,
        Err(_) => {
            return Ok(HttpResponse::InternalServerError()
                .body("CAPTCHA_FOX_SECRET_KEY is not set in environment."))
        }
    };

    // Send post request to api endpoint
    let client = Client::new();

    // Create the form data
    let params = [("secret", secret_key), ("response", post_data.cf_captcha_response.clone())];
    
    // Encode the parameters
    let body = serde_urlencoded::to_string(&params).expect("Failed to encode form data");

    // Perform the POST request
    let response = client
        .post("https://api.captchafox.com/siteverify")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
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
        let captchafox_response: Result<serde_json::Value, _> = response.json().await;

        match captchafox_response {
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
        let captchafox_response: Result<serde_json::Value, _> = response.json().await;

        match captchafox_response {
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