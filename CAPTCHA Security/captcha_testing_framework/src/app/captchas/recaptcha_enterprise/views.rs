use actix_web::{web, HttpResponse, Result};
use dotenv::dotenv;
use reqwest::Client;
use serde_json::Value;
use tera::{Context, Tera};

use super::forms::RecaptchaEnterpriseForm;

pub async fn recaptcha_enterprise(tera: web::Data<Tera>) -> Result<HttpResponse> {
    let mut context = Context::new();
    match std::env::var("RECAPTCHA_ENTERPRISE_SITE_KEY") {
        Ok(sitekey) => {
            context.insert("site_key", &sitekey);

            let rendered = tera
                .render("captchas/recaptcha_enterprise.html", &context)
                .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

            Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
        }
        Err(e) => {
            eprintln!("Environment variable error: {:?}", e);
            Ok(HttpResponse::InternalServerError()
                .body("Internal server error: RECAPTCHA_ENTERPRISE_SITE_KEY not found"))
        }
    }
}

pub async fn submit_recaptcha_enterprise(
    post_data: web::Form<RecaptchaEnterpriseForm>,
) -> Result<HttpResponse> {
    // Check env
    dotenv().ok();

    // Load API key
    let secret_key = match std::env::var("RECAPTCHA_ENTERPRISE_SECRET_KEY") {
        Ok(key) => key,
        Err(_) => {
            return Ok(HttpResponse::InternalServerError()
                .body("RECAPTCHA_ENTERPRISE_SECRET_KEY is not set in environment."))
        }
    };

    // Load sitekey
    let site_key = match std::env::var("RECAPTCHA_ENTERPRISE_SITE_KEY") {
        Ok(key) => key,
        Err(_) => {
            return Ok(HttpResponse::InternalServerError()
                .body("RECAPTCHA_ENTERPRISE_SITE_KEY is not set in environment."))
        }
    };

    let endpoint = format!("https://recaptchaenterprise.googleapis.com/v1/projects/test-project-1706648291888/assessments?key={}", secret_key);

    // Send post request to api endpoint
    let client = Client::new();
    let response = client
        .post(&endpoint)
        .json(&serde_json::json!({
            "event": {
                "token": post_data.recaptcha_token.clone(),
                "siteKey": site_key,
            }
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
    let recaptcha_response: Result<serde_json::Value, _> = response.json().await;

    match recaptcha_response {
        Ok(data) => {
            if data
                .get("tokenProperties")
                .and_then(|tp| tp.get("valid"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                Ok(HttpResponse::Ok().body(format!("Form submission successful: {:?}", data)))
            } else {
                Ok(HttpResponse::BadRequest().body(format!("Form submission failed: {:?}", data)))
            }
        }
        Err(e) => {
            eprintln!("JSON parsing error: {:?}", e);
            Ok(HttpResponse::InternalServerError().body("Error processing verification response."))
        }
    }
}