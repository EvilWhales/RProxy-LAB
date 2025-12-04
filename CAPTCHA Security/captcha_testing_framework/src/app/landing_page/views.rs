use actix_web::{web, HttpResponse, Result};
use tera::{Context, Tera};

pub async fn landing_page(tera: web::Data<Tera>) -> Result<HttpResponse> {
    let context = Context::new();

    let rendered = tera
        .render("index.html", &context)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e))?;

    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}
