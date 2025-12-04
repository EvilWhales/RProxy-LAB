use actix_files;
use actix_web::{middleware::Logger, web, App, HttpServer};
use env_logger::Env;
use tera::Tera;

mod app;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load env
    dotenv::dotenv().ok();

    // Create logger
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // Get static path from env -> default is ./static/
    let static_file_path = match std::env::var("STATIC_PATH") {
        Ok(path) => path,
        Err(_) => String::from("./static/"),
    };

    // Get subpaths from static directory
    let css_path = format!("{}/css", static_file_path);
    let template_path = format!("{}/templates/**/*", static_file_path);

    // Get Host configuration -> Default ist 0.0.0.0:8080
    let host = match std::env::var("HOST") {
        Ok(path) => path,
        Err(_) => String::from("0.0.0.0"),
    };

    let port = match std::env::var("PORT") {
        Ok(path) => path,
        Err(_) => String::from("8080"),
    };

    let bind_address = format!("{}:{}", host, port);

    // Create and start web server
    HttpServer::new(move || {
        // Create tera template engine
        let tera = Tera::new(&template_path.to_owned()).expect("Failed to initialize Tera");

        App::new()
            // Static path for css
            .service(actix_files::Files::new("/css", css_path.clone()).show_files_listing())
            // Logging
            .wrap(Logger::default())
            // Templating
            .app_data(web::Data::new(tera))
            // Routing
            .configure(app::register_urls)
    })
    .bind(bind_address)?
    .run()
    .await
}
