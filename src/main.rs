use actix_web::{middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use dotenv;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct GenerateSecret {
    secret: String,
    uri: String,
    qr_code: String,
}

#[derive(Deserialize)]
struct GenerateOTP {
    secret: String,
    encoding: Option<String>,
}

#[derive(Serialize)]
struct GenerateOTPResponse {
    token: String,
    period: u32,
}

#[derive(Deserialize)]
struct VerifyOTP {
    secret: String,
    token: String,
    encoding: Option<String>,
}

#[derive(Serialize)]
struct VerifyOTPResponse {
    is_valid: bool,
    period: u32,
    message: String,
}

async fn generate_secret(req: HttpRequest) -> Result<HttpResponse, Error> {
    let result = GenerateSecret {
        secret: "secret".to_string(),
        uri: "uri".to_string(),
        qr_code: "qr_code".to_string(),
    };
    Ok(HttpResponse::Created().json(result))
}

async fn generate_otp(payload: web::Json<GenerateOTP>) -> Result<HttpResponse, Error> {
    println!("secret {}", payload.secret);
    println!("encoding {:?}", payload.encoding);
    let result = GenerateOTPResponse {
        token: "token".to_string(),
        period: 30,
    };
    Ok(HttpResponse::Created().json(result))
}

async fn validate_otp(payload: web::Json<VerifyOTP>) -> Result<HttpResponse, Error> {
    println!("secret {}", payload.secret);
    println!("encoding {:?}", payload.encoding);
    let result = VerifyOTPResponse {
        is_valid: true,
        period: 30,
        message: "OTP is valid".to_string(),
    };
    Ok(HttpResponse::Ok().json(result))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();

    let port = match dotenv::var("PORT") {
        Ok(val) => val.to_string(),
        Err(_) => "5000".to_string(),
    };

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("starting HTTP server at http://localhost:{}", port);

    HttpServer::new(|| {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            .service(web::resource("/index.html").to(|| async { "Authenticator!" }))
            .route("/api/otp/secret", web::get().to(generate_secret))
            .route("/api/otp/generate", web::post().to(generate_otp))
            .route("/api/otp/validate", web::post().to(validate_otp))
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await
}
