use actix_web::{middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use dotenv;
use serde::{Deserialize, Serialize};

mod otp;

#[derive(Deserialize)]
struct GenerateSecret {
    length: Option<usize>,
    algo: Option<String>,
    digits: Option<u8>,
    period: Option<u32>,
    issuer: Option<String>,
    account_name: Option<String>,
}
#[derive(Serialize)]
struct GenerateSecretResponse {
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

async fn home(_: HttpRequest) -> String {
    String::from("Authenticator")
}

async fn generate_secret(query: web::Query<GenerateSecret>) -> Result<HttpResponse, Error> {
    let algo = match &query.algo {
        None => "SHA1".to_string(),
        Some(v) => v.to_string(),
    };
    let digits = match query.digits {
        None => 6,
        Some(v) => v,
    };
    let period = match query.period {
        None => 30,
        Some(v) => v,
    };
    let issuer = match &query.issuer {
        None => "Authenticator".to_string(),
        Some(v) => v.to_string(),
    };
    let account_name = match &query.account_name {
        None => "".to_string(),
        Some(v) => v.to_string(),
    };
    let generated_secret = otp::generate_secret(query.length);
    let uri = format!("otpauth://totp/{issuer}:{account_name}?secret={generated_secret}&algorithm={algo}&digits={digits}&period={period}");
    let uri = uri.replace(":?", "?");
    let (qr_code_width, qr_code_height) = (400, 400);
    let qr_code =
        format!("https://chart.googleapis.com/chart?chs={qr_code_width}x{qr_code_height}&chld=M&cht=qr&chl={uri}");

    Ok(HttpResponse::Created().json(GenerateSecretResponse {
        secret: generated_secret,
        uri: uri,
        qr_code: qr_code,
    }))
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
            .route("/", web::get().to(home))
            .route("/api/otp/secret", web::get().to(generate_secret))
            .route("/api/otp/generate", web::post().to(generate_otp))
            .route("/api/otp/validate", web::post().to(validate_otp))
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use actix_web::{body::to_bytes, dev::Service, http, test, web, App, Error};

    use super::*;

    #[actix_web::test]
    async fn test_home() -> Result<(), Error> {
        let app = App::new().route("/", web::get().to(home));
        let app = test::init_service(app).await;
        let req = test::TestRequest::get().uri("/").to_request();
        let resp = app.call(req).await?;

        assert_eq!(resp.status(), http::StatusCode::OK);

        let response_body = resp.into_body();
        assert_eq!(to_bytes(response_body).await?, r##"Authenticator"##);

        Ok(())
    }
}
