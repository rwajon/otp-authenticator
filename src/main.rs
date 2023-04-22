use actix_web::{middleware, web, App, HttpRequest, HttpResponse, HttpServer};
use dotenv;
use serde::{Deserialize, Serialize};

mod otp;

#[derive(Serialize)]
struct Response {
    message: String,
}

#[derive(Deserialize)]
struct GenerateSecret {
    length: Option<usize>,
    secret: Option<String>,
    algo: Option<String>,
    digits: Option<u8>,
    period: Option<u8>,
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
    counter: Option<u128>,
    digits: Option<u8>,
    period: Option<u8>,
}

#[derive(Serialize)]
struct GenerateOTPResponse {
    token: String,
}

#[derive(Deserialize)]
struct VerifyOTP {
    token: String,
    secret: String,
    counter: Option<u128>,
    period: Option<u8>,
    window: Option<u8>,
}

#[derive(Serialize)]
struct VerifyOTPResponse {
    is_valid: bool,
    message: String,
}

async fn home(_: HttpRequest) -> String {
    String::from("Authenticator")
}

async fn get_qr_code(query: web::Query<GenerateSecret>) -> HttpResponse {
    let algo = query.algo.clone().unwrap_or("SHA1".to_string());
    let digits = query.digits.unwrap_or(6);
    let period = query.period.unwrap_or(30);
    let issuer = query.issuer.clone().unwrap_or("Authenticator".to_string());
    let account_name = query.account_name.clone().unwrap_or("".to_string());
    let secret = query
        .secret
        .clone()
        .unwrap_or(otp::generate_secret(query.length));

    let uri = format!("otpauth://totp/{issuer}:{account_name}?secret={secret}&algorithm={algo}&digits={digits}&period={period}");
    let uri = uri.replace(":?", "?");
    let (qr_code_width, qr_code_height) = (400, 400);
    let qr_code =
        format!("https://chart.googleapis.com/chart?chs={qr_code_width}x{qr_code_height}&chld=M&cht=qr&chl={uri}");

    HttpResponse::Created().json(GenerateSecretResponse {
        secret,
        uri,
        qr_code,
    })
}

async fn generate_secret(query: web::Query<GenerateSecret>) -> HttpResponse {
    let algo = "SHA1";
    let digits = query.digits.unwrap_or(6);
    let period = query.period.unwrap_or(30);
    let issuer = query.issuer.clone().unwrap_or("Authenticator".to_string());
    let account_name = query.account_name.clone().unwrap_or("".to_string());
    let generated_secret = otp::generate_secret(query.length);

    let uri = format!("otpauth://totp/{issuer}:{account_name}?secret={generated_secret}&algorithm={algo}&digits={digits}&period={period}");
    let uri = uri.replace(":?", "?");
    let (qr_code_width, qr_code_height) = (400, 400);
    let qr_code =
        format!("https://chart.googleapis.com/chart?chs={qr_code_width}x{qr_code_height}&chld=M&cht=qr&chl={uri}");

    HttpResponse::Created().json(GenerateSecretResponse {
        secret: generated_secret,
        uri,
        qr_code,
    })
}

async fn generate_otp(payload: web::Json<GenerateOTP>) -> HttpResponse {
    match otp::generate_otp(
        &payload.secret,
        payload.counter,
        payload.digits,
        payload.period,
    ) {
        Ok(token) => return HttpResponse::Created().json(GenerateOTPResponse { token }),
        Err(msg) => {
            return HttpResponse::BadRequest().json(Response {
                message: msg.to_string(),
            })
        }
    };
}

async fn validate_otp(payload: web::Json<VerifyOTP>) -> HttpResponse {
    match otp::validate_otp(
        &payload.token,
        &payload.secret,
        payload.counter,
        payload.period,
        payload.window,
    ) {
        Ok(is_valid) => {
            return HttpResponse::Ok().json(VerifyOTPResponse {
                is_valid,
                message: "OTP is valid".to_string(),
            })
        }
        Err(msg) => {
            return HttpResponse::BadRequest().json(VerifyOTPResponse {
                is_valid: false,
                message: msg.to_string(),
            })
        }
    };
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();

    let port: String = match dotenv::var("PORT") {
        Ok(val) => val,
        Err(_) => "5000".to_string(),
    };

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("starting HTTP server at http://localhost:{}", port);

    HttpServer::new(|| {
        App::new()
            .wrap(middleware::Logger::default())
            .service(web::resource("/index.html").to(|| async { "Authenticator!" }))
            .route("/", web::get().to(home))
            .route("/api/otp/qrcode", web::get().to(get_qr_code))
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
