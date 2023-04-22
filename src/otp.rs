use base32::Alphabet::{Crockford, RFC4648};
use hmac::{Hmac, Mac};
use rand::{distributions::Alphanumeric, Rng};
use sha1::Sha1;
use std::{error::Error, ops::Add, time::SystemTime};

type HmacSha1 = Hmac<Sha1>;

/// Generate secret
///
/// # Arguments
///
/// * `length` - length of the secret
/// ```
pub fn generate_secret(length: Option<usize>) -> String {
    let text_length = length.unwrap_or(32);
    let random_text: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(text_length)
        .map(char::from)
        .collect();

    base32::encode(RFC4648 { padding: false }, &random_text.as_bytes())
}

/// Generate HOTP
///
/// # Arguments
///
/// * `secret` - Shared secret key
/// * `counter` - The counter value, calculated from time by default
/// * `digits` - the number of digits for the token
/// * `period` - the time to live of the token. Default 30 seconds
/// ```
pub fn generate_otp(
    secret: &str,
    counter: Option<u128>,
    digits: Option<u8>,
    period: Option<u8>,
) -> Result<String, Box<dyn Error>> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();

    let period = period.unwrap_or(30);
    let digits = digits.unwrap_or(6);
    let mut counter = counter.unwrap_or(now / (period as u128 * 1000));

    let decoded_secret = match base32::decode(RFC4648 { padding: false }, &secret) {
        None => match base32::decode(Crockford, &secret) {
            None => return Err("Secret can not be decoded".into()),
            Some(v) => v,
        },
        Some(v) => v,
    };

    let mut digest = vec![0; 8];

    for i in 0..digest.len() {
        let index = digest.len() - 1;
        digest[index - i] = counter as u8 & 0xff;
        counter >>= digest.len();
    }

    let mut hmac: Hmac<Sha1> = match HmacSha1::new_from_slice(&decoded_secret) {
        Ok(v) => v,
        Err(_) => return Err("Error generating HMAC".into()),
    };
    hmac.update(&digest);

    let result = hmac.finalize().into_bytes();
    let offset: u8 = result[result.len() - 1] & 0xf;
    let code = ((u32::from(result[offset as usize]) & 0x7f) << 24)
        | (u32::from((result[offset as usize + 1]) & 0xff) << 16)
        | (u32::from((result[offset as usize + 2]) & 0xff) << 8)
        | (u32::from(result[offset as usize + 3]) & 0xff);

    let token = match std::panic::catch_unwind(|| u32::pow(10, digits as u32)) {
        Ok(v) => code % v,
        Err(_e) => return Err("the maximum number of digits allowed is 9".into()),
    };
    let mut token = token.to_string();

    while token.len() < digits as usize {
        token = format!("0{token}");
    }

    Ok(token)
}

/// Validate OTP
///
/// # Arguments
///
/// * `token` - OTP to validate
/// * `secret` - Shared secret key
/// * `counter` - The counter value, calculated from time by default
/// * `period` - the time to live of the token. Default 30 seconds
/// * `window` - The allowable margin for the counter
/// ```
pub fn validate_otp(
    token: &str,
    secret: &str,
    counter: Option<u128>,
    period: Option<u8>,
    window: Option<u8>,
) -> Result<bool, Box<dyn Error>> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();

    let period = period.unwrap_or(30);
    let counter = counter.unwrap_or(now / (period as u128 * 1000));
    let window = window.unwrap_or(1);

    if window > 10 {
        return Err("error window is too big".into());
    }

    let mut error_window: i8 = 0 - window as i8;

    while error_window <= window as i8 {
        let otp = match generate_otp(
            &secret,
            Some((counter as i128).add(error_window as i128) as u128),
            Some(token.len() as u8),
            Some(period),
        ) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };

        if token == otp {
            return Ok(true);
        }
        error_window += 1;
    }
    return Err("OTP is not valid".into());
}
