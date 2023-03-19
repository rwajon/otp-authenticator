use base32::Alphabet::RFC4648;
use rand::{distributions::Alphanumeric, Rng};

pub fn generate_secret(length: Option<usize>) -> String {
    let text_length = match length {
        None => 32,
        Some(v) => v,
    };

    let random_text: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(text_length)
        .map(char::from)
        .collect();

    base32::encode(RFC4648 { padding: false }, &random_text.as_bytes())
}
