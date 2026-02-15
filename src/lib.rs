use base64::prelude::*;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use wasmtimer::std::{SystemTime, UNIX_EPOCH};
use worker::Response;
use worker::*;

#[derive(Deserialize)]
struct RequestPayload {
    event_id: String,
    event_start_time: u64,
    release_rate: Option<u32>,
}

impl RequestPayload {
    fn get_nonce(&self, public_key: &RsaPublicKey) -> String {
        let mut rng = rand::thread_rng();
        let encrypted_data = public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, self.event_id.as_bytes())
            .expect("Failed to encrypt nonce");
        BASE64_STANDARD.encode(encrypted_data)
    }
}

#[derive(Serialize, Deserialize)]
struct TokenData {
    event_id: String,
    issued_at: u64,
    event_start_time: u64,
    slot_index: u64,
}

impl TokenData {
    fn new(event_id: String, event_start_time: u64, release_rate: u32) -> Self {
        let issued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let slot_index = (issued_at - event_start_time) * release_rate as u64;
        TokenData {
            event_id,
            issued_at,
            event_start_time,
            slot_index,
        }
    }

    fn get_encoded(&self, public_key: &RsaPublicKey) -> String {
        let payload_json = serde_json::to_string(self).expect("Failed to serialize token data");
        let mut rng = rand::thread_rng();
        let encrypted_data = public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, payload_json.as_bytes())
            .expect("Failed to encrypt token data");
        BASE64_STANDARD.encode(encrypted_data)
    }

    fn from_encoded(encoded: &str, private_key: &RsaPrivateKey) -> Option<Self> {
        let decoded_data = BASE64_STANDARD.decode(encoded.as_bytes()).ok()?;
        let decrypted_data = private_key.decrypt(Pkcs1v15Encrypt, &decoded_data).ok()?;
        let payload: TokenData = serde_json::from_slice(&decrypted_data).ok()?;
        Some(payload)
    }

    fn get_estimated_wait_time(&self, release_rate: u32) -> u64 {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        std::cmp::max(0, (self.slot_index - current_time) / release_rate as u64)
    }

    fn is_ready(&self) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        self.slot_index <= current_time
    }
}

fn generate_response(
    estimated_time: u64,
    token: Option<String>,
    nonce: Option<String>,
) -> Result<Response> {
    let headers = Headers::new();

    headers.set("Content-Type", "text/plain")?;

    if let Some(t) = token {
        headers.set("WR-TOKEN", &t)?;
    }

    if let Some(n) = nonce {
        headers.set("WR-NONCE", &n)?;
    }

    let body = ResponseBody::Body(format!("{}", estimated_time).into());
    let response = Response::builder()
        .body(body)
        .with_headers(headers)
        .with_status(200);

    Ok(response)
}

#[event(fetch)]
async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let PRIVATE_KEY = env
        .secret("PRIVATE_KEY")
        .expect("PRIVATE_KEY not found.")
        .to_string();
    let PUBLIC_KEY = env
        .secret("PUBLIC_KEY")
        .expect("PRIVATE_KEY not found.")
        .to_string();

    let private_key = RsaPrivateKey::from_pkcs1_pem(PRIVATE_KEY.to_string().as_str())
        .expect("Failed to load private key");

    let public_key = RsaPublicKey::from_public_key_pem(PUBLIC_KEY.to_string().as_str())
        .expect("Failed to load public key");

    let Ok(body) = req.text().await else {
        return Response::error("Body not found", 400);
    };

    let Ok(decoded_body) = BASE64_STANDARD.decode(body.as_bytes()) else {
        return Response::error("Bad Request", 400);
    };

    let Ok(dec_body) = private_key.decrypt(Pkcs1v15Encrypt, &decoded_body) else {
        return Response::error("Bad Request", 400);
    };

    let mut request_payload: RequestPayload = match serde_json::from_slice(&dec_body) {
        Ok(payload) => payload,
        Err(_) => {
            return Response::error("Bad Request", 400);
        }
    };
    request_payload.release_rate = request_payload.release_rate.filter(|&v| v != 0);

    // WR is disabled for the event
    if request_payload.release_rate.is_none() {
        return generate_response(0, None, Some(request_payload.get_nonce(&public_key)));
    }
    let release_rate = request_payload.release_rate.unwrap();

    let wr_token = req
        .headers()
        .get("WR-TOKEN")
        .expect("Failed to fetch headers");

    match wr_token {
        None => {
            // Stage 1
            // Request to waiting room without wr-token on headers
            let token_data = TokenData::new(
                request_payload.event_id,
                request_payload.event_start_time,
                release_rate,
            );
            let est_time = token_data.get_estimated_wait_time(release_rate);
            let encoded_token = token_data.get_encoded(&public_key);
            return generate_response(est_time, Some(encoded_token), None);
        }
        Some(token) => {
            // Stage 2
            // Request to waiting room with wr-token (same event_id)
            let Some(token_data) = TokenData::from_encoded(&token, &private_key) else {
                console_error!("Err");
                return Response::error("Invalid Token", 400);
            };

            if token_data.event_id != request_payload.event_id {
                console_error!("Missmatch");
                return Response::error("Invalid Token", 400);
            }

            match token_data.is_ready() {
                true => {
                    // Slot index is ready to release
                    return generate_response(
                        0,
                        Some(token),
                        Some(request_payload.get_nonce(&public_key)),
                    );
                }
                false => {
                    // Slot index is still in waiting
                    let est_time = token_data.get_estimated_wait_time(release_rate);
                    return generate_response(est_time, Some(token), None);
                }
            }
        }
    }
}
