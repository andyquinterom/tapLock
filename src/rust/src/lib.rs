use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use extendr_api::prelude::*;
use jsonwebtoken::{jwk::JwkSet, Algorithm, DecodingKey};
use serde::{Deserialize, Serialize};

fn parse_cookie(keyvalue: &str) -> (&str, Robj) {
    let (name, value) = keyvalue
        .split_once('=')
        .expect("Cookie does not contain a key value pair");
    (name.trim(), Robj::from(value.trim()))
}

/// @title Parse cookies
/// @description Parses cookies from a string
///
/// @param x A string containing the cookies
///
/// @return A list containing the cookies
/// @keywords internal
#[extendr]
fn parse_cookies(cookies: Nullable<Strings>) -> List {
    match cookies {
        NotNull(cookies) => match cookies.first() {
            Some(cookies) => {
                List::from_pairs(cookies.split(';').map(parse_cookie).collect::<Vec<_>>())
            }
            None => List::new(0),
        },
        Null => List::new(0),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: usize, // Optional. Issued at (as UTC timestamp)
    #[serde(flatten)]
    data: HashMap<String, serde_json::Value>,
}

#[extendr]
impl Claims {
    fn print(&self) {
        println!("{:?}", self);
    }
}

struct JwksManager {
    decoding_keys: Arc<Mutex<Vec<DecodingKey>>>,
    jwks_refresh_handle: std::thread::JoinHandle<()>,
}

#[extendr]
impl JwksManager {
    fn new(url: String) -> Self {
        let agent = ureq::Agent::new();
        let jwks: JwkSet = agent
            .get(&url)
            .call()
            .expect("Unable to get Jwks")
            .into_json()
            .expect("Unable to deserialize JWKS");
        let decoding_keys = jwks
            .keys
            .into_iter()
            .filter_map(|jwk| DecodingKey::from_jwk(&jwk).ok())
            .collect();
        let decoding_keys = Arc::new(Mutex::new(decoding_keys));
        let jwks_refresh_handle = {
            let decoding_keys = Arc::clone(&decoding_keys);
            std::thread::spawn(move || {
                // Default refresh to 10 minutes
                let refresh_rate = std::time::Duration::from_secs(60 * 10);
                loop {
                    std::thread::sleep(refresh_rate);
                    let decoding_keys_new = match agent.get(&url).call() {
                        Ok(resp) => match resp.into_json::<JwkSet>() {
                            Ok(jwks) => jwks
                                .keys
                                .into_iter()
                                .filter_map(|jwk| DecodingKey::from_jwk(&jwk).ok())
                                .collect(),
                            Err(e) => {
                                eprintln!("{e}");
                                continue;
                            }
                        },
                        Err(e) => {
                            eprintln!("{e}");
                            continue;
                        }
                    };
                    let mut decoding_keys = decoding_keys.lock().expect("Posioned Jwks Mutex");
                    *decoding_keys = decoding_keys_new;
                }
            })
        };
        JwksManager {
            decoding_keys,
            jwks_refresh_handle,
        }
    }
    fn decode_token(&self, token: &str) -> Result<Claims> {
        let decoding_keys = self.decoding_keys.lock().expect("Poisoned handle");
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        for key in decoding_keys.iter() {
            match jsonwebtoken::decode::<Claims>(token, key, &validation) {
                Ok(claims) => return Ok(claims.claims),
                Err(e) => eprintln!("{:?}", e),
            }
        }
        Err("Unable to decode token".into())
    }
}

// Macro to generate exports.
// This ensures exported functions are registered with R.
// See corresponding C code in `entrypoint.c`.
extendr_module! {
    mod tapLock;
    fn parse_cookies;
    impl Claims;
    impl JwksManager;
}
