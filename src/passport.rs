//! Relintio agent protocol v2 — passport and request signing.
//!
//! Implements `contracts/agent-protocol-v2.md` and is verified against
//! `contracts/passport-v2-vectors.json` by the shared conformance suite.
//!
//! Nothing here touches the network: the edge must keep deciding when the
//! control plane is unreachable, so a passport is verifiable with the licence
//! key alone.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle_compare::constant_time_eq;

type HmacSha256 = Hmac<Sha256>;

/// Cookie an agent sets once a visitor has passed the challenge.
pub const PASSPORT_COOKIE: &str = "relintio_passport";

/// Absorbs clock drift between the challenge server and this agent.
pub const CLOCK_SKEW_SECONDS: i64 = 60;

const MIN_TTL: i64 = 300;
const MAX_TTL: i64 = 604_800;

/// Decoded body of a v2 token.
///
/// Unknown fields are ignored rather than rejected — that is the extension
/// point for a future revision, and a strict decoder here would break every
/// agent the day the server adds a field.
#[derive(Debug, Clone, Deserialize)]
pub struct PassportPayload {
    #[serde(default)]
    pub v: i64,
    #[serde(default)]
    pub exp: i64,
    #[serde(default)]
    pub b: String,
    #[serde(default)]
    pub ttl: Option<i64>,
    #[serde(default)]
    pub jti: Option<String>,
}

fn now_or(now: Option<i64>) -> i64 {
    now.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    })
}

/// The client identity a passport is tied to.
///
/// `user_agent` and `accept_language` must be the raw header values as
/// received. Trimming or lowercasing them here makes this agent disagree with
/// the challenge server, which locks every visitor out.
pub fn passport_binding(license_key: &str, user_agent: &str, accept_language: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{license_key}|{user_agent}|{accept_language}").as_bytes());

    hex::encode(hasher.finalize())[..16].to_string()
}

/// Verify a v2 pass token or passport cookie.
///
/// Returns `None` when the value is malformed, forged, expired, or bound to a
/// different client.
pub fn verify_passport(
    value: &str,
    license_key: &str,
    user_agent: &str,
    accept_language: &str,
    now: Option<i64>,
) -> Option<PassportPayload> {
    if !value.starts_with("v2.") {
        return None;
    }

    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let raw = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    let signature = URL_SAFE_NO_PAD.decode(parts[2]).ok()?;
    if raw.is_empty() || signature.is_empty() {
        return None;
    }

    let mut mac = HmacSha256::new_from_slice(license_key.as_bytes()).ok()?;
    mac.update(&raw);
    // verify_slice is already constant time.
    mac.verify_slice(&signature).ok()?;

    let payload: PassportPayload = serde_json::from_slice(&raw).ok()?;

    if payload.exp + CLOCK_SKEW_SECONDS < now_or(now) {
        return None;
    }

    let expected = passport_binding(license_key, user_agent, accept_language);
    if !constant_time_eq(payload.b.as_bytes(), expected.as_bytes()) {
        return None;
    }

    Some(payload)
}

/// The cookie value this agent sets after a successful exchange.
pub fn mint_passport(
    ttl: i64,
    license_key: &str,
    user_agent: &str,
    accept_language: &str,
    now: Option<i64>,
) -> String {
    // Hand-built so field order and separators are fixed: the signature covers
    // these exact bytes, and a serializer's ordering is not part of the
    // contract.
    let raw = format!(
        r#"{{"v":2,"exp":{},"b":"{}"}}"#,
        now_or(now) + ttl,
        passport_binding(license_key, user_agent, accept_language)
    );

    let mut mac = HmacSha256::new_from_slice(license_key.as_bytes()).expect("hmac accepts any key length");
    mac.update(raw.as_bytes());

    format!(
        "v2.{}.{}",
        URL_SAFE_NO_PAD.encode(raw.as_bytes()),
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

/// Keep a signed-but-implausible ttl inside sane bounds.
pub fn clamp_ttl(ttl: i64) -> i64 {
    let ttl = if ttl <= 0 { 86_400 } else { ttl };

    ttl.clamp(MIN_TTL, MAX_TTL)
}

/// Signature for one ingest call.
///
/// `body` must be the exact bytes that will be transmitted; hashing a struct
/// and letting an HTTP client re-encode it yields a signature the server cannot
/// reproduce.
pub fn sign_request(body: &[u8], license_key: &str, timestamp: i64, nonce: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash = hex::encode(hasher.finalize());

    let base = format!("v1:{timestamp}:{nonce}:{body_hash}");

    let mut mac = HmacSha256::new_from_slice(license_key.as_bytes()).expect("hmac accepts any key length");
    mac.update(base.as_bytes());

    hex::encode(mac.finalize().into_bytes())
}

/// Ready-made headers for an ingest call, with a fresh nonce per request.
pub fn signing_headers(body: &[u8], license_key: &str) -> Vec<(String, String)> {
    let timestamp = now_or(None);

    // Nanosecond clock plus the body hash: unique per call without pulling in
    // an RNG dependency, and the server treats the nonce as single-use anyway.
    let mut hasher = Sha256::new();
    hasher.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
            .to_string()
            .as_bytes(),
    );
    hasher.update(body);
    let nonce = hex::encode(hasher.finalize())[..24].to_string();

    vec![
        ("X-Relintio-Timestamp".into(), timestamp.to_string()),
        ("X-Relintio-Nonce".into(), nonce.clone()),
        (
            "X-Relintio-Signature".into(),
            format!("v1={}", sign_request(body, license_key, timestamp, &nonce)),
        ),
    ]
}

/// Byte comparison that does not return early.
mod subtle_compare {
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }

        diff == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::PathBuf;

    use serde_json::Value;

    /// Conformance against the vectors shared by all twelve SDKs. A failure
    /// here means this agent disagrees with the challenge server, which in
    /// production means visitors who passed the challenge get blocked.
    fn vectors() -> Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/passport-v2-vectors.json");

        serde_json::from_str(&fs::read_to_string(path).expect("vectors present")).expect("vectors parse")
    }

    #[test]
    fn binding_matches_vectors() {
        let v = vectors();
        let key = v["license_key"].as_str().unwrap();

        for case in v["binding"].as_array().unwrap() {
            assert_eq!(
                passport_binding(
                    key,
                    case["user_agent"].as_str().unwrap(),
                    case["accept_language"].as_str().unwrap()
                ),
                case["expect"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn mint_matches_vectors() {
        let v = vectors();
        let key = v["license_key"].as_str().unwrap();
        let ua = v["user_agent"].as_str().unwrap();
        let lang = v["accept_language"].as_str().unwrap();
        let now = v["now"].as_i64().unwrap();

        for case in v["mint"].as_array().unwrap() {
            assert_eq!(
                mint_passport(case["ttl"].as_i64().unwrap(), key, ua, lang, Some(now)),
                case["expect"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn verify_matches_vectors() {
        let v = vectors();
        let key = v["license_key"].as_str().unwrap();
        let ua = v["user_agent"].as_str().unwrap();
        let lang = v["accept_language"].as_str().unwrap();
        let now = v["now"].as_i64().unwrap();

        for case in v["verify"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let payload = verify_passport(case["token"].as_str().unwrap(), key, ua, lang, Some(now));

            assert_eq!(
                payload.is_some(),
                case["expect_valid"].as_bool().unwrap(),
                "vector: {name}"
            );

            if let Some(expected_ttl) = case["expect_ttl"].as_i64() {
                assert_eq!(payload.unwrap().ttl, Some(expected_ttl), "vector: {name}");
            }
        }
    }

    #[test]
    fn signing_matches_vectors() {
        let v = vectors();
        let s = &v["signing"];

        assert_eq!(
            sign_request(
                s["body"].as_str().unwrap().as_bytes(),
                v["license_key"].as_str().unwrap(),
                s["timestamp"].as_i64().unwrap(),
                s["nonce"].as_str().unwrap()
            ),
            s["expect"].as_str().unwrap()
        );
    }

    #[test]
    fn round_trip_is_bound_to_the_client() {
        let v = vectors();
        let key = v["license_key"].as_str().unwrap();
        let ua = v["user_agent"].as_str().unwrap();
        let lang = v["accept_language"].as_str().unwrap();

        let minted = mint_passport(3600, key, ua, lang, None);

        assert!(verify_passport(&minted, key, ua, lang, None).is_some());
        assert!(verify_passport(&minted, key, "curl/8.4.0", lang, None).is_none());
    }

    #[test]
    fn ttl_is_clamped() {
        assert_eq!(clamp_ttl(10), 300);
        assert_eq!(clamp_ttl(99_999_999), 604_800);
        assert_eq!(clamp_ttl(86_400), 86_400);
        assert_eq!(clamp_ttl(0), 86_400);
    }

    #[test]
    fn signing_headers_are_fresh_each_call() {
        let v = vectors();
        let key = v["license_key"].as_str().unwrap();

        let first = signing_headers(br#"{"a":1}"#, key);
        let second = signing_headers(br#"{"a":2}"#, key);

        let nonce = |h: &Vec<(String, String)>| {
            h.iter().find(|(k, _)| k == "X-Relintio-Nonce").unwrap().1.clone()
        };

        assert_ne!(nonce(&first), nonce(&second));
        assert!(first
            .iter()
            .any(|(k, val)| k == "X-Relintio-Signature" && val.starts_with("v1=") && val.len() == 67));
    }
}
