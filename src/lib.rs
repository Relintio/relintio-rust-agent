pub mod obsidian;
pub mod rules;
pub mod passport;
pub mod utils;
pub mod middleware;

#[cfg(test)]
mod metering_test;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(test)]
use hmac::{Hmac, Mac};
#[cfg(test)]
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(test)]
type HmacSha256 = Hmac<Sha256>;

const AGENT_VERSION: &str = "0.1.2";
const THRESHOLDS: &[(&str, u32)] = &[
    ("ALLOW", 0),
    ("SLOW", 40),
    ("CHALLENGE", 60),
    ("DECOY", 75),
    ("BLOCK", 85),
];

const DECOY_HTML: &str = r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Scheduled Maintenance</title><style>body{background:#0a0a0a;color:#aaa;font-family:system-ui;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}.box{text-align:center;max-width:480px}h1{font-size:1.5rem;color:#fff;margin:0 0 1rem}p{color:#666;font-size:.875rem}</style></head><body><div class="box"><h1>Scheduled Maintenance</h1><p>We are currently performing scheduled maintenance. Please try again later.</p><p style="color:#444;font-size:.75rem;margin-top:2rem">ETA: ~15 minutes</p></div></body></html>"#;

const BLOCK_HTML: &str = r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Access Denied</title><style>body{background:#050507;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}.card{background:#0E0E10;padding:40px;border-radius:20px;border:1px solid rgba(255,255,255,.1);text-align:center}h1{color:#ef4444;margin:0 0 1rem}</style></head><body><div class="card"><h1>Access Blocked</h1><p>Security policies have flagged this request as suspicious.</p></div></body></html>"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Slow,
    Challenge { redirect_url: String },
    Decoy,
    Block,
}

/// The result of asking the control plane to start a challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ChallengeOutcome {
    /// Send the visitor here.
    Redirect(String),
    /// The licence has the challenge switched off. `block` carries the
    /// customer's chosen fallback, so this is not the same as "no challenge
    /// available" and must not be treated as one.
    Disabled { block: bool },
    /// The control plane could not be reached, or answered with something
    /// unusable. No challenge was issued, so nothing was passed, and the
    /// engine's own verdict on this visitor still stands: fail closed.
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelintioConfig {
    pub license_key: String,
    pub api_url: String,
    pub sync_interval_seconds: u64,
}

struct TokenBucket {
    tokens: f64,
    last_ts: f64,
}

pub struct RelintioAgent {
    config: RelintioConfig,
    pub(crate) rules: Arc<RwLock<Option<Value>>>,
    synced_at: Arc<Mutex<u64>>,
    next_sync_at: Arc<Mutex<u64>>,
    sync_failures: Arc<Mutex<u8>>,
    sync_in_progress: AtomicBool,
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
    client: reqwest::Client,
    cache_path: PathBuf,
}

impl RelintioAgent {
    pub fn new(config: RelintioConfig) -> Self {
        let license_hash = format!("{:x}", md5::compute(config.license_key.as_bytes()));
        let mut cache_dir = env::temp_dir();
        cache_dir.push("relintio");
        let _ = fs::create_dir_all(&cache_dir);
        cache_dir.push(format!("up_rules_{}.json", &license_hash[..16]));

        let agent = Self {
            config,
            rules: Arc::new(RwLock::new(None)),
            synced_at: Arc::new(Mutex::new(0)),
            next_sync_at: Arc::new(Mutex::new(0)),
            sync_failures: Arc::new(Mutex::new(0)),
            sync_in_progress: AtomicBool::new(false),
            buckets: Arc::new(Mutex::new(HashMap::new())),
            client: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            cache_path: cache_dir,
        };

        // Try load cache on startup
        let _ = agent.load_cache_from_disk();
        agent
    }

    /// Verify a v2 pass token or passport cookie against this request's client.
    ///
    /// Returns the payload so the caller can honour the ttl the challenge server
    /// asked for. See contracts/agent-protocol-v2.md.
    pub fn verify_passport(
        &self,
        token: &str,
        user_agent: &str,
        accept_language: &str,
    ) -> Option<crate::passport::PassportPayload> {
        crate::passport::verify_passport(
            token,
            &self.config.license_key,
            user_agent,
            accept_language,
            None,
        )
    }

    /// The cookie value to set once a pass token has been accepted.
    pub fn mint_passport(&self, ttl: i64, user_agent: &str, accept_language: &str) -> String {
        crate::passport::mint_passport(ttl, &self.config.license_key, user_agent, accept_language, None)
    }

    fn load_cache_from_disk(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.cache_path.exists() {
            let data = fs::read_to_string(&self.cache_path)?;
            let parsed: Value = serde_json::from_str(&data)?;
            let mut w = self.rules.write().unwrap_or_else(|poisoned| poisoned.into_inner());
            *w = Some(parsed);
        }
        Ok(())
    }

    fn save_cache_to_disk(&self, val: &Value) -> Result<(), Box<dyn std::error::Error>> {
        let serialized = serde_json::to_string(val)?;
        fs::write(&self.cache_path, serialized)?;
        Ok(())
    }

    /// Triggers rules fetch from the API and saves it. Async-safe.
    pub async fn refresh_rules(&self, domain: &str) -> Result<(), Box<dyn std::error::Error>> {
        let url = format!("{}/agent/verify", self.config.api_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "license_key": self.config.license_key,
            "domain": domain,
            "protocol_version": 1,
            "agent_kind": "rust",
            "agent_version": AGENT_VERSION,
            "capabilities": ["custom_rules", "telemetry"]
        });
        let res = self.signed_post(&url, &body)?
            .send()
            .await?
            .error_for_status()?;

        let val: Value = res.json().await?;

        // No `rules` array means this is not a policy — an unknown status, an
        // error envelope, an empty object that still parsed as JSON. Keep
        // enforcing the last policy, in memory and on disk, and let the caller
        // treat this as a failed sync. Storing the body regardless is how
        // `quota_exceeded` used to switch a customer's protection off over a
        // billing state: `score_request` reads `rules` out of whatever is here,
        // finds nothing, and scores every visitor zero. Any answer this agent
        // did not recognise would have done the same. An explicit
        // `"rules": []` is a real, empty policy and is stored.
        if !val.get("rules").map(Value::is_array).unwrap_or(false) {
            return Err(format!(
                "/agent/verify answered without a rules array (status: {}); keeping the last policy",
                val.get("status").and_then(Value::as_str).unwrap_or("none")
            )
            .into());
        }

        {
            let mut w = self.rules.write().unwrap_or_else(|poisoned| poisoned.into_inner());
            *w = Some(val.clone());
        }
        let mut sync = self.synced_at.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *sync = unix_now();
        let _ = self.save_cache_to_disk(&val);
        Ok(())
    }

    /// Heartbeat signal trigger.
    pub async fn send_heartbeat(&self, domain: &str) {
        let url = format!("{}/agent/heartbeat", self.config.api_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "license_key": self.config.license_key,
            "domain": domain,
            "agent_version": AGENT_VERSION,
            "agent_kind": "rust",
            "timestamp": unix_now()
        });

        let Ok(request) = self.signed_post(&url, &body) else {
            return;
        };

        let _ = request
            .timeout(Duration::from_secs(2))
            .send()
            .await;
    }

    /// Build one ingest POST carrying the signature the API requires.
    ///
    /// Every call to the control plane goes through here. Unsigned requests are
    /// refused outright once `agent_signature_mode` is `required`, which is its
    /// default, so an endpoint that skips this does not degrade — it 401s and
    /// the edge goes blind.
    ///
    /// The body is serialised once and that same `Vec` is both signed and sent.
    /// Handing reqwest a `Value` to encode on its own would leave the signature
    /// covering a byte sequence that never reached the wire: nothing obliges two
    /// `serde_json` passes to agree on key order or spacing, and the server
    /// hashes exactly what it received.
    fn signed_post(&self, url: &str, body: &Value) -> Result<reqwest::RequestBuilder, serde_json::Error> {
        let bytes = serde_json::to_vec(body)?;

        let mut request = self.client.post(url).header("Content-Type", "application/json");
        for (name, value) in crate::passport::signing_headers(&bytes, &self.config.license_key) {
            request = request.header(name.as_str(), value.as_str());
        }

        Ok(request.body(bytes))
    }

    /// What asking the control plane for a challenge produced.
    ///
    /// Three outcomes, not two. Collapsing "the customer turned the challenge
    /// off and wants these blocked" into the same `None` as "the call failed"
    /// is what made the entire challenge band silently allow.
    async fn challenge_url(&self, domain: &str, path: &str) -> ChallengeOutcome {
        use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

        let endpoint = format!("{}/agent/challenge/init", self.config.api_url.trim_end_matches('/'));
        let scheme = if domain == "localhost" || domain.starts_with("localhost:") || domain == "127.0.0.1" || domain.starts_with("127.0.0.1:") {
            "http"
        } else {
            "https"
        };
        let return_url = format!("{}://{}{}", scheme, domain, path);

        // challenge/init sits behind the same signature middleware as the
        // ingest endpoints, so an unsigned call here fails the request that
        // would have sent a suspicious visitor to the challenge — and an
        // unchallenged visitor is an allowed one.
        let Ok(request) = self.signed_post(&endpoint, &serde_json::json!({
            "license_key": self.config.license_key,
            "return_url": return_url,
        })) else {
            return ChallengeOutcome::Unavailable;
        };

        let Ok(response) = request.send().await else {
            return ChallengeOutcome::Unavailable;
        };

        let Ok(response) = response.error_for_status() else {
            return ChallengeOutcome::Unavailable;
        };

        let Ok(body) = response.json::<Value>().await else {
            return ChallengeOutcome::Unavailable;
        };

        // The customer has switched the challenge off, or their plan does not
        // include it. This is a policy answer carrying what to do instead, and
        // it arrives as a 200 for exactly that reason.
        if body.get("status").and_then(Value::as_str) == Some("challenge_disabled") {
            return ChallengeOutcome::Disabled {
                block: body.get("fallback").and_then(Value::as_str) != Some("allow"),
            };
        }

        // An absolute URL from the control plane wins, and is read before the
        // token: a response can legitimately supply one without the other.
        if let Some(challenge_url) = body.get("challenge_url").and_then(Value::as_str) {
            if challenge_url.starts_with("https://") || challenge_url.starts_with("http://") {
                return ChallengeOutcome::Redirect(challenge_url.to_string());
            }
        }

        let Some(token) = body.get("token").and_then(Value::as_str) else {
            return ChallengeOutcome::Unavailable;
        };

        let Ok(mut platform_url) = reqwest::Url::parse(self.config.api_url.trim_end_matches('/')) else {
            return ChallengeOutcome::Unavailable;
        };

        if let Some(host) = platform_url.host_str().map(str::to_string) {
            if let Some(root_host) = host.strip_prefix("api.") {
                if platform_url.set_host(Some(root_host)).is_err() {
                    return ChallengeOutcome::Unavailable;
                }
            }
        }

        platform_url.set_path("");
        platform_url.set_query(None);
        platform_url.set_fragment(None);

        ChallengeOutcome::Redirect(format!(
            "{}/security-check?token={}",
            platform_url.as_str().trim_end_matches('/'),
            utf8_percent_encode(token, NON_ALPHANUMERIC),
        ))
    }

    /// Evaluates the request against protection rules.
    pub fn score_request(
        &self,
        ip: &str,
        user_agent: Option<&str>,
        headers: &HashMap<String, String>,
        method: &str,
        path: &str,
    ) -> u32 {
        let mut score: u32 = 0;

        // UA evaluation
        let ua = user_agent.unwrap_or("");
        let ua_lower = ua.to_lowercase();
        if ua.is_empty() {
            score += 40;
        } else {
            let headless_keywords = ["puppeteer", "playwright", "phantomjs", "headlesschrome", "selenium"];
            if headless_keywords.iter().any(|&k| ua_lower.contains(k)) {
                score += 25;
            }
            let bot_keywords = ["googlebot", "bingbot", "yandex", "baiduspider", "curl", "wget", "httpclient", "python-urllib"];
            if bot_keywords.iter().any(|&k| ua_lower.contains(k)) {
                score += 35;
            }
        }

        // Header check
        if !headers.contains_key("accept") && !headers.contains_key("Accept") {
            score += 15;
        }

        // Method Referrer check
        if method.eq_ignore_ascii_case("POST") && !headers.contains_key("referer") && !headers.contains_key("Referer") {
            score += 20;
        }

        // Rate Limit bucket check
        if !self.consume_token(ip, path) {
            score += 35;
        }

        // The matching itself is `crate::rules`, asserted against
        // contracts/rule-conditions-v1.json. It used to live inline here, where
        // `regex` collapsed to a substring test, `header` had no branch at all,
        // and an unrecognised condition matched instead of failing closed.
        let facts = crate::rules::RequestFacts { ip, path, user_agent: ua, headers };

        let rules = self.rules.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(custom_rules) = rules.as_ref().and_then(|value| value.get("rules")).and_then(Value::as_array) {
            for rule in custom_rules {
                if crate::rules::rule_matches(rule, &facts) {
                    score = score.saturating_add(rule.get("score").and_then(Value::as_u64).unwrap_or(0) as u32);
                }
            }
        }

        score.min(100)
    }

    fn consume_token(&self, ip: &str, path: &str) -> bool {
        let now = unix_now() as f64;

        let mut multiplier = 1.0;
        let route_multipliers = [
            ("/login", 0.4),
            ("/auth", 0.4),
            ("/api/", 0.7),
            ("/assets/", 2.0),
        ];

        for (prefix, mult) in route_multipliers {
            if path.starts_with(prefix) {
                multiplier = mult;
                break;
            }
        }

        let burst = 24.0 * multiplier;
        let rate_per_sec = 8.0 * multiplier;

        let mut buckets = self.buckets.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let bucket = buckets.entry(ip.to_string()).or_insert_with(|| TokenBucket {
            tokens: burst,
            last_ts: now,
        });

        let elapsed = now - bucket.last_ts;
        bucket.last_ts = now;
        bucket.tokens = (bucket.tokens + elapsed * rate_per_sec).min(burst);

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Evaluates the full decision path.
    pub async fn evaluate(
        &self,
        ip: &str,
        user_agent: Option<&str>,
        headers: &HashMap<String, String>,
        method: &str,
        path: &str,
        domain: &str,
    ) -> Decision {
        // Sync rules if empty or expired
        let now = unix_now();
        let should_sync = now >= *self.next_sync_at.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        if should_sync && self.sync_in_progress.compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            let success = self.refresh_rules(domain).await.is_ok();
            self.schedule_next_sync(success);
            self.sync_in_progress.store(false, Ordering::Release);
        }

        let score = self.score_request(ip, user_agent, headers, method, path);

        if score >= threshold("BLOCK") {
            return Decision::Block;
        }
        if score >= threshold("DECOY") {
            return Decision::Decoy;
        }
        if score >= threshold("CHALLENGE") {
            return match self.challenge_url(domain, path).await {
                ChallengeOutcome::Redirect(redirect_url) => Decision::Challenge { redirect_url },
                ChallengeOutcome::Disabled { block: true } => Decision::Block,
                // The customer switched the challenge off and chose `allow` as
                // what happens instead. This is the one way a visitor in the
                // challenge band goes through, and it is the licence's own
                // decision rather than an accident of the network.
                ChallengeOutcome::Disabled { block: false } => Decision::Allow,
                // No challenge was issued, so nothing was passed. The traffic
                // that reaches here is by definition traffic the engine already
                // judged suspicious enough to challenge, and an unreachable
                // token service must not be the way in.
                ChallengeOutcome::Unavailable => Decision::Block,
            };
        }
        if score >= threshold("SLOW") {
            return Decision::Slow;
        }

        Decision::Allow
    }

    fn schedule_next_sync(&self, success: bool) {
        let mut failures = self.sync_failures.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *failures = if success { 0 } else { failures.saturating_add(1).min(5) };
        let base = if success {
            self.config.sync_interval_seconds.max(10)
        } else {
            self.config.sync_interval_seconds.max(10).saturating_mul(1_u64 << *failures).min(300)
        };
        let jitter = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| 80 + (u64::from(duration.subsec_nanos()) % 41))
            .unwrap_or(100);
        let delay = (base.saturating_mul(jitter) / 100).max(8);
        *self.next_sync_at.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = unix_now().saturating_add(delay);
    }

    pub fn decoy_html() -> &'static str {
        DECOY_HTML
    }

    pub fn block_html() -> &'static str {
        BLOCK_HTML
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn threshold(tier: &str) -> u32 {
    THRESHOLDS.iter()
        .find_map(|(name, value)| (*name == tier).then_some(*value))
        .unwrap_or(0)
}

/// The ingest calls are signed on the wire, not just in the helper.
///
/// `signing_headers` had a passing conformance test long before anything called
/// it, so these assert against real outbound requests: a loopback listener
/// receives the bytes reqwest actually transmitted and re-derives the signature
/// the way VerifyAgentSignature does. A body that gets re-encoded between being
/// signed and being sent shows up here as a mismatch rather than as a 401 in
/// production.
///
/// The listener is hand-rolled on `TcpListener` deliberately: an HTTP mocking
/// crate would be a new dependency, and mocking reqwest away would put the test
/// back on the wrong side of the thing being tested.
#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc::{self, Receiver};

    use sha2::Digest;

    struct Received {
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    impl Received {
        fn header(&self, name: &str) -> &str {
            self.headers.get(name).map(String::as_str).unwrap_or_default()
        }
    }

    fn read_request(stream: &mut TcpStream) -> Received {
        let mut raw = Vec::new();
        let mut chunk = [0u8; 2048];

        let header_end = loop {
            if let Some(at) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                break at + 4;
            }
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break raw.len(),
                Ok(read) => raw.extend_from_slice(&chunk[..read]),
            }
        };

        let mut headers = HashMap::new();
        for line in String::from_utf8_lossy(&raw[..header_end]).lines().skip(1) {
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_lowercase(), value.trim().to_string());
            }
        }

        // Read to the declared length rather than to EOF: reqwest holds the
        // connection open, so waiting for a close here would hang the test.
        let expected: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
        let mut body = raw[header_end..].to_vec();
        while body.len() < expected {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(read) => body.extend_from_slice(&chunk[..read]),
            }
        }

        Received { headers, body }
    }

    /// Serve `calls` requests on an ephemeral port and hand each one back.
    ///
    /// Every response closes its connection so a second call cannot ride the
    /// first's keep-alive and slip past the accept loop.
    fn intercept(calls: usize) -> (String, Receiver<Received>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            for _ in 0..calls {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };

                let received = read_request(&mut stream);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\nConnection: close\r\n\r\n{\"rules\":[]}",
                );
                let _ = stream.flush();

                if tx.send(received).is_err() {
                    return;
                }
            }
        });

        (url, rx)
    }

    fn agent_for(url: String, license_key: &str) -> RelintioAgent {
        RelintioAgent::new(RelintioConfig {
            license_key: license_key.to_string(),
            api_url: url,
            sync_interval_seconds: 10,
        })
    }

    fn next(rx: &Receiver<Received>) -> Received {
        rx.recv_timeout(Duration::from_secs(10)).expect("a request reached the server")
    }

    /// Mirrors the server's check in the order the server applies it, so a
    /// divergence fails here instead of as a 401 that nobody can reproduce.
    fn assert_signed(received: &Received, license_key: &str) {
        assert_eq!(received.header("content-type"), "application/json");

        let signature = received.header("x-relintio-signature");
        let provided = signature
            .strip_prefix("v1=")
            .unwrap_or_else(|| panic!("signature header missing or wrong version: {signature:?}"));
        assert_eq!(provided.len(), 64, "signature is not 64 hex chars: {provided}");

        let timestamp = received.header("x-relintio-timestamp");
        let seconds: i64 = timestamp.parse().unwrap_or_else(|_| panic!("timestamp {timestamp:?} is not an integer"));
        // The server allows 300s of drift; anything near that in a test means
        // the header is built from something other than now.
        assert!((unix_now() as i64 - seconds).abs() <= 5, "timestamp drifts from the wall clock");

        let nonce = received.header("x-relintio-nonce");
        assert!(
            (16..=128).contains(&nonce.len()),
            "nonce length {} outside the 16..128 the server accepts",
            nonce.len()
        );
        // The server matches [A-Za-z0-9_-]+, so standard base64 padding or a
        // raw byte string is rejected before the signature is ever checked.
        assert!(
            nonce.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "nonce {nonce:?} is outside the server's charset"
        );

        // Hash what the server received, not what the agent believes it sent.
        let mut hasher = Sha256::new();
        hasher.update(&received.body);
        let base = format!("v1:{timestamp}:{nonce}:{}", hex::encode(hasher.finalize()));

        let mut mac = HmacSha256::new_from_slice(license_key.as_bytes()).expect("hmac accepts any key length");
        mac.update(base.as_bytes());

        assert_eq!(
            hex::encode(mac.finalize().into_bytes()),
            provided,
            "signature does not cover the transmitted bytes: {}",
            String::from_utf8_lossy(&received.body)
        );
    }

    #[tokio::test]
    async fn refresh_rules_signs_what_it_sends() {
        let key = "sk_live_rust_refresh";
        let (url, rx) = intercept(1);

        agent_for(url, key).refresh_rules("example.com").await.expect("sync against a 200");

        let received = next(&rx);
        assert_signed(&received, key);
        // Guards the restructure itself: the signed slice has to be the request
        // body, not a re-encode of the same Value.
        assert!(String::from_utf8_lossy(&received.body).contains("\"domain\":\"example.com\""));
    }

    #[tokio::test]
    async fn heartbeat_signs_what_it_sends() {
        let key = "sk_live_rust_heartbeat";
        let (url, rx) = intercept(1);

        agent_for(url, key).send_heartbeat("example.com").await;

        assert_signed(&next(&rx), key);
    }

    #[tokio::test]
    async fn challenge_init_signs_what_it_sends() {
        let key = "sk_live_rust_challenge";
        let (url, rx) = intercept(1);

        // The canned response carries no token, so this returns None — the
        // request is what matters, and challenge/init sits behind the same
        // signature middleware as the ingest endpoints.
        let _ = agent_for(url, key).challenge_url("example.com", "/login").await;

        assert_signed(&next(&rx), key);
    }

    /// A nonce is single-use server-side: two calls that shared one would leave
    /// the second rejected as a replay.
    #[tokio::test]
    async fn each_call_carries_its_own_nonce() {
        let key = "sk_live_rust_nonce";
        let (url, rx) = intercept(2);
        let agent = agent_for(url, key);

        agent.send_heartbeat("example.com").await;
        agent.send_heartbeat("example.com").await;

        let (first, second) = (next(&rx), next(&rx));
        assert_ne!(first.header("x-relintio-nonce"), second.header("x-relintio-nonce"));
        assert_signed(&first, key);
        assert_signed(&second, key);
    }

    /// Serve `calls` requests with one canned JSON body.
    ///
    /// `intercept` answers everything with an empty rule set, which is what the
    /// signing tests need. What `/agent/challenge/init` answers is the entire
    /// subject of the tests below, so they choose the body.
    fn serve_json(body: &'static str, calls: usize) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));

        std::thread::spawn(move || {
            for _ in 0..calls {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };

                let _ = read_request(&mut stream);
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body,
                    )
                    .as_bytes(),
                );
                let _ = stream.flush();
            }
        });

        url
    }

    /// Drive the real decision path with a visitor the engine scores into the
    /// challenge band: a curl UA (35), no `Accept` (15) and a POST with no
    /// referer (20) is 70 — over CHALLENGE, under DECOY. What comes back is
    /// therefore whatever the challenge outcome was mapped to, and nothing else.
    async fn challenge_band_decision(key: &str, api_url: String) -> Decision {
        agent_for(api_url, key)
            .evaluate(
                "203.0.113.10",
                Some("curl/8.4.0"),
                &HashMap::new(),
                "POST",
                "/login",
                "example.com",
            )
            .await
    }

    /// The invariant the whole fleet shares. A challenge that could not be
    /// issued is not a challenge anyone passed, and the traffic that reaches
    /// this branch is by definition traffic already judged suspicious enough to
    /// challenge — so an unreachable token service must not be the way in.
    #[tokio::test]
    async fn an_unreachable_control_plane_blocks() {
        // A port with nothing listening: the call fails, no challenge is issued.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let dead = format!("http://{}", listener.local_addr().expect("local addr"));
        drop(listener);

        assert_eq!(challenge_band_decision("sk_live_rust_unreachable", dead).await, Decision::Block);
    }

    /// The other half of Unavailable: reachable, answered, and the answer
    /// carries neither a policy nor anything to send the visitor to.
    #[tokio::test]
    async fn an_unusable_challenge_response_blocks() {
        let url = serve_json("{}", 2);

        assert_eq!(challenge_band_decision("sk_live_rust_unusable", url).await, Decision::Block);
    }

    /// The one case where a visitor in the challenge band goes through, and the
    /// reason `Disabled` may not be collapsed into `Unavailable`: the customer
    /// switched the challenge off and chose what happens instead.
    #[tokio::test]
    async fn the_licences_own_allow_fallback_passes_the_visitor_through() {
        let url = serve_json(r#"{"status":"challenge_disabled","fallback":"allow"}"#, 2);

        assert_eq!(challenge_band_decision("sk_live_rust_fallback_allow", url).await, Decision::Allow);
    }

    #[tokio::test]
    async fn a_disabled_challenge_blocks_on_the_block_fallback() {
        let url = serve_json(r#"{"status":"challenge_disabled","fallback":"block"}"#, 2);

        assert_eq!(challenge_band_decision("sk_live_rust_fallback_block", url).await, Decision::Block);
    }

    /// Absent is not `allow`. A policy answer that names no fallback blocks.
    #[tokio::test]
    async fn a_disabled_challenge_with_no_fallback_blocks() {
        let url = serve_json(r#"{"status":"challenge_disabled"}"#, 2);

        assert_eq!(challenge_band_decision("sk_live_rust_fallback_absent", url).await, Decision::Block);
    }

    /// And the happy path, so a change that blocked everything would fail here
    /// rather than look like a pass.
    #[tokio::test]
    async fn a_token_sends_the_visitor_to_the_challenge() {
        let url = serve_json(r#"{"token":"tok0123456789abcdef0123"}"#, 2);

        match challenge_band_decision("sk_live_rust_token", url).await {
            Decision::Challenge { redirect_url } => assert!(
                redirect_url.contains("/security-check?token=tok0123456789abcdef0123"),
                "redirected to {redirect_url}"
            ),
            other => panic!("expected a challenge redirect, got {other:?}"),
        }
    }
}
