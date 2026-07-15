pub mod obsidian;
pub mod utils;
pub mod middleware;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use serde_json::Value;

type HmacSha256 = Hmac<Sha256>;

const AGENT_VERSION: &str = "0.1.0";
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

    /// Verifies the query string challenge token using HMAC-SHA256 signature checks.
    pub fn verify_up_token(&self, token: &str) -> bool {
        use base64::{engine::general_purpose, Engine as _};
        let decoded_bytes = match general_purpose::STANDARD.decode(token) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let decoded = match String::from_utf8(decoded_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let parts: Vec<&str> = decoded.split("::").collect();
        if parts.len() != 2 {
            return false;
        }

        let ts_raw = parts[0];
        let sig = parts[1];

        let ts: u64 = match ts_raw.parse() {
            Ok(val) => val,
            Err(_) => return false,
        };

        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => return false,
        };

        if now.abs_diff(ts) > 120 {
            return false;
        }

        let message = format!("{}|{}", ts, self.config.license_key);
        let mut mac = match HmacSha256::new_from_slice(self.config.license_key.as_bytes()) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(message.as_bytes());
        let result = mac.finalize();
        let calc_sig = hex::encode(result.into_bytes());

        // Constant time comparison
        let calc_bytes = calc_sig.as_bytes();
        let sig_bytes = sig.as_bytes();
        if calc_bytes.len() != sig_bytes.len() {
            return false;
        }

        let mut diff = 0;
        for i in 0..calc_bytes.len() {
            diff |= calc_bytes[i] ^ sig_bytes[i];
        }
        diff == 0
    }

    /// Calculate the SHA256 hashed signature value for setting the passport cookie.
    pub fn passport_value(&self) -> String {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(format!("verified{}", self.config.license_key));
        hex::encode(hasher.finalize())
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
        let res = self.client.post(&url)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        let val: Value = res.json().await?;
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
            "timestamp": unix_now()
        });

        let _ = self.client.post(&url)
            .json(&body)
            .timeout(Duration::from_secs(2))
            .send()
            .await;
    }

    async fn challenge_url(&self, domain: &str, path: &str) -> Option<String> {
        use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

        let endpoint = format!("{}/agent/challenge/init", self.config.api_url.trim_end_matches('/'));
        let scheme = if domain == "localhost" || domain.starts_with("localhost:") || domain == "127.0.0.1" || domain.starts_with("127.0.0.1:") {
            "http"
        } else {
            "https"
        };
        let return_url = format!("{}://{}{}", scheme, domain, path);
        let response = self.client.post(endpoint)
            .json(&serde_json::json!({
                "license_key": self.config.license_key,
                "return_url": return_url,
            }))
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?;
        let body: Value = response.json().await.ok()?;
        let token = body.get("token")?.as_str()?;
        let platform_url = self.config.api_url.trim_end_matches('/').strip_suffix("/api")
            .unwrap_or(self.config.api_url.trim_end_matches('/'));

        Some(format!(
            "{}/security-check?token={}",
            platform_url,
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

        let rules = self.rules.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(custom_rules) = rules.as_ref().and_then(|value| value.get("rules")).and_then(Value::as_array) {
            for rule in custom_rules {
                let rule_type = rule.get("type").and_then(Value::as_str).unwrap_or("");
                let pattern = rule.get("pattern").and_then(Value::as_str).unwrap_or("");
                let condition = rule.get("condition").and_then(Value::as_str).unwrap_or("contains");
                let candidate = match rule_type {
                    "ip" => ip,
                    "user_agent" => ua,
                    "path" => path,
                    _ => continue,
                };
                let matched = if condition == "equals" {
                    candidate.eq_ignore_ascii_case(pattern)
                } else {
                    candidate.to_lowercase().contains(&pattern.to_lowercase())
                };
                if matched {
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
        let should_sync = {
            let last = self.synced_at.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            *last == 0 || now.saturating_sub(*last) > self.config.sync_interval_seconds
        };

        if should_sync {
            let _ = self.refresh_rules(domain).await;
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
                Some(redirect_url) => Decision::Challenge { redirect_url },
                None => Decision::Allow,
            };
        }
        if score >= threshold("SLOW") {
            return Decision::Slow;
        }

        Decision::Allow
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
