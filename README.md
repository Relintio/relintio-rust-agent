# Relintio Rust Agent SDK

The official in-process protection agent for Rust web application frameworks (Axum and Actix-web). Relintio blocks bots, credential stuffing, scraping, and other automated abuse in real-time.

## Features

- **Dynamic Ruleset Caching:** Fetches WAF rules dynamically from the Relintio API and caches them locally to ensure offline safety and minimal lookup latency.
- **Additive Scoring Engine:** Inspects requests for client characteristics (missing headers, automated client user-agents, request rate bursts) and adds points up to 100.
- **Token-bucket Rate Limiter:** Built-in rate limits per client IP.
- **Obsidian Layer (Axum):** Injects anti-copy, right-click disabling, and DevTools blocking directly into HTML response payloads.
- **Multiple Frameworks:** First-class integrations for Axum and Actix-web.

---

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
relintio-agent = "0.1.0"
```

To enable only a specific framework integration, disable default features:

```toml
[dependencies]
relintio-agent = { version = "0.1.0", default-features = false, features = ["axum"] }
```

---

## Quickstart

### 1. Axum Example

```rust
use std::sync::Arc;
use axum::{routing::get, Router, middleware};
use relintio_agent::{RelintioAgent, RelintioConfig, middleware::axum::relintio_middleware};

#[tokio::main]
async fn main() {
    let config = RelintioConfig {
        license_key: "YOUR_LICENSE_KEY".to_string(),
        api_url: "https://api.relintio.com/api".to_string(),
        sync_interval_seconds: 60,
    };

    let agent = Arc::new(RelintioAgent::new(config));

    let app = Router::new()
        .route("/", get(|| async { "Hello, Protected World!" }))
        .layer(middleware::from_fn(move |req, next| {
            relintio_middleware(agent.clone(), req, next)
        }));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### 2. Actix-web Example

```rust
use std::sync::Arc;
use actix_web::{get, App, HttpServer, Responder};
use relintio_agent::{RelintioAgent, RelintioConfig, middleware::actix::RelintioActixMiddleware};

#[get("/")]
async fn hello() -> impl Responder {
    "Hello, Protected World!"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = RelintioConfig {
        license_key: "YOUR_LICENSE_KEY".to_string(),
        api_url: "https://api.relintio.com/api".to_string(),
        sync_interval_seconds: 60,
    };

    let agent = Arc::new(RelintioAgent::new(config));

    HttpServer::new(move || {
        App::new()
            .wrap(RelintioActixMiddleware::new(agent.clone()))
            .service(hello)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

---

## How It Works

1. **Rule Syncing:** The agent pulls your custom security configuration (banned IPs, geo-fencing rules, rate limits) on boot, and updates it in a background thread every `sync_interval_seconds` seconds.
2. **Request Scoring:** Incoming requests are evaluated dynamically. If the total score hits blocking thresholds, the middleware intercepts the call and serves a decoy, security challenge, or block screen.
3. **Fail-Open Policy:** If the Relintio API is down, the agent fails open, ensuring no downtime for legitimate users.

---

## License

This project is licensed under the MIT License.
