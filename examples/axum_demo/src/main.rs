use std::sync::Arc;
use axum::{routing::get, Router, middleware, response::Html};
use relintio_agent::{RelintioAgent, RelintioConfig, middleware::axum::relintio_middleware};

#[tokio::main]
async fn main() {
    println!("Starting Relintio Axum Protection Demo...");

    // Relintio agent configuration
    // The main platform downloads controller will replace {{LICENSE_KEY}} and {{API_URL}} dynamically.
    let config = RelintioConfig {
        license_key: "{{LICENSE_KEY}}".to_string(),
        api_url: "{{API_URL}}".to_string(),
        sync_interval_seconds: 60,
    };

    let agent = Arc::new(RelintioAgent::new(config));

    // Define routes
    let app = Router::new()
        .route("/", get(home_handler))
        .route("/login", get(login_handler))
        .layer(middleware::from_fn(move |req, next| {
            relintio_middleware(agent.clone(), req, next)
        }));

    // Start listening on port 3000
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Server listening on http://{}", addr);
    
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn home_handler() -> Html<&'static str> {
    Html("<!DOCTYPE html><html><head><title>Relintio Protected Site</title></head><body><h1>Welcome to Relintio Protected Site!</h1><p>Your connection is secured and audited in real-time.</p></body></html>")
}

async fn login_handler() -> &'static str {
    "Login form page (high protection multipliers active)"
}
