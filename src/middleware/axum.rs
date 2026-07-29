use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::{Body, HttpBody},
    http::{header, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use cookie::Cookie;

use crate::{Decision, RelintioAgent};

/// Axum middleware function to protect routes.
pub async fn relintio_middleware(
    agent: Arc<RelintioAgent>,
    req: Request<Body>,
    next: Next<Body>,
) -> Response {
    // The authority lives in the Host header, not the URI: an
    // origin-form HTTP/1.1 request line carries only the path, so
    // `uri().host()` is None for essentially all real traffic. Reading
    // it meant every site reported itself as `localhost` — which is the
    // domain the control plane matched rules against, and the domain a
    // challenged visitor was redirected back to.
    let domain = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| req.uri().host())
        .unwrap_or("localhost")
        .to_string();
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();

    // 1. Resolve IP address
    let mut ip = "127.0.0.1".to_string();
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(val) = forwarded.to_str() {
            if let Some(first_ip) = val.split(',').next() {
                ip = crate::utils::normalize_ip(first_ip);
            }
        }
    } else if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(val) = real_ip.to_str() {
            ip = crate::utils::normalize_ip(val);
        }
    }

    // 2. Extract headers
    let mut headers = HashMap::new();
    for (name, value) in req.headers().iter() {
        if let Ok(val_str) = value.to_str() {
            headers.insert(name.as_str().to_lowercase(), val_str.to_string());
        }
    }

    let user_agent = headers.get("user-agent").map(|s| s.as_str());

    // Raw header values, used verbatim for the passport binding — normalising
    // them here would diverge from the challenge server.
    let ua_header = headers.get("user-agent").cloned().unwrap_or_default();
    let lang_header = headers.get("accept-language").cloned().unwrap_or_default();

    // 3. Handle up_token verification/exchange (challenge success)
    let query = req.uri().query().unwrap_or("");
    let mut params = HashMap::new();
    for pair in query.split('&') {
        let parts: Vec<&str> = pair.split('=').collect();
        if parts.len() == 2 {
            params.insert(parts[0], parts[1]);
        }
    }

    if let Some(&up_token) = params.get("up_token") {
        let decoded_token = percent_encoding::percent_decode_str(up_token)
            .decode_utf8_lossy()
            .to_string();
        if let Some(payload) = agent.verify_passport(&decoded_token, &ua_header, &lang_header) {
            let ttl = crate::passport::clamp_ttl(payload.ttl.unwrap_or(0));
            let cookie_val = agent.mint_passport(ttl, &ua_header, &lang_header);
            let cookie = Cookie::build(("relintio_passport", cookie_val))
                .path("/")
                .max_age(cookie::time::Duration::seconds(ttl))
                .http_only(true)
                .build();

            // Redirect back to clean path
            let redirect_res = Response::builder()
                .status(StatusCode::FOUND)
                .header(header::LOCATION, &path)
                .header(header::SET_COOKIE, cookie.to_string())
                .body(axum::body::boxed(Body::empty()))
                .unwrap_or_else(|_| Response::new(axum::body::boxed(Body::empty())));
            return redirect_res;
        } else {
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(axum::body::boxed(Body::from("Invalid Token")))
                .unwrap_or_else(|_| Response::new(axum::body::boxed(Body::empty())));
        }
    }

    // 4. Passport / Human Verification Cookie check
    let mut is_human = false;
    if let Some(cookie_header) = req.headers().get(header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie_item in Cookie::split_parse(cookie_str) {
                if let Ok(c) = cookie_item {
                    if c.name() == "relintio_passport"
                        && agent.verify_passport(c.value(), &ua_header, &lang_header).is_some()
                    {
                        is_human = true;
                        break;
                    }
                }
            }
        }
    }

    if is_human {
        // Human bypass - log allows periodically or just pass through
        return next.run(req).await;
    }

    // 5. Evaluate threat score
    let decision = agent.evaluate(&ip, user_agent, &headers, &method, &path, &domain).await;

    match decision {
        Decision::Allow => {
            // Forward request
            let res = next.run(req).await;
            
            // Intercept HTML for Obsidian Injection
            let is_html = res.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.contains("text/html"))
                .unwrap_or(false);

            if is_html {
                let (parts, mut body) = res.into_parts();
                let mut bytes = Vec::new();
                while let Some(chunk) = body.data().await {
                    if let Ok(b) = chunk {
                        bytes.extend_from_slice(&b);
                    }
                }
                
                // Fetch rules to pass config values to builder
                let rules_guard = agent.rules.read().unwrap_or_else(|poisoned| poisoned.into_inner());
                let rules = rules_guard.as_ref().cloned().unwrap_or(serde_json::json!({}));
                
                let injector = crate::obsidian::ObsidianInjector::new();
                let new_body = injector.inject_into_html(&bytes, &rules);

                let mut intercepted_res = Response::from_parts(parts, axum::body::boxed(Body::from(new_body)));
                // Update content length
                if intercepted_res.headers().contains_key(header::CONTENT_LENGTH) {
                    let len = intercepted_res.body().size_hint().exact().unwrap_or(0);
                    intercepted_res.headers_mut().insert(
                        header::CONTENT_LENGTH,
                        HeaderValue::from(len),
                    );
                }
                intercepted_res
            } else {
                res
            }
        }
        Decision::Slow => {
            tokio::time::sleep(Duration::from_secs(2)).await;
            next.run(req).await
        }
        Decision::Challenge { redirect_url } => {
            Response::builder()
                .status(StatusCode::FOUND)
                .header(header::LOCATION, redirect_url)
                .body(axum::body::boxed(Body::empty()))
                .unwrap_or_else(|_| Response::new(axum::body::boxed(Body::empty())))
        }
        Decision::Decoy => {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/html")
                .body(axum::body::boxed(Body::from(RelintioAgent::decoy_html())))
                .unwrap_or_else(|_| Response::new(axum::body::boxed(Body::empty())))
        }
        Decision::Block => {
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header(header::CONTENT_TYPE, "text/html")
                .body(axum::body::boxed(Body::from(RelintioAgent::block_html())))
                .unwrap_or_else(|_| Response::new(axum::body::boxed(Body::empty())))
        }
    }
}
